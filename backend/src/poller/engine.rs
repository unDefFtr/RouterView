use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Datelike, Timelike};
use futures_util::FutureExt;
use serde::Serialize;
use tokio::sync::{broadcast, watch, RwLock};
use tracing::{debug, error, info, warn};

use crate::backends::{
    InterfaceEntry, RouterBackend, RouterConnectionConfig, RouterData, RouterType,
};
use crate::config_store::MergedConfig;
use crate::db::{
    CounterCheckpointInput, DatabaseError, TrafficDb, TrafficGapInput, TrafficQuality,
    TrafficQuery, TrafficSampleInput,
};
use crate::error::AppError;
use crate::ws::protocol::*;

/// Per-round network quality assessment derived from all probe results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeQuality {
    /// All or majority of targets reachable with acceptable latency.
    Good,
    /// A significant fraction of targets show poor latency or are unreachable,
    /// but the network is still functional.
    Degraded,
    /// Majority of targets unreachable — likely a link-down or ISP outage.
    Down,
}

/// Parameters for multi-ping probing.
const PING_COUNT: usize = 3;
const PING_GAP_MS: u64 = 200;
const PING_TIMEOUT_SECS: u64 = 2;
const MAX_RECONNECT_DELAY_SECS: u64 = 30;
const AGGREGATE_INTERFACE_KEY: &str = "__aggregate__";
const EXACT_TRAFFIC_SOURCE: &str = "routeros-counter";

#[derive(Debug, Clone)]
struct CounterBaseline {
    rx_counter: u64,
    tx_counter: u64,
    observed_at_ms: i64,
    monotonic: Instant,
    uptime_seconds: Option<u64>,
    boot_epoch_seconds: Option<i64>,
    reboot_marker: Option<String>,
    member_signature: Option<String>,
}

#[derive(Debug)]
struct CounterObservation<'a> {
    router_id: i64,
    interface_id: i64,
    rx_counter: u64,
    tx_counter: u64,
    observed_at_ms: i64,
    monotonic: Instant,
    uptime_seconds: Option<u64>,
    member_signature: Option<&'a str>,
    forced_gap: Option<(&'a str, &'a str)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterPersistenceOutcome {
    Initialized,
    ExactSample,
    Gap,
}

struct ExactPersistenceResult {
    router_id: i64,
    aggregate_interface_id: i64,
    errors: Vec<String>,
}

struct PollSnapshot {
    snapshot: DashboardSnapshot,
    storage_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PollReadinessState {
    Starting,
    Ready,
    Degraded,
    Stopped,
}

/// Observable poller health for a future readiness endpoint or supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PollReadiness {
    pub state: PollReadinessState,
    pub router_connected: bool,
    pub consecutive_failures: u32,
    pub last_successful_poll: Option<String>,
    pub last_error: Option<String>,
}

/// Handle used by the process supervisor to inspect and stop the poller.
#[derive(Clone)]
pub struct PollEngineControl {
    readiness_tx: watch::Sender<PollReadiness>,
    shutdown_tx: watch::Sender<bool>,
}

impl PollEngineControl {
    pub fn readiness(&self) -> PollReadiness {
        self.readiness_tx.borrow().clone()
    }

    #[cfg(test)]
    pub fn subscribe_readiness(&self) -> watch::Receiver<PollReadiness> {
        self.readiness_tx.subscribe()
    }

    pub fn request_shutdown(&self) {
        self.shutdown_tx.send_replace(true);
    }

    pub fn shutdown_requested(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    pub fn report_unexpected_exit(&self, message: impl Into<String>) {
        let previous = self.readiness_tx.borrow().clone();
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Stopped,
            router_connected: false,
            consecutive_failures: previous.consecutive_failures.saturating_add(1),
            last_successful_poll: previous.last_successful_poll,
            last_error: Some(message.into()),
        });
    }
}

/// The poll engine runs on a configurable interval, fetches data from
/// the router backend, transforms it into dashboard structures,
/// diffs against the previous snapshot, and broadcasts changes to
/// all connected WebSocket clients.
pub struct PollEngine {
    /// Router backend — None when unconfigured or unreachable.
    client: Option<Box<dyn RouterBackend>>,
    /// Last connection params that produced a working client.
    /// Includes transport policy so allowlist changes rebuild the pinned client.
    last_conn_params: (
        RouterType,
        String,
        u16,
        String,
        String,
        String,
        bool,
        Vec<ipnet::IpNet>,
        bool,
    ),
    config: Arc<RwLock<MergedConfig>>,
    broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
    /// Shared snapshot cache — written after every poll, read by new WS clients.
    snapshot_cache: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
    /// Previous poll's interface byte counters, keyed by interface name.
    prev_counters: HashMap<String, (u64, u64)>,
    /// Router uptime paired with `prev_counters` for reboot detection.
    prev_uptime_seconds: Option<u64>,
    /// Completion time of the previous successful sample.
    last_successful_sample_at: Option<Instant>,
    /// Router identity that owns the in-memory dashboard and counter state.
    active_router_id: Option<i64>,
    /// Per-interface durable counter baselines. Entries advance only after the
    /// corresponding sample/gap and checkpoint transaction succeeds.
    exact_counter_baselines: HashMap<i64, CounterBaseline>,
    /// Previous poll's full snapshot for diffing.
    prev_snapshot: Option<DashboardSnapshot>,
    /// Whether this is the first successful poll.
    first_poll: bool,
    /// Accumulated traffic history for snapshot initialization.
    traffic_history: Vec<TrafficPoint>,
    /// Per-WAN traffic history buffers, keyed by WAN interface name.
    wan_traffic_history: HashMap<String, Vec<TrafficPoint>>,
    /// Latency probe targets — shared with API handlers for hot-reload.
    probe_targets: Arc<RwLock<Vec<(String, String, String)>>>,
    /// Latency classification thresholds from config.
    latency_good_ms: f64,
    latency_poor_ms: f64,
    /// Latency probe results from last probe cycle.
    last_probe_results: Vec<LatencyProbe>,
    /// Stability tracking: rolling window of probe quality assessments.
    stability_history: Vec<ProbeQuality>,
    /// SQLite traffic history database.
    traffic_db: Arc<TrafficDb>,
    /// Poll count for periodic DB maintenance.
    poll_count: u64,
    /// Latched until the next successful rollup and retention cycle.
    maintenance_error: Option<String>,
    /// Consecutive failed reconnect attempts.
    reconnect_failures: u32,
    /// Earliest time another reconnect may be attempted.
    reconnect_not_before: Instant,
    /// Consecutive fetch/poll failures exposed through readiness.
    consecutive_poll_failures: u32,
    readiness_tx: watch::Sender<PollReadiness>,
    shutdown_tx: watch::Sender<bool>,
}

impl PollEngine {
    pub async fn new(
        config: Arc<RwLock<MergedConfig>>,
        broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
        snapshot_cache: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
        traffic_db: Arc<TrafficDb>,
        probe_targets: Arc<RwLock<Vec<(String, String, String)>>>,
    ) -> Self {
        let (conn_params, latency_good_ms, latency_poor_ms) = {
            let cfg = config.read().await;
            (
                (
                    cfg.router_type,
                    cfg.router_host.clone(),
                    cfg.router_port,
                    cfg.router_scheme.clone(),
                    cfg.router_username.clone(),
                    cfg.router_password.clone(),
                    cfg.accept_invalid_certs,
                    cfg.router_management_cidrs.clone(),
                    cfg.allow_insecure_router_http,
                ),
                cfg.latency_good_ms as f64,
                cfg.latency_poor_ms as f64,
            )
        };

        let msg = Arc::new(ServerMessage::ConnectionStatus {
            connected: false,
            last_poll: None,
        });
        let _ = broadcast_tx.send(msg);

        let initial_readiness = PollReadiness {
            state: PollReadinessState::Starting,
            router_connected: false,
            consecutive_failures: 0,
            last_successful_poll: None,
            last_error: None,
        };
        let (readiness_tx, _) = watch::channel(initial_readiness);
        let (shutdown_tx, _) = watch::channel(false);

        Self {
            client: None,
            last_conn_params: conn_params,
            config,
            broadcast_tx,
            snapshot_cache,
            prev_counters: HashMap::new(),
            prev_uptime_seconds: None,
            last_successful_sample_at: None,
            active_router_id: None,
            exact_counter_baselines: HashMap::new(),
            prev_snapshot: None,
            first_poll: true,
            traffic_history: Vec::with_capacity(7200),
            wan_traffic_history: HashMap::new(),
            probe_targets,
            last_probe_results: Vec::new(),
            stability_history: Vec::with_capacity(60),
            traffic_db,
            poll_count: 0,
            maintenance_error: None,
            latency_good_ms,
            latency_poor_ms,
            reconnect_failures: 0,
            reconnect_not_before: Instant::now(),
            consecutive_poll_failures: 0,
            readiness_tx,
            shutdown_tx,
        }
    }

    pub fn control(&self) -> PollEngineControl {
        PollEngineControl {
            readiness_tx: self.readiness_tx.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    fn clear_counter_baseline(&mut self) {
        self.prev_counters.clear();
        self.prev_uptime_seconds = None;
        self.last_successful_sample_at = None;
    }

    async fn switch_router_scope(&mut self, router_id: i64) {
        if self.active_router_id == Some(router_id) {
            return;
        }

        if let Some(previous) = self.active_router_id {
            info!(
                previous_router_id = previous,
                router_id, "Router identity changed; clearing router-scoped state"
            );
        }
        self.active_router_id = Some(router_id);
        self.clear_counter_baseline();
        self.exact_counter_baselines.clear();
        self.prev_snapshot = None;
        self.first_poll = true;
        self.traffic_history.clear();
        self.wan_traffic_history.clear();
        *self.snapshot_cache.write().await = None;
    }

    fn schedule_reconnect(&mut self) {
        self.reconnect_failures = self.reconnect_failures.saturating_add(1);
        self.reconnect_not_before = Instant::now() + reconnect_delay(self.reconnect_failures);
    }

    fn mark_ready(&mut self) {
        self.consecutive_poll_failures = 0;
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Ready,
            router_connected: true,
            consecutive_failures: 0,
            last_successful_poll: Some(chrono::Utc::now().to_rfc3339()),
            last_error: None,
        });
    }

    fn mark_poll_failure(&mut self, message: String) {
        self.client = None;
        self.first_poll = true;
        self.clear_counter_baseline();
        self.schedule_reconnect();
        self.consecutive_poll_failures = self.consecutive_poll_failures.saturating_add(1);
        let previous = self.readiness_tx.borrow().clone();
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Degraded,
            router_connected: false,
            consecutive_failures: self.consecutive_poll_failures,
            last_successful_poll: previous.last_successful_poll,
            last_error: Some(message),
        });
    }

    fn mark_storage_failure(&mut self, message: String) {
        self.consecutive_poll_failures = self.consecutive_poll_failures.saturating_add(1);
        let previous = self.readiness_tx.borrow().clone();
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Degraded,
            router_connected: true,
            consecutive_failures: self.consecutive_poll_failures,
            last_successful_poll: previous.last_successful_poll,
            last_error: Some(message),
        });
    }

    fn mark_connection_failure(&mut self, message: String) {
        self.consecutive_poll_failures = self.consecutive_poll_failures.saturating_add(1);
        let previous = self.readiness_tx.borrow().clone();
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Degraded,
            router_connected: false,
            consecutive_failures: self.consecutive_poll_failures,
            last_successful_poll: previous.last_successful_poll,
            last_error: Some(message),
        });
    }

    fn mark_stopped(&mut self) {
        let previous = self.readiness_tx.borrow().clone();
        self.readiness_tx.send_replace(PollReadiness {
            state: PollReadinessState::Stopped,
            router_connected: false,
            consecutive_failures: previous.consecutive_failures,
            last_successful_poll: previous.last_successful_poll,
            last_error: previous.last_error,
        });
    }

    /// Attempt to rebuild the router client from current config.
    /// Returns true if a new client was created.
    async fn try_reconnect(&mut self) -> bool {
        let current_params = {
            let cfg = self.config.read().await;
            (
                cfg.router_type,
                cfg.router_host.clone(),
                cfg.router_port,
                cfg.router_scheme.clone(),
                cfg.router_username.clone(),
                cfg.router_password.clone(),
                cfg.accept_invalid_certs,
                cfg.router_management_cidrs.clone(),
                cfg.allow_insecure_router_http,
            )
        };

        // Only reconnect if connection params actually changed or we have no client
        let params_changed = self.last_conn_params != current_params;
        if !params_changed && self.client.is_some() {
            return false;
        }

        if params_changed {
            self.client = None;
            self.clear_counter_baseline();
            self.reconnect_failures = 0;
            self.reconnect_not_before = Instant::now();
        } else if Instant::now() < self.reconnect_not_before {
            debug!(
                "Poll engine: reconnect deferred for {:?}",
                self.reconnect_not_before
                    .saturating_duration_since(Instant::now())
            );
            return false;
        }

        if params_changed {
            let host = &current_params.1;
            let port = current_params.2;
            let scheme = &current_params.3;
            info!("Poll engine: config changed, reconnecting to {host}:{port} ({scheme})");
        }

        let conn_config = {
            let cfg = self.config.read().await;
            RouterConnectionConfig {
                router_type: cfg.router_type,
                host: cfg.router_host.clone(),
                port: cfg.router_port,
                scheme: cfg.router_scheme.clone(),
                username: cfg.router_username.clone(),
                password: cfg.router_password.clone(),
                accept_invalid_certs: cfg.accept_invalid_certs,
                management_cidrs: cfg.router_management_cidrs.clone(),
                allow_insecure_http: cfg.allow_insecure_router_http,
            }
        };
        match connect_backend(&conn_config).await {
            Ok(c) => {
                info!("Poll engine: reconnected to router successfully");
                self.client = Some(c);
                self.last_conn_params = current_params;
                self.first_poll = true; // force full snapshot
                self.reconnect_failures = 0;
                self.reconnect_not_before = Instant::now();
                true
            }
            Err(e) => {
                self.schedule_reconnect();
                warn!(
                    "Poll engine: reconnect failed ({e}); next attempt in {:?}",
                    self.reconnect_not_before
                        .saturating_duration_since(Instant::now())
                );
                if params_changed {
                    self.last_conn_params = current_params; // don't retry same params on every tick
                }
                self.mark_connection_failure(e.to_string());
                false
            }
        }
    }

    /// Run the poll loop indefinitely. Reads config intervals on each
    /// iteration so changes take effect without restart.
    pub async fn run(mut self) {
        let (poll_secs, probe_secs) = {
            let cfg = self.config.read().await;
            (cfg.poll_interval_secs, cfg.probe_interval_secs)
        };

        info!("Poll engine started: poll={poll_secs}s, probe={probe_secs}s");

        // Use sleep-based polling so interval changes hot-reload
        let mut next_poll = tokio::time::Instant::now();
        let mut next_probe = tokio::time::Instant::now();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if *shutdown_rx.borrow() {
            self.mark_stopped();
            return;
        }

        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(next_poll) => {
                    if AssertUnwindSafe(self.poll_tick()).catch_unwind().await.is_err() {
                        error!("Poll tick panicked; isolating failure and rebuilding the router client");
                        self.mark_poll_failure("poll tick panicked".to_string());
                    }
                    let secs = {
                        let cfg = self.config.read().await;
                        cfg.poll_interval_secs
                    };
                    next_poll = tokio::time::Instant::now() + Duration::from_secs(secs);
                }
                _ = tokio::time::sleep_until(next_probe) => {
                    if AssertUnwindSafe(self.probe_tick()).catch_unwind().await.is_err() {
                        error!("Probe tick panicked; continuing poll supervision");
                    }
                    let secs = {
                        let cfg = self.config.read().await;
                        cfg.probe_interval_secs
                    };
                    next_probe = tokio::time::Instant::now() + Duration::from_secs(secs);
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        info!("Poll engine shutdown requested");
                        break;
                    }
                }
            }
        }

        self.mark_stopped();
    }

    /// Execute one poll cycle: fetch, transform, diff, broadcast.
    /// If no router backend is available, try reconnecting and broadcast
    /// disconnected status until the user configures connection params.
    async fn poll_tick(&mut self) {
        self.try_reconnect().await;

        if self.client.is_none() {
            debug!("Poll tick skipped — no router connection");
            let msg = Arc::new(ServerMessage::ConnectionStatus {
                connected: false,
                last_poll: Some(chrono::Utc::now().to_rfc3339()),
            });
            let _ = self.broadcast_tx.send(msg);
            return;
        }

        match self.fetch_and_transform().await {
            Ok(PollSnapshot {
                snapshot,
                mut storage_errors,
            }) => {
                // Update latency probes with latest results
                let mut snapshot = snapshot;
                snapshot.latency_probes = self.last_probe_results.clone();

                // Build ISP stability from history
                let probe_interval = {
                    let cfg = self.config.read().await;
                    cfg.probe_interval_secs
                };
                snapshot.stability = self.build_stability(probe_interval);

                // Apply user device overrides from the database
                crate::db::apply_device_overrides(&mut snapshot.wifi, &self.traffic_db);

                // ── Traffic history: push latest point, prune to 6h window ──
                // Clone out the point first to release the immutable borrow on
                // snapshot.traffic.points before we overwrite it below.
                let latest_pt = { snapshot.traffic.points.first().cloned() };
                if let Some(ref pt) = latest_pt {
                    self.traffic_history.push(pt.clone());
                    let cutoff = chrono::Utc::now() - chrono::Duration::hours(6);
                    self.traffic_history.retain(|p| {
                        chrono::DateTime::parse_from_rfc3339(&p.timestamp)
                            .map(|ts| ts.with_timezone(&chrono::Utc) >= cutoff)
                            .unwrap_or(false)
                    });
                    snapshot.traffic.points = self.traffic_history.clone();
                }

                // ── Per-WAN traffic history ──────────────────────
                for wan_pt in &snapshot.wan_traffic_points {
                    if let Some(ref wan_name) = wan_pt.wan_name {
                        let buffer = self
                            .wan_traffic_history
                            .entry(wan_name.clone())
                            .or_insert_with(|| Vec::with_capacity(7200));
                        buffer.push(wan_pt.clone());
                        let cutoff = chrono::Utc::now() - chrono::Duration::hours(6);
                        buffer.retain(|p| {
                            chrono::DateTime::parse_from_rfc3339(&p.timestamp)
                                .map(|ts| ts.with_timezone(&chrono::Utc) >= cutoff)
                                .unwrap_or(false)
                        });
                    }
                }

                // Periodic DB maintenance: transactional exact-byte rollup and retention.
                self.poll_count += 1;
                if self.poll_count.is_multiple_of(60) {
                    let (raw_days, total_days) = {
                        let cfg = self.config.read().await;
                        (
                            cfg.db_raw_retention_days as i64,
                            cfg.db_total_retention_days as i64,
                        )
                    };
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let raw_cutoff = now_ms.saturating_sub(raw_days.saturating_mul(86_400_000));
                    let total_cutoff = now_ms.saturating_sub(total_days.saturating_mul(86_400_000));
                    let mut maintenance_errors = Vec::new();
                    match self.traffic_db.rollup_exact_samples(raw_cutoff, 60_000) {
                        Ok(deleted) if deleted > 0 => {
                            info!(
                                deleted,
                                "Rolled exact traffic samples into one-minute buckets"
                            )
                        }
                        Ok(_) => {}
                        Err(error) => {
                            maintenance_errors.push(format!("traffic rollup failed: {error}"))
                        }
                    }
                    if let Err(error) = self.traffic_db.prune_exact_history(total_cutoff) {
                        maintenance_errors.push(format!("traffic retention failed: {error}"));
                    }
                    self.maintenance_error =
                        (!maintenance_errors.is_empty()).then(|| maintenance_errors.join("; "));
                }
                if let Some(error) = &self.maintenance_error {
                    storage_errors.push(error.clone());
                }

                // ── Cache snapshot for new WS clients ──────────
                let snapshot_arc = Arc::new(snapshot.clone());
                *self.snapshot_cache.write().await = Some(snapshot_arc);

                if self.first_poll {
                    // First poll: send full snapshot
                    info!("First poll successful — sending snapshot");
                    let msg = Arc::new(ServerMessage::Snapshot {
                        data: snapshot.clone(),
                    });
                    let _ = self.broadcast_tx.send(msg);
                    self.first_poll = false;
                    self.prev_snapshot = Some(snapshot);
                } else {
                    // Subsequent poll: diff and send update
                    if let Some(prev) = &self.prev_snapshot {
                        let update = self.diff_snapshots(prev, &snapshot);
                        if self.has_changes(&update) {
                            let msg = Arc::new(ServerMessage::Update { data: update });
                            let _ = self.broadcast_tx.send(msg);
                        }
                    }
                    self.prev_snapshot = Some(snapshot);
                }

                if storage_errors.is_empty() {
                    self.mark_ready();
                } else {
                    self.mark_storage_failure(storage_errors.join("; "));
                }
            }
            Err(e) => {
                warn!("Poll failed: {e}");
                self.mark_poll_failure(e.to_string());
                let msg = Arc::new(ServerMessage::ConnectionStatus {
                    connected: false,
                    last_poll: Some(chrono::Utc::now().to_rfc3339()),
                });
                let _ = self.broadcast_tx.send(msg);
            }
        }
    }

    /// Execute one latency probe cycle — send ICMP pings via surge-ping.
    async fn probe_tick(&mut self) {
        // Read latest targets and thresholds from shared state
        let targets = self.probe_targets.read().await.clone();

        // Hot-reload latency thresholds
        {
            let cfg = self.config.read().await;
            self.latency_good_ms = cfg.latency_good_ms as f64;
            self.latency_poor_ms = cfg.latency_poor_ms as f64;
        }

        debug!("Probe tick — pinging {} targets", targets.len());

        let results = run_icmp_probes(&targets, self.latency_good_ms, self.latency_poor_ms).await;

        // ── Three-state quality classification ──
        let quality = classify_probe_quality(&results);
        self.stability_history.push(quality);

        // ── Dynamic window: keep ~30 min worth of history ──
        let probe_interval = {
            let cfg = self.config.read().await;
            cfg.probe_interval_secs
        };
        let max_entries = (30 * 60 / probe_interval as usize).clamp(10, 120);
        while self.stability_history.len() > max_entries {
            self.stability_history.remove(0);
        }

        let ok = results.iter().filter(|r| r.latency_ms.is_some()).count();
        let total = results.len();
        debug!(
            "Probe complete: {}/{} reachable, quality={:?}",
            ok, total, quality,
        );

        self.last_probe_results = results;
    }

    /// Fetch all router data and transform into a snapshot.
    /// Only called when `self.client` is `Some`.
    async fn fetch_and_transform(&mut self) -> Result<PollSnapshot, AppError> {
        // Fetch all data via the backend trait — parallelization is internal
        let data = self
            .client
            .as_ref()
            .expect("client must be Some when fetch_and_transform is called")
            .fetch_all()
            .await?;
        let sampled_at = data.counter_sample_time.monotonic;
        let sampled_at_ms = data.counter_sample_time.unix_ms;

        let mut storage_errors = Vec::new();
        let mut monthly_usage_gb = 0.0;
        let fallback_target = self.last_conn_params.1.clone();
        match self.traffic_db.resolve_router(
            data.system.hardware_identity.as_deref(),
            &fallback_target,
            sampled_at_ms,
        ) {
            Ok(router) => {
                self.switch_router_scope(router.id).await;
                let wan_names = crate::poller::transform::wan_interface_names(&data);
                match persist_exact_traffic(
                    &self.traffic_db,
                    &mut self.exact_counter_baselines,
                    router.id,
                    &data,
                    &wan_names,
                ) {
                    Ok(result) => {
                        debug_assert_eq!(result.router_id, router.id);
                        storage_errors.extend(result.errors);
                        match monthly_usage_gb_v4(
                            &self.traffic_db,
                            router.id,
                            result.aggregate_interface_id,
                            sampled_at_ms,
                        ) {
                            Ok(usage) => monthly_usage_gb = usage,
                            Err(error) => storage_errors
                                .push(format!("monthly traffic query failed: {error}")),
                        }
                    }
                    Err(error) => {
                        storage_errors.push(format!("traffic persistence failed: {error}"))
                    }
                }
            }
            Err(error) => {
                storage_errors.push(format!("router identity persistence failed: {error}"));
                if self.active_router_id.take().is_some() {
                    self.clear_counter_baseline();
                    self.exact_counter_baselines.clear();
                    self.prev_snapshot = None;
                    self.first_poll = true;
                    self.traffic_history.clear();
                    self.wan_traffic_history.clear();
                    *self.snapshot_cache.write().await = None;
                }
            }
        }

        let sample_elapsed_secs = self
            .last_successful_sample_at
            .map(|previous| sampled_at.saturating_duration_since(previous).as_secs_f64());

        // ── Snapshot current byte counters for next tick's rate calculation ──
        let current_counters: HashMap<String, (u64, u64)> = data
            .interfaces
            .iter()
            .filter_map(|iface| Some((iface.name.clone(), (iface.rx_byte?, iface.tx_byte?))))
            .collect();
        let current_uptime_seconds = data.system.uptime_seconds;

        // Count DHCP leases for IP allocations
        let ip_allocations = data
            .dhcp_leases
            .iter()
            .filter(|l| l.status == "bound")
            .count() as u32;

        let previous_sample = self.last_successful_sample_at.map(|_| {
            crate::poller::transform::PreviousCounterSample {
                counters: &self.prev_counters,
                uptime_seconds: self.prev_uptime_seconds,
                elapsed_secs: sample_elapsed_secs
                    .expect("elapsed time must accompany a successful sample"),
            }
        });
        let mut snapshot = crate::poller::transform::to_dashboard_snapshot(
            data,
            previous_sample,
            Vec::new(), // Will be filled in poll_tick
            IspStability {
                online_rate: 100.0,
                segments: vec![],
                window_minutes: 30,
            },
            monthly_usage_gb,
        )?;

        // The dashboard rate baseline is independent of the durable per-interface
        // baselines, which advance only inside successful DB transactions above.
        self.prev_counters = current_counters;
        self.prev_uptime_seconds = current_uptime_seconds;
        self.last_successful_sample_at = Some(sampled_at);

        // Update IP allocations in gateway info
        snapshot.gateway.ip_allocations = ip_allocations;

        Ok(PollSnapshot {
            snapshot,
            storage_errors,
        })
    }

    /// Compute a shallow diff between two snapshots.
    ///
    /// Only fields that changed are included in the update.
    fn diff_snapshots(
        &self,
        prev: &DashboardSnapshot,
        current: &DashboardSnapshot,
    ) -> DashboardUpdate {
        let traffic = current.traffic.points.last().cloned();

        DashboardUpdate {
            system: if prev.system != current.system {
                Some(current.system.clone())
            } else {
                None
            },
            gateway: if prev.gateway != current.gateway {
                Some(current.gateway.clone())
            } else {
                None
            },
            interfaces: if prev.interfaces != current.interfaces {
                Some(current.interfaces.clone())
            } else {
                None
            },
            isp: if prev.isp != current.isp {
                Some(current.isp.clone())
            } else {
                None
            },
            traffic,
            latency_probes: if prev.latency_probes != current.latency_probes {
                Some(current.latency_probes.clone())
            } else {
                None
            },
            wifi: if prev.wifi != current.wifi {
                Some(current.wifi.clone())
            } else {
                None
            },
            stability: if prev.stability != current.stability {
                Some(current.stability.clone())
            } else {
                None
            },
            interface_statuses: if prev.interface_statuses != current.interface_statuses {
                Some(current.interface_statuses.clone())
            } else {
                None
            },
            timestamp: current.timestamp.clone(),
            wans: if prev.wans != current.wans {
                Some(current.wans.clone())
            } else {
                None
            },
            wans_isp: if prev.wans_isp != current.wans_isp {
                Some(current.wans_isp.clone())
            } else {
                None
            },
            wan_traffic_points: if !current.wan_traffic_points.is_empty() {
                Some(current.wan_traffic_points.clone())
            } else {
                None
            },
        }
    }

    /// Check if a differential update has any actual changes.
    fn has_changes(&self, update: &DashboardUpdate) -> bool {
        update.system.is_some()
            || update.gateway.is_some()
            || update.interfaces.is_some()
            || update.isp.is_some()
            || update.traffic.is_some()
            || update.latency_probes.is_some()
            || update.wifi.is_some()
            || update.stability.is_some()
            || update.interface_statuses.is_some()
            || update.wans.is_some()
            || update.wans_isp.is_some()
            || update.wan_traffic_points.is_some()
    }

    /// Build ISP stability from rolling probe quality history.
    ///
    /// Produces three segments: Good (green), Degraded (amber), Down (gray).
    /// Online rate counts Good + Degraded as "online" (degraded is still usable).
    ///
    /// `probe_interval_secs` is used to calculate the real time window.
    fn build_stability(&self, probe_interval_secs: u64) -> IspStability {
        let total = self.stability_history.len() as f64;
        if total == 0.0 {
            return IspStability {
                online_rate: 100.0,
                segments: vec![StabilitySegment {
                    color: "#22c55e".into(),
                    value: 30.0,
                    label: Some("100%".into()),
                }],
                window_minutes: 30,
            };
        }

        let good = self
            .stability_history
            .iter()
            .filter(|s| matches!(s, ProbeQuality::Good))
            .count() as f64;
        let degraded = self
            .stability_history
            .iter()
            .filter(|s| matches!(s, ProbeQuality::Degraded))
            .count() as f64;
        let down = self
            .stability_history
            .iter()
            .filter(|s| matches!(s, ProbeQuality::Down))
            .count() as f64;

        // Online rate = Good + Degraded (degraded is still online, just degraded quality)
        let online_rate = ((good + degraded) / total) * 100.0;

        // Actual time window = history_entries × probe_interval
        let window_minutes =
            ((self.stability_history.len() as u64 * probe_interval_secs) / 60).max(1) as u32;

        let segments = vec![
            StabilitySegment {
                color: "#22c55e".into(),
                value: good,
                label: Some(format!("{:.1}%", online_rate)),
            },
            StabilitySegment {
                color: "#f59e0b".into(),
                value: degraded,
                label: if degraded > 0.0 {
                    Some(format!("{:.0}", degraded))
                } else {
                    None
                },
            },
            StabilitySegment {
                color: "#6b7280".into(),
                value: down,
                label: None,
            },
        ];

        IspStability {
            online_rate,
            segments,
            window_minutes,
        }
    }
}

fn persist_exact_traffic(
    traffic_db: &TrafficDb,
    baselines: &mut HashMap<i64, CounterBaseline>,
    router_id: i64,
    data: &RouterData,
    wan_names: &[String],
) -> Result<ExactPersistenceResult, DatabaseError> {
    let observed_at_ms = data.counter_sample_time.unix_ms;
    let aggregate_interface = traffic_db.upsert_router_interface(
        router_id,
        AGGREGATE_INTERFACE_KEY,
        "Aggregate",
        "aggregate",
        None,
        observed_at_ms,
    )?;
    let mut errors = Vec::new();
    let mut active_interface_ids = HashSet::from([aggregate_interface.id]);
    let mut aggregate_rx = 0_u64;
    let mut aggregate_tx = 0_u64;
    let mut aggregate_complete = !wan_names.is_empty();
    let mut aggregate_continuous = !wan_names.is_empty();
    let mut aggregate_members = Vec::with_capacity(wan_names.len());

    for wan_name in wan_names {
        let Some(interface) = data
            .interfaces
            .iter()
            .find(|interface| interface.name == *wan_name)
        else {
            aggregate_complete = false;
            errors.push(format!(
                "WAN interface {wan_name} disappeared during sampling"
            ));
            continue;
        };

        let interface_key = durable_interface_key(interface);
        let hardware_id =
            (!interface.mac_address.trim().is_empty()).then_some(interface.mac_address.as_str());
        let record = match traffic_db.upsert_router_interface(
            router_id,
            &interface_key,
            &interface.name,
            "wan",
            hardware_id,
            observed_at_ms,
        ) {
            Ok(record) => record,
            Err(error) => {
                aggregate_complete = false;
                errors.push(format!(
                    "failed to resolve WAN interface {}: {error}",
                    interface.name
                ));
                continue;
            }
        };
        active_interface_ids.insert(record.id);
        aggregate_members.push(record.id);

        let (Some(rx_counter), Some(tx_counter)) = (interface.rx_byte, interface.tx_byte) else {
            aggregate_complete = false;
            baselines.remove(&record.id);
            errors.push(format!(
                "WAN interface {} omitted a byte counter; exact sampling paused",
                interface.name
            ));
            continue;
        };
        let observation = CounterObservation {
            router_id,
            interface_id: record.id,
            rx_counter,
            tx_counter,
            observed_at_ms,
            monotonic: data.counter_sample_time.monotonic,
            uptime_seconds: data.system.uptime_seconds,
            member_signature: None,
            forced_gap: None,
        };
        match persist_counter_observation(traffic_db, baselines, &observation) {
            Ok(CounterPersistenceOutcome::ExactSample) => {}
            Ok(CounterPersistenceOutcome::Initialized | CounterPersistenceOutcome::Gap) => {
                aggregate_continuous = false;
            }
            Err(error) => {
                aggregate_continuous = false;
                errors.push(format!(
                    "failed to persist WAN interface {}: {error}",
                    interface.name
                ));
            }
        }

        match (
            aggregate_rx.checked_add(rx_counter),
            aggregate_tx.checked_add(tx_counter),
        ) {
            (Some(rx), Some(tx)) => {
                aggregate_rx = rx;
                aggregate_tx = tx;
            }
            _ => {
                aggregate_complete = false;
                errors.push("aggregate WAN counters overflowed u64".to_string());
            }
        }
    }

    aggregate_members.sort_unstable();
    let aggregate_signature = aggregate_members
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if aggregate_complete {
        let observation = CounterObservation {
            router_id,
            interface_id: aggregate_interface.id,
            rx_counter: aggregate_rx,
            tx_counter: aggregate_tx,
            observed_at_ms,
            monotonic: data.counter_sample_time.monotonic,
            uptime_seconds: data.system.uptime_seconds,
            member_signature: Some(&aggregate_signature),
            forced_gap: (!aggregate_continuous).then_some((
                "wan_member_discontinuity",
                "one or more aggregate WAN members lacked an exact interval",
            )),
        };
        if let Err(error) = persist_counter_observation(traffic_db, baselines, &observation) {
            errors.push(format!("failed to persist aggregate WAN traffic: {error}"));
        }
    } else {
        baselines.remove(&aggregate_interface.id);
    }

    baselines.retain(|interface_id, _| active_interface_ids.contains(interface_id));
    Ok(ExactPersistenceResult {
        router_id,
        aggregate_interface_id: aggregate_interface.id,
        errors,
    })
}

fn durable_interface_key(interface: &InterfaceEntry) -> String {
    if interface.id.trim().is_empty() {
        format!("name:{}", interface.name)
    } else {
        format!("routeros:{}", interface.id)
    }
}

fn persist_counter_observation(
    traffic_db: &TrafficDb,
    baselines: &mut HashMap<i64, CounterBaseline>,
    observation: &CounterObservation<'_>,
) -> Result<CounterPersistenceOutcome, DatabaseError> {
    let current_marker = boot_marker(observation.observed_at_ms, observation.uptime_seconds);
    let rx_counter = observation.rx_counter.to_string();
    let tx_counter = observation.tx_counter.to_string();

    let Some(previous) = baselines.get(&observation.interface_id).cloned() else {
        let checkpoint = CounterCheckpointInput {
            router_id: observation.router_id,
            interface_id: observation.interface_id,
            rx_counter: &rx_counter,
            tx_counter: &tx_counter,
            observed_at_ms: observation.observed_at_ms,
            reboot_marker: current_marker.as_deref(),
        };
        if traffic_db.initialize_checkpoint_if_absent(&checkpoint)? {
            baselines.insert(
                observation.interface_id,
                baseline_from_observation(observation, current_marker),
            );
            return Ok(CounterPersistenceOutcome::Initialized);
        }

        let existing = traffic_db
            .counter_checkpoint(observation.router_id, observation.interface_id)?
            .ok_or_else(|| {
                DatabaseError::Verification(
                    "counter checkpoint disappeared after initialization conflict".into(),
                )
            })?;
        if observation.observed_at_ms == existing.observed_at_ms
            && existing.rx_counter == rx_counter
            && existing.tx_counter == tx_counter
            && existing.reboot_marker.as_deref() == current_marker.as_deref()
        {
            baselines.insert(
                observation.interface_id,
                baseline_from_observation(observation, current_marker),
            );
            return Ok(CounterPersistenceOutcome::Initialized);
        }
        if observation.observed_at_ms <= existing.observed_at_ms {
            return Err(DatabaseError::Verification(format!(
                "counter sample timestamp {} does not advance checkpoint {}",
                observation.observed_at_ms, existing.observed_at_ms
            )));
        }
        let gap = TrafficGapInput {
            router_id: observation.router_id,
            interface_id: Some(observation.interface_id),
            started_at_ms: existing.observed_at_ms,
            ended_at_ms: observation.observed_at_ms,
            reason: "poller_discontinuity",
            details: Some("counter baseline was unavailable in the current process"),
        };
        traffic_db.commit_gap_and_checkpoint(&gap, &checkpoint)?;
        baselines.insert(
            observation.interface_id,
            baseline_from_observation(observation, current_marker),
        );
        return Ok(CounterPersistenceOutcome::Gap);
    };

    if observation.observed_at_ms <= previous.observed_at_ms {
        return Err(DatabaseError::Verification(format!(
            "counter sample timestamp {} does not advance baseline {}",
            observation.observed_at_ms, previous.observed_at_ms
        )));
    }
    let elapsed = observation
        .monotonic
        .saturating_duration_since(previous.monotonic);
    let wall_elapsed_ms = observation
        .observed_at_ms
        .saturating_sub(previous.observed_at_ms);
    let current_boot_epoch =
        estimated_boot_epoch(observation.observed_at_ms, observation.uptime_seconds);
    let uptime_continuous =
        previous.uptime_seconds.is_some() && observation.uptime_seconds.is_some();
    let rebooted = previous
        .uptime_seconds
        .zip(observation.uptime_seconds)
        .is_some_and(|(previous, current)| current < previous)
        || previous
            .boot_epoch_seconds
            .zip(current_boot_epoch)
            .is_some_and(|(previous, current)| previous.abs_diff(current) > 5);
    let marker = if rebooted {
        current_marker
    } else {
        previous.reboot_marker.clone().or(current_marker)
    };
    let checkpoint = CounterCheckpointInput {
        router_id: observation.router_id,
        interface_id: observation.interface_id,
        rx_counter: &rx_counter,
        tx_counter: &tx_counter,
        observed_at_ms: observation.observed_at_ms,
        reboot_marker: marker.as_deref(),
    };

    let member_changed = previous.member_signature.as_deref() != observation.member_signature;
    let clock_consistent = sampling_clocks_are_consistent(wall_elapsed_ms, elapsed);
    let elapsed_secs = elapsed.as_secs_f64();
    let rx_rate = crate::poller::transform::calculate_counter_rate(
        Some(previous.rx_counter),
        observation.rx_counter,
        previous.uptime_seconds,
        observation.uptime_seconds,
        Some(elapsed_secs),
    );
    let tx_rate = crate::poller::transform::calculate_counter_rate(
        Some(previous.tx_counter),
        observation.tx_counter,
        previous.uptime_seconds,
        observation.uptime_seconds,
        Some(elapsed_secs),
    );

    let exact_deltas = rx_rate
        .delta_bytes
        .zip(tx_rate.delta_bytes)
        .zip(rx_rate.bits_per_second.zip(tx_rate.bits_per_second));
    let exact_deltas = exact_deltas.and_then(|((rx, tx), (rx_bps, tx_bps))| {
        Some((
            i64::try_from(rx).ok()?,
            i64::try_from(tx).ok()?,
            rx_bps,
            tx_bps,
        ))
    });

    if !member_changed
        && observation.forced_gap.is_none()
        && !rebooted
        && uptime_continuous
        && clock_consistent
    {
        if let Some((download_bytes, upload_bytes, download_bps, upload_bps)) = exact_deltas {
            let sample = TrafficSampleInput {
                router_id: observation.router_id,
                interface_id: observation.interface_id,
                started_at_ms: previous.observed_at_ms,
                ended_at_ms: observation.observed_at_ms,
                duration_ms: wall_elapsed_ms,
                download_bytes,
                upload_bytes,
                download_bps,
                upload_bps,
                quality: TrafficQuality::Exact,
                source: EXACT_TRAFFIC_SOURCE,
            };
            traffic_db.commit_sample_and_checkpoint(&sample, &checkpoint)?;
            baselines.insert(
                observation.interface_id,
                baseline_from_observation(observation, marker),
            );
            return Ok(CounterPersistenceOutcome::ExactSample);
        }
    }

    let (reason, details) = if member_changed {
        (
            "wan_membership_changed",
            "aggregate WAN interface membership changed",
        )
    } else if let Some(forced_gap) = observation.forced_gap {
        forced_gap
    } else if !uptime_continuous {
        (
            "uptime_unavailable",
            "router uptime was unavailable for reboot detection",
        )
    } else if rebooted {
        ("router_rebooted", "router uptime decreased between samples")
    } else if !clock_consistent {
        (
            "clock_discontinuity",
            "wall-clock and monotonic sample intervals diverged",
        )
    } else if matches!(
        rx_rate.transition,
        crate::poller::transform::CounterTransition::Reset
    ) || matches!(
        tx_rate.transition,
        crate::poller::transform::CounterTransition::Reset
    ) {
        ("counter_reset", "one or more interface counters decreased")
    } else if matches!(
        rx_rate.transition,
        crate::poller::transform::CounterTransition::InvalidElapsed
    ) || matches!(
        tx_rate.transition,
        crate::poller::transform::CounterTransition::InvalidElapsed
    ) {
        ("invalid_elapsed", "counter sample elapsed time was invalid")
    } else {
        (
            "counter_discontinuity",
            "counter delta could not be represented as an exact SQLite integer",
        )
    };
    let gap = TrafficGapInput {
        router_id: observation.router_id,
        interface_id: Some(observation.interface_id),
        started_at_ms: previous.observed_at_ms,
        ended_at_ms: observation.observed_at_ms,
        reason,
        details: Some(details),
    };
    traffic_db.commit_gap_and_checkpoint(&gap, &checkpoint)?;
    baselines.insert(
        observation.interface_id,
        baseline_from_observation(observation, marker),
    );
    Ok(CounterPersistenceOutcome::Gap)
}

fn baseline_from_observation(
    observation: &CounterObservation<'_>,
    reboot_marker: Option<String>,
) -> CounterBaseline {
    CounterBaseline {
        rx_counter: observation.rx_counter,
        tx_counter: observation.tx_counter,
        observed_at_ms: observation.observed_at_ms,
        monotonic: observation.monotonic,
        uptime_seconds: observation.uptime_seconds,
        boot_epoch_seconds: estimated_boot_epoch(
            observation.observed_at_ms,
            observation.uptime_seconds,
        ),
        reboot_marker,
        member_signature: observation.member_signature.map(str::to_string),
    }
}

fn boot_marker(observed_at_ms: i64, uptime_seconds: Option<u64>) -> Option<String> {
    estimated_boot_epoch(observed_at_ms, uptime_seconds)
        .map(|boot_epoch| format!("boot-epoch:{boot_epoch}"))
}

fn estimated_boot_epoch(observed_at_ms: i64, uptime_seconds: Option<u64>) -> Option<i64> {
    uptime_seconds.map(|uptime| {
        let uptime = i64::try_from(uptime).unwrap_or(i64::MAX);
        observed_at_ms.div_euclid(1000).saturating_sub(uptime)
    })
}

fn sampling_clocks_are_consistent(wall_elapsed_ms: i64, monotonic_elapsed: Duration) -> bool {
    if wall_elapsed_ms <= 0 || monotonic_elapsed.is_zero() {
        return false;
    }
    let monotonic_ms = i64::try_from(monotonic_elapsed.as_millis()).unwrap_or(i64::MAX);
    let difference = wall_elapsed_ms.abs_diff(monotonic_ms);
    let tolerance = 250_u64.saturating_add(monotonic_ms.unsigned_abs() / 100);
    difference <= tolerance
}

fn monthly_usage_gb_v4(
    traffic_db: &TrafficDb,
    router_id: i64,
    aggregate_interface_id: i64,
    now_ms: i64,
) -> Result<f64, DatabaseError> {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms).ok_or_else(|| {
        DatabaseError::Verification("counter sample contains an invalid Unix timestamp".into())
    })?;
    let month_start = now
        .with_day(1)
        .and_then(|value| value.with_hour(0))
        .and_then(|value| value.with_minute(0))
        .and_then(|value| value.with_second(0))
        .and_then(|value| value.with_nanosecond(0))
        .ok_or_else(|| DatabaseError::Verification("failed to calculate month boundary".into()))?;
    if month_start.timestamp_millis() >= now_ms {
        return Ok(0.0);
    }
    let result = traffic_db.query_traffic_v4(&TrafficQuery {
        router_id,
        interface_id: aggregate_interface_id,
        from_ms: month_start.timestamp_millis(),
        to_ms: now_ms,
        max_points: 1,
    })?;
    let download = result
        .totals
        .download_bytes
        .parse::<f64>()
        .map_err(|_| DatabaseError::Verification("invalid monthly download total".into()))?;
    let upload = result
        .totals
        .upload_bytes
        .parse::<f64>()
        .map_err(|_| DatabaseError::Verification("invalid monthly upload total".into()))?;
    Ok((download + upload) / 1_000_000_000.0)
}

// ═══════════════════════════════════════════════════════════════════
// Backend Dispatch
// ═══════════════════════════════════════════════════════════════════

/// Create a backend instance based on the router type in the connection config.
async fn connect_backend(
    config: &RouterConnectionConfig,
) -> Result<Box<dyn RouterBackend>, AppError> {
    use crate::backends::routeros::client::RouterOsClient;

    match config.router_type {
        RouterType::RouterOs => {
            let client = RouterOsClient::connect(config).await?;
            Ok(Box::new(client))
        } // Future backends: add a match arm here
    }
}

// ═══════════════════════════════════════════════════════════════════
// ICMP Latency Probe — real ping via surge-ping
// ═══════════════════════════════════════════════════════════════════

/// Run ICMP pings against all probe targets concurrently.
///
/// Uses surge-ping for raw ICMP echo requests. Each spawned task creates
/// its own ICMP socket. All targets are pinged in parallel via `tokio::spawn`.
async fn run_icmp_probes(
    targets: &[(String, String, String)],
    latency_good_ms: f64,
    latency_poor_ms: f64,
) -> Vec<LatencyProbe> {
    // Fire all pings concurrently — each task owns its Client (raw socket)
    let handles: Vec<_> = targets
        .iter()
        .map(|(name, host, cat)| {
            let name = name.clone();
            let host = host.clone();
            let category = cat.clone();
            let good = latency_good_ms;
            let poor = latency_poor_ms;
            let task_name = name.clone();
            let task_host = host.clone();
            let task_category = category.clone();
            (
                task_name,
                task_host,
                task_category,
                tokio::spawn(async move { probe_one(&name, &host, &category, good, poor).await }),
            )
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for (name, host, category, handle) in handles {
        match handle.await {
            Ok(probe) => results.push(probe),
            Err(e) => {
                warn!("Probe task for {name} ({host}) failed: {e}");
                results.push(LatencyProbe {
                    target: name,
                    host,
                    latency_ms: None,
                    status: "unknown".to_string(),
                    category,
                });
            }
        }
    }
    results
}

/// Send N ICMP pings to a host, collecting individual RTTs.
///
/// Returns a vector of latencies (in ms) for successful pings.
/// Failed or timed-out pings are omitted.
async fn send_n_pings(pinger: &mut surge_ping::Pinger, host: &str) -> Vec<f64> {
    let mut latencies = Vec::with_capacity(PING_COUNT);
    for seq in 0..PING_COUNT {
        // First ping fires immediately; subsequent pings are spaced by PING_GAP_MS.
        if seq > 0 {
            tokio::time::sleep(Duration::from_millis(PING_GAP_MS)).await;
        }

        let result = tokio::time::timeout(
            Duration::from_secs(PING_TIMEOUT_SECS),
            pinger.ping(surge_ping::PingSequence(seq as u16), &[0u8; 56]),
        )
        .await;

        match result {
            Ok(Ok((_packet, rtt))) => {
                latencies.push(rtt.as_secs_f64() * 1000.0);
            }
            Ok(Err(ref e)) => {
                debug!("Ping #{seq} to {host} failed: {e}");
            }
            Err(_) => {
                debug!("Ping #{seq} to {host} timed out");
            }
        }
    }
    latencies
}

/// Ping a single target: resolve hostname → send N ICMP pings → majority-vote decision.
async fn probe_one(
    name: &str,
    host: &str,
    category: &str,
    latency_good_ms: f64,
    latency_poor_ms: f64,
) -> LatencyProbe {
    let down = || LatencyProbe {
        target: name.to_string(),
        host: host.to_string(),
        latency_ms: None,
        status: "down".to_string(),
        category: category.to_string(),
    };

    let unknown = || LatencyProbe {
        target: name.to_string(),
        host: host.to_string(),
        latency_ms: None,
        status: "unknown".to_string(),
        category: category.to_string(),
    };

    // Resolve hostname → IP
    let ip = match resolve_host(host).await {
        Some(ip) => ip,
        None => return down(),
    };

    // Create ICMP client + pinger — choose ICMP kind based on resolved IP family
    let config = match ip {
        IpAddr::V4(_) => surge_ping::Config::new(),
        IpAddr::V6(_) => surge_ping::Config::builder()
            .kind(surge_ping::ICMP::V6)
            .build(),
    };
    let client = match surge_ping::Client::new(&config) {
        Ok(c) => c,
        Err(e) => {
            debug!("ICMP client failed for {host}: {e}");
            return unknown();
        }
    };

    let mut pinger = client.pinger(ip, surge_ping::PingIdentifier(0)).await;

    let latencies = send_n_pings(&mut pinger, host).await;
    let success = latencies.len();

    // ── Majority-vote decision ──
    if success > PING_COUNT / 2 {
        // Majority succeeded: use average RTT
        let avg_ms = latencies.iter().sum::<f64>() / success as f64;
        LatencyProbe {
            target: name.to_string(),
            host: host.to_string(),
            latency_ms: Some(avg_ms),
            status: classify_latency(avg_ms, latency_good_ms, latency_poor_ms),
            category: category.to_string(),
        }
    } else if success > 0 {
        // Minority succeeded — unreliable, treat as down
        debug!(
            "{name} ({host}): only {}/{} pings succeeded, marking down",
            success, PING_COUNT,
        );
        down()
    } else {
        // All failed or timed out
        down()
    }
}

/// Classify the overall network quality from this round's probe results.
///
/// Rules (evaluated in order):
/// 1. All targets unreachable → Down
/// 2. Majority (>50%) unreachable → Down (likely ISP outage)
/// 3. Over 1/3 of targets are poor-latency or unreachable → Degraded
/// 4. Otherwise → Good
fn classify_probe_quality(results: &[LatencyProbe]) -> ProbeQuality {
    let total = results.len();
    if total == 0 {
        return ProbeQuality::Good;
    }

    let reachable = results.iter().filter(|r| r.latency_ms.is_some()).count();
    let down_count = total - reachable;
    let poor_count = results.iter().filter(|r| r.status == "poor").count();
    let problem_count = poor_count + down_count;

    // All or majority unreachable → likely link-down / ISP outage
    if reachable == 0 || down_count > total / 2 {
        return ProbeQuality::Down;
    }

    // More than 1/3 of targets problematic → degraded quality
    if problem_count > total / 3 {
        return ProbeQuality::Degraded;
    }

    ProbeQuality::Good
}

/// Resolve a hostname to an IP address.
/// Returns immediately if the input is already an IP.
async fn resolve_host(host: &str) -> Option<IpAddr> {
    // Already an IP?
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }

    // DNS lookup with a 3-second timeout
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host(format!("{}:0", host)),
    )
    .await;

    match result {
        Ok(Ok(addrs)) => {
            let mut v6 = None;
            for a in addrs {
                match a.ip() {
                    IpAddr::V4(_) => return Some(a.ip()),
                    IpAddr::V6(_) if v6.is_none() => v6 = Some(a.ip()),
                    _ => {}
                }
            }
            v6
        }
        _ => {
            debug!("DNS lookup failed for: {}", host);
            None
        }
    }
}

/// Classify RTT into a status label for the frontend's color coding.
fn classify_latency(ms: f64, good_ms: f64, poor_ms: f64) -> String {
    if ms < good_ms {
        "good".to_string()
    } else if ms < poor_ms {
        "moderate".to_string()
    } else {
        "poor".to_string()
    }
}

fn reconnect_delay(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(5);
    Duration::from_secs((1u64 << exponent).min(MAX_RECONNECT_DELAY_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exact_traffic_fixture() -> (TrafficDb, i64, i64) {
        let db = TrafficDb::open(&PathBuf::from(":memory:")).unwrap();
        let router = db
            .resolve_router(Some("serial-1"), "192.0.2.1", 1_000)
            .unwrap();
        let interface = db
            .upsert_router_interface(
                router.id,
                "routeros:*1",
                "wan1",
                "wan",
                Some("00:11:22:33:44:55"),
                1_000,
            )
            .unwrap();
        (db, router.id, interface.id)
    }

    fn observation(
        router_id: i64,
        interface_id: i64,
        counters: (u64, u64),
        observed_at_ms: i64,
        monotonic: Instant,
        uptime_seconds: u64,
        member_signature: Option<&str>,
    ) -> CounterObservation<'_> {
        CounterObservation {
            router_id,
            interface_id,
            rx_counter: counters.0,
            tx_counter: counters.1,
            observed_at_ms,
            monotonic,
            uptime_seconds: Some(uptime_seconds),
            member_signature,
            forced_gap: None,
        }
    }

    fn observation_with_optional_uptime(
        router_id: i64,
        interface_id: i64,
        rx_counter: u64,
        tx_counter: u64,
        observed_at_ms: i64,
        monotonic: Instant,
        uptime_seconds: Option<u64>,
    ) -> CounterObservation<'static> {
        CounterObservation {
            router_id,
            interface_id,
            rx_counter,
            tx_counter,
            observed_at_ms,
            monotonic,
            uptime_seconds,
            member_signature: None,
            forced_gap: None,
        }
    }

    fn router_data(
        sampled_at_ms: i64,
        monotonic: Instant,
        uptime_seconds: Option<u64>,
        wan_a: (u64, u64),
        wan_b: (u64, u64),
    ) -> RouterData {
        let interface = |id: &str, name: &str, counters: (u64, u64)| InterfaceEntry {
            id: id.into(),
            name: name.into(),
            iface_type: "ether".into(),
            mac_address: format!("00:11:22:33:44:{id}"),
            running: true,
            rx_byte: Some(counters.0),
            tx_byte: Some(counters.1),
            default_name: name.into(),
        };
        let route = |id: &str, interface: &str, distance| crate::backends::RouteEntry {
            id: id.into(),
            dst_address: "0.0.0.0/0".into(),
            gateway: "192.0.2.254".into(),
            gateway_status: "reachable".into(),
            interface: interface.into(),
            active: true,
            disabled: false,
            distance,
        };
        RouterData {
            counter_sample_time: crate::backends::CounterSampleTime {
                monotonic,
                unix_ms: sampled_at_ms,
            },
            system: crate::backends::SystemData {
                hardware_identity: Some("serial-1".into()),
                uptime: String::new(),
                uptime_seconds,
                cpu_load: 0.0,
                free_memory: 0,
                total_memory: 0,
                free_hdd: 0,
                total_hdd: 0,
                architecture_name: String::new(),
                board_name: String::new(),
                version: String::new(),
            },
            identity: crate::backends::IdentityData {
                name: "router".into(),
            },
            ip_addresses: vec![],
            ipv6_addresses: vec![],
            interfaces: vec![
                interface("1", "wan-a", wan_a),
                interface("2", "wan-b", wan_b),
            ],
            routes: vec![route("1", "wan-a", 1), route("2", "wan-b", 2)],
            ipv6_routes: vec![],
            arp_entries: vec![],
            ipv6_neighbors: vec![],
            dhcp_leases: vec![],
            wireless_clients: vec![],
            connection_count: 0,
            ipv6_connection_count: 0,
        }
    }

    #[test]
    fn reconnect_backoff_is_exponential_and_bounded() {
        let delays: Vec<_> = (1..=8).map(reconnect_delay).collect();

        assert_eq!(delays[0], Duration::from_secs(1));
        assert_eq!(delays[1], Duration::from_secs(2));
        assert_eq!(delays[2], Duration::from_secs(4));
        assert_eq!(delays[3], Duration::from_secs(8));
        assert_eq!(delays[4], Duration::from_secs(16));
        assert_eq!(delays[5], Duration::from_secs(30));
        assert_eq!(delays[6], Duration::from_secs(30));
        assert_eq!(delays[7], Duration::from_secs(30));
    }

    #[test]
    fn control_exposes_readiness_and_latches_shutdown() {
        let readiness = PollReadiness {
            state: PollReadinessState::Starting,
            router_connected: false,
            consecutive_failures: 0,
            last_successful_poll: None,
            last_error: None,
        };
        let (readiness_tx, _) = watch::channel(readiness.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let control = PollEngineControl {
            readiness_tx,
            shutdown_tx,
        };

        assert_eq!(control.readiness(), readiness);
        let _subscriber = control.subscribe_readiness();
        control.report_unexpected_exit("task failed");
        assert_eq!(control.readiness().state, PollReadinessState::Stopped);
        assert_eq!(
            control.readiness().last_error.as_deref(),
            Some("task failed")
        );
        control.request_shutdown();
        assert!(*shutdown_rx.borrow());
    }

    #[test]
    fn exact_counter_baseline_does_not_claim_initial_traffic() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let mut baselines = HashMap::new();
        let started = Instant::now();

        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (1_000, 2_000),
                1_000,
                started,
                100,
                None,
            ),
        )
        .unwrap();
        let initial = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 0,
                to_ms: 1_001,
                max_points: 10,
            })
            .unwrap();
        assert!(initial.points.is_empty());
        assert_eq!(initial.coverage.covered_duration_ms, 0);

        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (1_500, 2_750),
                6_000,
                started + Duration::from_secs(5),
                105,
                None,
            ),
        )
        .unwrap();
        let measured = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 1_000,
                to_ms: 6_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(measured.totals.exact_download_bytes, "500");
        assert_eq!(measured.totals.exact_upload_bytes, "750");
        assert_eq!(measured.coverage.exact_duration_ms, 5_000);
        assert_eq!(measured.coverage.gap_count, 0);
    }

    #[test]
    fn process_restart_records_gap_before_resuming_exact_samples() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let started = Instant::now();
        let mut original_process = HashMap::new();
        persist_counter_observation(
            &db,
            &mut original_process,
            &observation(router_id, interface_id, (10, 20), 1_000, started, 100, None),
        )
        .unwrap();

        let mut restarted_process = HashMap::new();
        persist_counter_observation(
            &db,
            &mut restarted_process,
            &observation(
                router_id,
                interface_id,
                (110, 220),
                6_000,
                started + Duration::from_secs(5),
                105,
                None,
            ),
        )
        .unwrap();
        let restart_range = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 1_000,
                to_ms: 6_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(restart_range.totals.download_bytes, "0");
        assert_eq!(restart_range.coverage.gap_count, 1);

        persist_counter_observation(
            &db,
            &mut restarted_process,
            &observation(
                router_id,
                interface_id,
                (160, 300),
                11_000,
                started + Duration::from_secs(10),
                110,
                None,
            ),
        )
        .unwrap();
        let resumed = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 6_000,
                to_ms: 11_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(resumed.totals.exact_download_bytes, "50");
        assert_eq!(resumed.totals.exact_upload_bytes, "80");
    }

    #[test]
    fn reboot_with_higher_counters_is_a_gap_not_exact_traffic() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let mut baselines = HashMap::new();
        let started = Instant::now();
        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (100, 200),
                1_000,
                started,
                10_000,
                None,
            ),
        )
        .unwrap();
        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (500, 700),
                6_000,
                started + Duration::from_secs(5),
                5,
                None,
            ),
        )
        .unwrap();

        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 1_000,
                to_ms: 6_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(result.totals.download_bytes, "0");
        assert_eq!(result.coverage.gap_count, 1);
    }

    #[test]
    fn boot_epoch_detects_reboot_after_uptime_surpasses_old_value() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let mut baselines = HashMap::new();
        let started = Instant::now();
        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (100, 200),
                1_000,
                started,
                10_000,
                None,
            ),
        )
        .unwrap();

        let elapsed = Duration::from_secs(30_000);
        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (50_000, 70_000),
                30_001_000,
                started + elapsed,
                20_000,
                None,
            ),
        )
        .unwrap();

        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 1_000,
                to_ms: 30_001_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(result.totals.download_bytes, "0");
        assert_eq!(result.coverage.gap_count, 1);
    }

    #[test]
    fn missing_uptime_requires_two_continuous_observations_before_exact_traffic() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let mut baselines = HashMap::new();
        let started = Instant::now();
        for (counter, timestamp, elapsed, uptime) in [
            (100, 1_000, 0, Some(100)),
            (150, 6_000, 5, None),
            (200, 11_000, 10, Some(110)),
            (250, 16_000, 15, Some(115)),
        ] {
            persist_counter_observation(
                &db,
                &mut baselines,
                &observation_with_optional_uptime(
                    router_id,
                    interface_id,
                    counter,
                    counter,
                    timestamp,
                    started + Duration::from_secs(elapsed),
                    uptime,
                ),
            )
            .unwrap();
        }

        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id,
                interface_id,
                from_ms: 1_000,
                to_ms: 16_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(result.totals.exact_download_bytes, "50");
        assert_eq!(result.totals.exact_upload_bytes, "50");
        assert_eq!(result.coverage.exact_duration_ms, 5_000);
        assert_eq!(result.coverage.estimated_duration_ms, 0);
        assert_eq!(result.coverage.covered_duration_ms, 5_000);
        assert_eq!(result.coverage.gap_count, 2);
    }

    #[test]
    fn aggregate_gaps_when_one_member_reset_is_masked_by_another_member() {
        let db = TrafficDb::open(&PathBuf::from(":memory:")).unwrap();
        let router = db
            .resolve_router(Some("serial-1"), "192.0.2.1", 1_000)
            .unwrap();
        let started = Instant::now();
        let mut baselines = HashMap::new();
        let first = router_data(1_000, started, Some(100), (1_000, 1_000), (1_000, 1_000));
        let wan_names = crate::poller::transform::wan_interface_names(&first);
        let first_result =
            persist_exact_traffic(&db, &mut baselines, router.id, &first, &wan_names).unwrap();

        let second = router_data(
            6_000,
            started + Duration::from_secs(5),
            Some(105),
            (0, 0),
            (3_000, 3_000),
        );
        let second_wans = crate::poller::transform::wan_interface_names(&second);
        persist_exact_traffic(&db, &mut baselines, router.id, &second, &second_wans).unwrap();

        let aggregate = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: first_result.aggregate_interface_id,
                from_ms: 1_000,
                to_ms: 6_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(aggregate.totals.download_bytes, "0");
        assert_eq!(aggregate.totals.upload_bytes, "0");
        assert_eq!(aggregate.totals.exact_download_bytes, "0");
        assert_eq!(aggregate.totals.exact_upload_bytes, "0");
        assert_eq!(aggregate.coverage.exact_duration_ms, 0);
        assert_eq!(aggregate.coverage.covered_duration_ms, 0);
        assert_eq!(aggregate.coverage.gap_count, 1);

        let wan_b = db
            .traffic_interface_for_query(router.id, Some("wan-b"))
            .unwrap()
            .unwrap();
        let wan_b_result = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: wan_b.id,
                from_ms: 1_000,
                to_ms: 6_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(wan_b_result.totals.exact_download_bytes, "2000");
    }

    #[test]
    fn clock_step_larger_than_sampling_tolerance_creates_gap() {
        assert!(sampling_clocks_are_consistent(
            3_020,
            Duration::from_secs(3)
        ));
        assert!(!sampling_clocks_are_consistent(
            6_000,
            Duration::from_secs(3)
        ));
        assert!(!sampling_clocks_are_consistent(500, Duration::from_secs(3)));
    }

    #[test]
    fn failed_persistence_does_not_advance_the_durable_baseline() {
        let (db, router_id, interface_id) = exact_traffic_fixture();
        let mut baselines = HashMap::new();
        let started = Instant::now();
        persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (100, 200),
                1_000,
                started,
                100,
                None,
            ),
        )
        .unwrap();
        let before = baselines.get(&interface_id).unwrap().clone();

        let error = persist_counter_observation(
            &db,
            &mut baselines,
            &observation(
                router_id,
                interface_id,
                (150, 250),
                1_000,
                started + Duration::from_secs(5),
                105,
                None,
            ),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not advance baseline"));
        let after = baselines.get(&interface_id).unwrap();
        assert_eq!(after.rx_counter, before.rx_counter);
        assert_eq!(after.tx_counter, before.tx_counter);
        assert_eq!(after.observed_at_ms, before.observed_at_ms);
    }
}
