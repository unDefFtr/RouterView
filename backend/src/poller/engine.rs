use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::config_store::MergedConfig;
use crate::db::TrafficDb;
use crate::error::AppError;
use crate::routeros::client::RouterOsClient;
use crate::ws::protocol::*;

/// The poll engine runs on a configurable interval, fetches data from
/// the RouterOS REST API, transforms it into dashboard structures,
/// diffs against the previous snapshot, and broadcasts changes to
/// all connected WebSocket clients.
pub struct PollEngine {
    /// RouterOS HTTP client — None when unconfigured or unreachable.
    client: Option<RouterOsClient>,
    /// Last connection params that produced a working client.
    /// Includes all fields that affect connection; any change triggers reconnect.
    last_conn_params: (String, u16, String, String, String, bool),
    config: Arc<RwLock<MergedConfig>>,
    broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
    /// Shared snapshot cache — written after every poll, read by new WS clients.
    snapshot_cache: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
    /// Previous poll's interface byte counters, keyed by interface name.
    prev_counters: HashMap<String, (u64, u64)>,
    /// Previous poll's full snapshot for diffing.
    prev_snapshot: Option<DashboardSnapshot>,
    /// Whether this is the first successful poll.
    first_poll: bool,
    /// Accumulated traffic history for snapshot initialization.
    traffic_history: Vec<TrafficPoint>,
    /// Per-WAN traffic history buffers, keyed by WAN interface name.
    wan_traffic_history: HashMap<String, Vec<TrafficPoint>>,
    /// Latency probe targets.
    probe_targets: Vec<(String, String, String)>,
    /// Latency probe results from last probe cycle.
    last_probe_results: Vec<LatencyProbe>,
    /// Stability tracking: rolling window of probe success/failure.
    stability_history: Vec<bool>,
    /// SQLite traffic history database.
    traffic_db: Arc<TrafficDb>,
    /// Poll count for periodic DB maintenance.
    poll_count: u64,
}

impl PollEngine {
    pub async fn new(
        config: Arc<RwLock<MergedConfig>>,
        broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
        snapshot_cache: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
        traffic_db: Arc<TrafficDb>,
    ) -> Self {
        let (client, conn_params) = {
            let cfg = config.read().await;
            let params = (
                cfg.routeros_host.clone(),
                cfg.routeros_port,
                cfg.routeros_scheme.clone(),
                cfg.routeros_username.clone(),
                cfg.routeros_password.clone(),
                cfg.accept_invalid_certs,
            );
            match RouterOsClient::new(&cfg).await {
                Ok(c) => {
                    info!("Poll engine: RouterOS client created successfully");
                    (Some(c), params)
                }
                Err(e) => {
                    warn!("Poll engine: RouterOS not available at startup ({e}). Running in config-waiting mode.");
                    (None, params)
                }
            }
        };

        let probe_targets = crate::poller::transform::default_latency_probe_targets(&[]);

        let last_probe_results = run_icmp_probes(&probe_targets).await;

        info!(
            "Poll engine: {} probe targets initialized ({}/{} reachable)",
            last_probe_results.len(),
            last_probe_results.iter().filter(|r| r.latency_ms.is_some()).count(),
            last_probe_results.len(),
        );

        // Broadcast initial connection status
        if client.is_none() {
            let msg = Arc::new(ServerMessage::ConnectionStatus {
                routeros: false,
                last_poll: None,
            });
            let _ = broadcast_tx.send(msg);
        }

        Self {
            client,
            last_conn_params: conn_params,
            config,
            broadcast_tx,
            snapshot_cache,
            prev_counters: HashMap::new(),
            prev_snapshot: None,
            first_poll: true,
            traffic_history: Vec::with_capacity(7200),
            wan_traffic_history: HashMap::new(),
            probe_targets,
            last_probe_results,
            stability_history: Vec::with_capacity(30),
            traffic_db,
            poll_count: 0,
        }
    }

    /// Attempt to rebuild the RouterOS client from current config.
    /// Returns true if a new client was created.
    async fn try_reconnect(&mut self) -> bool {
        let current_params = {
            let cfg = self.config.read().await;
            (
                cfg.routeros_host.clone(),
                cfg.routeros_port,
                cfg.routeros_scheme.clone(),
                cfg.routeros_username.clone(),
                cfg.routeros_password.clone(),
                cfg.accept_invalid_certs,
            )
        };

        // Only reconnect if connection params actually changed or we have no client
        let params_changed = self.last_conn_params != current_params;
        if !params_changed && self.client.is_some() {
            return false;
        }

        if params_changed {
            let (ref host, port, ref scheme, _, _, _) = current_params;
            info!("Poll engine: config changed, reconnecting to {host}:{port} ({scheme})");
        }

        let cfg = self.config.read().await;
        match RouterOsClient::new(&cfg).await {
            Ok(c) => {
                info!("Poll engine: reconnected to RouterOS successfully");
                self.client = Some(c);
                self.last_conn_params = current_params;
                self.first_poll = true; // force full snapshot
                true
            }
            Err(e) => {
                warn!("Poll engine: reconnect failed — {e}");
                if params_changed {
                    self.last_conn_params = current_params; // don't retry same params on every tick
                }
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
        let mut next_poll = tokio::time::Instant::now() + Duration::from_secs(poll_secs);
        let mut next_probe = tokio::time::Instant::now() + Duration::from_secs(probe_secs);

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(next_poll) => {
                    self.poll_tick().await;
                    let secs = {
                        let cfg = self.config.read().await;
                        cfg.poll_interval_secs
                    };
                    next_poll = tokio::time::Instant::now() + Duration::from_secs(secs);
                }
                _ = tokio::time::sleep_until(next_probe) => {
                    self.probe_tick().await;
                    let secs = {
                        let cfg = self.config.read().await;
                        cfg.probe_interval_secs
                    };
                    next_probe = tokio::time::Instant::now() + Duration::from_secs(secs);
                }
            }
        }
    }

    /// Execute one poll cycle: fetch, transform, diff, broadcast.
    /// If no RouterOS client is available, try reconnecting and broadcast
    /// disconnected status until the user configures connection params.
    /// When config changes, reconnects automatically.
    async fn poll_tick(&mut self) {
        // Always check for config changes — reconnect if params changed
        // or if we have no working client.
        self.try_reconnect().await;

        // Still no client — broadcast disconnected and skip this tick
        if self.client.is_none() {
            debug!("Poll tick skipped — no RouterOS connection");
            let msg = Arc::new(ServerMessage::ConnectionStatus {
                routeros: false,
                last_poll: Some(chrono::Utc::now().to_rfc3339()),
            });
            let _ = self.broadcast_tx.send(msg);
            return;
        }

        match self.fetch_and_transform().await {
            Ok(snapshot) => {
                // Update latency probes with latest results
                let mut snapshot = snapshot;
                snapshot.latency_probes = self.last_probe_results.clone();

                // Build ISP stability from history
                snapshot.stability = self.build_stability();

                // Apply user device overrides from the database
                crate::db::apply_device_overrides(&mut snapshot.wifi, &self.traffic_db);

                // ── Traffic history: push latest point, prune to 6h window ──
                // Clone out the point first to release the immutable borrow on
                // snapshot.traffic.points before we overwrite it below.
                let latest_pt = {
                    snapshot.traffic.points.first().cloned()
                };
                if let Some(ref pt) = latest_pt {
                    // DB persist aggregate traffic
                    let ts_ms = timestamp_to_ms(&pt.timestamp);
                    self.traffic_db.insert(ts_ms, pt.download_bps, pt.upload_bps, "");

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
                        let ts_ms = timestamp_to_ms(&wan_pt.timestamp);
                        self.traffic_db.insert(
                            ts_ms,
                            wan_pt.download_bps,
                            wan_pt.upload_bps,
                            wan_name,
                        );

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

                // Periodic DB maintenance: aggregate + prune every 60 polls
                self.poll_count += 1;
                if self.poll_count % 60 == 0 {
                    let (raw_days, total_days) = {
                        let cfg = self.config.read().await;
                        (cfg.db_raw_retention_days as i64, cfg.db_total_retention_days as i64)
                    };
                    self.traffic_db.aggregate_and_prune(raw_days, total_days);
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

                // Also broadcast connection status if previously down
                // (handled implicitly by receiving data)
            }
            Err(e) => {
                warn!("Poll failed: {e}");
                let msg = Arc::new(ServerMessage::ConnectionStatus {
                    routeros: false,
                    last_poll: Some(chrono::Utc::now().to_rfc3339()),
                });
                let _ = self.broadcast_tx.send(msg);
            }
        }
    }

    /// Execute one latency probe cycle — send ICMP pings via surge-ping.
    async fn probe_tick(&mut self) {
        debug!(
            "Probe tick — pinging {} targets",
            self.probe_targets.len()
        );

        let results = run_icmp_probes(&self.probe_targets).await;

        // Update stability: any target reachable → ISP is up
        let any_ok = results.iter().any(|r| r.latency_ms.is_some());
        self.stability_history.push(any_ok);
        if self.stability_history.len() > 30 {
            self.stability_history.remove(0);
        }

        let ok = results.iter().filter(|r| r.latency_ms.is_some()).count();
        let total = results.len();
        debug!("Probe complete: {}/{} targets reachable", ok, total);

        self.last_probe_results = results;
    }

    /// Fetch all RouterOS endpoints and transform into a snapshot.
    /// Only called when `self.client` is `Some`.
    async fn fetch_and_transform(&mut self) -> Result<DashboardSnapshot, AppError> {
        let client = self.client.as_ref().expect("client must be Some when fetch_and_transform is called");

        let poll_interval_secs = {
            let cfg = self.config.read().await;
            cfg.poll_interval_secs as f64
        };

        // Fetch all endpoints in parallel
        let (
            sys_result,
            identity_result,
            ips_result,
            interfaces_result,
            arp_result,
            dns_result,
            leases_result,
            wireless_result,
            routes_result,
        ) = tokio::try_join!(
            client.system_resource(),
            client.system_identity(),
            client.ip_addresses(),
            client.interfaces(),
            client.arp_table(),
            client.dns_config(),
            client.dhcp_leases(),
            client.wireless_registrations(),
            client.routes(),
        )?;

        // ── Snapshot current byte counters for next tick's rate calculation ──
        let current_counters: HashMap<String, (u64, u64)> = interfaces_result
            .iter()
            .map(|iface| {
                (
                    iface.name.clone(),
                    (
                        iface.rx_byte.parse().unwrap_or(0),
                        iface.tx_byte.parse().unwrap_or(0),
                    ),
                )
            })
            .collect();
        let prev = std::mem::replace(&mut self.prev_counters, current_counters);

        // Count DHCP leases for IP allocations
        let ip_allocations = leases_result.len() as u32;

        let mut snapshot = crate::poller::transform::to_dashboard_snapshot(
            sys_result,
            identity_result,
            ips_result,
            interfaces_result,
            arp_result,
            dns_result,
            leases_result,
            wireless_result,
            routes_result,
            Some(&prev),
            Vec::new(),  // Will be filled in poll_tick
            IspStability {
                online_rate: 100.0,
                segments: vec![],
            },
            &self.traffic_db,
            poll_interval_secs,
        )?;

        // Update IP allocations in gateway info
        snapshot.gateway.ip_allocations = ip_allocations;

        Ok(snapshot)
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

    /// Build ISP stability from rolling history.
    fn build_stability(&self) -> IspStability {
        let total = self.stability_history.len() as f64;
        if total == 0.0 {
            return IspStability {
                online_rate: 100.0,
                segments: vec![
                    StabilitySegment {
                        color: "#22c55e".into(),
                        value: 30.0,
                        label: Some("100%".into()),
                    },
                ],
            };
        }

        let successful = self.stability_history.iter().filter(|&&s| s).count() as f64;
        let online_rate = (successful / total) * 100.0;

        let good = successful;
        let bad = total - successful;

        let segments = vec![
            StabilitySegment {
                color: "#22c55e".into(),
                value: good,
                label: Some(format!("{:.1}%", online_rate)),
            },
            StabilitySegment {
                color: "#f59e0b".into(),
                value: 0.0,
                label: None,
            },
            StabilitySegment {
                color: "#6b7280".into(),
                value: bad,
                label: None,
            },
        ];

        IspStability {
            online_rate,
            segments,
        }
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
) -> Vec<LatencyProbe> {
    // Fire all pings concurrently — each task owns its Client (raw socket)
    let handles: Vec<_> = targets
        .iter()
        .map(|(name, host, cat)| {
            let name = name.clone();
            let host = host.clone();
            let category = cat.clone();
            tokio::spawn(async move {
                probe_one(&name, &host, &category).await
            })
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(probe) => results.push(probe),
            Err(e) => warn!("Probe task panicked: {e}"),
        }
    }
    results
}

/// Ping a single target: resolve hostname → ICMP echo → classify RTT.
async fn probe_one(name: &str, host: &str, category: &str) -> LatencyProbe {
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

    // Create ICMP client + pinger for this target
    let client = match surge_ping::Client::new(&surge_ping::Config::new()) {
        Ok(c) => c,
        Err(e) => {
            debug!("ICMP client failed for {host}: {e}");
            return unknown();
        }
    };

    let mut pinger = client
        .pinger(ip, surge_ping::PingIdentifier(0))
        .await;

    // Send ping with 2-second timeout
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        pinger.ping(surge_ping::PingSequence(0), &[0u8; 56]),
    )
    .await;

    match result {
        Ok(Ok((_packet, rtt))) => {
            let ms = rtt.as_secs_f64() * 1000.0;
            LatencyProbe {
                target: name.to_string(),
                host: host.to_string(),
                latency_ms: Some(ms),
                status: classify_latency(ms),
                category: category.to_string(),
            }
        }
        Ok(Err(e)) => {
            debug!("Ping {name} ({host}) failed: {e}");
            down()
        }
        Err(_timeout) => {
            debug!("Ping {name} ({host}) timed out");
            down()
        }
    }
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
        Ok(Ok(mut addrs)) => addrs.next().map(|a| a.ip()),
        _ => {
            debug!("DNS lookup failed for: {}", host);
            None
        }
    }
}

/// Parse an ISO 8601 timestamp to unix milliseconds.
fn timestamp_to_ms(ts: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

/// Classify RTT into a status label for the frontend's color coding.
fn classify_latency(ms: f64) -> String {
    if ms < 30.0 {
        "good".to_string()
    } else if ms < 100.0 {
        "moderate".to_string()
    } else {
        "poor".to_string()
    }
}
