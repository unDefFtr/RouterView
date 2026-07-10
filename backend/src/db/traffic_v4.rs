use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, MutexGuard, TryLockError,
};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Rows, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::types::{DatabaseError, DatabaseResult};
use super::TrafficDb;

const MAX_TRAFFIC_SOURCE_ROWS: usize = 1_000_000;
const ROLLUP_SAMPLE_BATCH_SIZE: usize = 10_000;
const ROLLUP_SAMPLE_BATCH_SQL: &str =
    "SELECT id, router_id, interface_id, started_at_ms, ended_at_ms,
            duration_ms, download_bytes, upload_bytes, quality
     FROM traffic_samples INDEXED BY idx_traffic_samples_rollup_cutoff
     WHERE started_at_ms < ?1
     ORDER BY started_at_ms, id
     LIMIT ?2";
const RETENTION_DELETE_BATCH_SIZE: usize = 10_000;
const PRUNE_TRAFFIC_SAMPLES_BATCH_SQL: &str = "DELETE FROM traffic_samples
     WHERE id IN (
         SELECT id
         FROM traffic_samples INDEXED BY idx_traffic_samples_retention
         WHERE ended_at_ms <= ?1
         ORDER BY ended_at_ms, id
         LIMIT ?2
     )";
const PRUNE_TRAFFIC_ROLLUPS_BATCH_SQL: &str = "DELETE FROM traffic_rollups
     WHERE id IN (
         SELECT id
         FROM traffic_rollups INDEXED BY idx_traffic_rollups_retention
         WHERE bucket_end_ms <= ?1
         ORDER BY bucket_end_ms, id
         LIMIT ?2
     )";
const PRUNE_TRAFFIC_GAPS_BATCH_SQL: &str = "DELETE FROM traffic_gaps
     WHERE id IN (
         SELECT id
         FROM traffic_gaps INDEXED BY idx_traffic_gaps_retention
         WHERE ended_at_ms <= ?1
         ORDER BY ended_at_ms, id
         LIMIT ?2
     )";
const TRAFFIC_QUERY_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);
const TRAFFIC_QUERY_PROGRESS_INTERVAL: i32 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficQuality {
    Exact,
    Estimated,
}

impl TrafficQuality {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Estimated => "estimated",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterRecord {
    pub id: i64,
    pub internal_uuid: String,
    pub hardware_identity: Option<String>,
    pub fallback_target: String,
    pub identity_source: String,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterInterfaceRecord {
    pub id: i64,
    pub router_id: i64,
    pub interface_key: String,
    pub name: String,
    pub kind: String,
    pub hardware_id: Option<String>,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct TrafficSampleInput<'a> {
    pub router_id: i64,
    pub interface_id: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub duration_ms: i64,
    pub download_bytes: i64,
    pub upload_bytes: i64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub quality: TrafficQuality,
    pub source: &'a str,
}

#[derive(Debug, Clone)]
pub struct CounterCheckpointInput<'a> {
    pub router_id: i64,
    pub interface_id: i64,
    pub rx_counter: &'a str,
    pub tx_counter: &'a str,
    pub observed_at_ms: i64,
    pub reboot_marker: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterCheckpoint {
    pub router_id: i64,
    pub interface_id: i64,
    pub rx_counter: String,
    pub tx_counter: String,
    pub observed_at_ms: i64,
    pub reboot_marker: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrafficGapInput<'a> {
    pub router_id: i64,
    pub interface_id: Option<i64>,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub reason: &'a str,
    pub details: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct TrafficQuery {
    pub router_id: i64,
    pub interface_id: i64,
    pub from_ms: i64,
    pub to_ms: i64,
    pub max_points: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficBucket {
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub exact_download_bytes: String,
    pub exact_upload_bytes: String,
    pub estimated_download_bytes: String,
    pub estimated_upload_bytes: String,
    pub exact_duration_ms: i64,
    pub estimated_duration_ms: i64,
    pub sample_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficTotals {
    pub download_bytes: String,
    pub upload_bytes: String,
    pub exact_download_bytes: String,
    pub exact_upload_bytes: String,
    pub estimated_download_bytes: String,
    pub estimated_upload_bytes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficCoverage {
    pub requested_duration_ms: i64,
    pub exact_duration_ms: i64,
    pub estimated_duration_ms: i64,
    pub covered_duration_ms: i64,
    pub completeness: f64,
    pub gap_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficQueryResult {
    pub bucket_size_ms: i64,
    pub points: Vec<TrafficBucket>,
    pub totals: TrafficTotals,
    pub coverage: TrafficCoverage,
}

#[derive(Debug)]
struct RawTrafficSample {
    id: i64,
    router_id: i64,
    interface_id: i64,
    started_at_ms: i64,
    ended_at_ms: i64,
    duration_ms: i64,
    download_bytes: i64,
    upload_bytes: i64,
    quality: String,
}

#[derive(Debug)]
struct RawTrafficRemainder {
    id: i64,
    started_at_ms: i64,
    ended_at_ms: i64,
    download_bytes: i128,
    upload_bytes: i128,
}

impl TrafficDb {
    pub fn resolve_router(
        &self,
        hardware_identity: Option<&str>,
        fallback_target: &str,
        observed_at_ms: i64,
    ) -> DatabaseResult<RouterRecord> {
        let fallback_target = fallback_target.trim();
        if fallback_target.is_empty() {
            return Err(DatabaseError::InvalidCommand(
                "router fallback target must not be empty".into(),
            ));
        }
        let hardware_identity = hardware_identity
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = if let Some(identity) = hardware_identity {
            router_by_hardware_identity(&tx, identity)?
        } else {
            router_by_fallback_target(&tx, fallback_target)?
        };
        let id = if let Some(router) = existing {
            tx.execute(
                "UPDATE routers SET fallback_target = ?1, last_seen_at_ms = ?2 WHERE id = ?3",
                params![fallback_target, observed_at_ms, router.id],
            )?;
            router.id
        } else if let Some(identity) = hardware_identity {
            if let Some(router) = router_by_fallback_only(&tx, fallback_target)? {
                tx.execute(
                    "UPDATE routers
                     SET hardware_identity = ?1, identity_source = 'hardware', last_seen_at_ms = ?2
                     WHERE id = ?3",
                    params![identity, observed_at_ms, router.id],
                )?;
                router.id
            } else {
                insert_router(
                    &tx,
                    Some(identity),
                    fallback_target,
                    "hardware",
                    observed_at_ms,
                )?
            }
        } else {
            insert_router(&tx, None, fallback_target, "fallback", observed_at_ms)?
        };
        adopt_legacy_history(&tx, id, observed_at_ms)?;
        let router = router_by_id(&tx, id)?.ok_or_else(|| {
            DatabaseError::Verification("resolved router disappeared before commit".into())
        })?;
        tx.commit()?;
        Ok(router)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_router_interface(
        &self,
        router_id: i64,
        interface_key: &str,
        name: &str,
        kind: &str,
        hardware_id: Option<&str>,
        observed_at_ms: i64,
    ) -> DatabaseResult<RouterInterfaceRecord> {
        if interface_key.trim().is_empty() || name.trim().is_empty() || kind.trim().is_empty() {
            return Err(DatabaseError::InvalidCommand(
                "interface key, name, and kind must not be empty".into(),
            ));
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute(
            "INSERT INTO router_interfaces(
                 router_id, interface_key, name, kind, hardware_id,
                 first_seen_at_ms, last_seen_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(router_id, interface_key) DO UPDATE SET
                 name = excluded.name,
                 kind = excluded.kind,
                 hardware_id = COALESCE(excluded.hardware_id, router_interfaces.hardware_id),
                 last_seen_at_ms = excluded.last_seen_at_ms",
            params![
                router_id,
                interface_key,
                name,
                kind,
                hardware_id,
                observed_at_ms
            ],
        )?;
        interface_by_key(&conn, router_id, interface_key)?.ok_or_else(|| {
            DatabaseError::Verification("upserted interface could not be reloaded".into())
        })
    }

    pub fn commit_sample_and_checkpoint(
        &self,
        sample: &TrafficSampleInput<'_>,
        checkpoint: &CounterCheckpointInput<'_>,
    ) -> DatabaseResult<bool> {
        validate_sample(sample)?;
        validate_checkpoint(checkpoint)?;
        if sample.router_id != checkpoint.router_id
            || sample.interface_id != checkpoint.interface_id
            || sample.ended_at_ms != checkpoint.observed_at_ms
        {
            return Err(DatabaseError::InvalidCommand(
                "sample and checkpoint must refer to the same router interface and observation"
                    .into(),
            ));
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owns_interface: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM router_interfaces WHERE id = ?1 AND router_id = ?2
             )",
            params![sample.interface_id, sample.router_id],
            |row| row.get(0),
        )?;
        if !owns_interface {
            return Err(DatabaseError::InvalidCommand(
                "interface does not belong to the specified router".into(),
            ));
        }
        let existing_sample = tx
            .query_row(
                "SELECT started_at_ms, duration_ms, download_bytes, upload_bytes,
                        download_bps, upload_bps, quality
                 FROM traffic_samples
                 WHERE router_id = ?1 AND interface_id = ?2
                   AND ended_at_ms = ?3 AND source = ?4",
                params![
                    sample.router_id,
                    sample.interface_id,
                    sample.ended_at_ms,
                    sample.source
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                        row.get::<_, f64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing_sample {
            let sample_matches = existing.0 == sample.started_at_ms
                && existing.1 == sample.duration_ms
                && existing.2 == sample.download_bytes
                && existing.3 == sample.upload_bytes
                && existing.4 == sample.download_bps
                && existing.5 == sample.upload_bps
                && existing.6 == sample.quality.as_str();
            if !sample_matches {
                return Err(DatabaseError::Verification(
                    "duplicate traffic sample key contains different data".into(),
                ));
            }
            let current =
                checkpoint_for_connection(&tx, checkpoint.router_id, checkpoint.interface_id)?
                    .ok_or_else(|| {
                        DatabaseError::Verification(
                            "duplicate traffic sample exists without a counter checkpoint".into(),
                        )
                    })?;
            if current.observed_at_ms < checkpoint.observed_at_ms
                || (current.observed_at_ms == checkpoint.observed_at_ms
                    && !checkpoint_matches(&current, checkpoint))
            {
                return Err(DatabaseError::Verification(
                    "duplicate traffic sample conflicts with its counter checkpoint".into(),
                ));
            }
            return Ok(false);
        }

        if checkpoint_for_connection(&tx, checkpoint.router_id, checkpoint.interface_id)?
            .is_some_and(|current| current.observed_at_ms >= checkpoint.observed_at_ms)
        {
            return Err(DatabaseError::Verification(
                "counter checkpoint must advance strictly with a new sample".into(),
            ));
        }

        tx.execute(
            "INSERT INTO traffic_samples(
                 router_id, interface_id, started_at_ms, ended_at_ms, duration_ms,
                 download_bytes, upload_bytes, download_bps, upload_bps,
                 quality, source, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?4)",
            params![
                sample.router_id,
                sample.interface_id,
                sample.started_at_ms,
                sample.ended_at_ms,
                sample.duration_ms,
                sample.download_bytes,
                sample.upload_bytes,
                sample.download_bps,
                sample.upload_bps,
                sample.quality.as_str(),
                sample.source,
            ],
        )?;
        let checkpoint_updates = tx.execute(
            "INSERT INTO counter_checkpoints(
                 router_id, interface_id, rx_counter, tx_counter, observed_at_ms, reboot_marker
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(router_id, interface_id) DO UPDATE SET
                 rx_counter = excluded.rx_counter,
                 tx_counter = excluded.tx_counter,
                 observed_at_ms = excluded.observed_at_ms,
                 reboot_marker = excluded.reboot_marker
             WHERE excluded.observed_at_ms > counter_checkpoints.observed_at_ms",
            params![
                checkpoint.router_id,
                checkpoint.interface_id,
                checkpoint.rx_counter,
                checkpoint.tx_counter,
                checkpoint.observed_at_ms,
                checkpoint.reboot_marker,
            ],
        )?;
        if checkpoint_updates != 1 {
            return Err(DatabaseError::Verification(
                "counter checkpoint did not advance with the inserted sample".into(),
            ));
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn counter_checkpoint(
        &self,
        router_id: i64,
        interface_id: i64,
    ) -> DatabaseResult<Option<CounterCheckpoint>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        checkpoint_for_connection(&conn, router_id, interface_id)
    }

    /// Establish the first durable counter baseline without claiming traffic coverage.
    ///
    /// Returns `true` when the checkpoint was inserted and `false` when an existing
    /// checkpoint was left untouched. Callers must handle an existing checkpoint as
    /// a sampling discontinuity instead of deriving traffic across a process restart.
    pub fn initialize_checkpoint_if_absent(
        &self,
        checkpoint: &CounterCheckpointInput<'_>,
    ) -> DatabaseResult<bool> {
        validate_checkpoint(checkpoint)?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        ensure_interface_owner(&conn, checkpoint.router_id, Some(checkpoint.interface_id))?;
        let inserted = conn.execute(
            "INSERT INTO counter_checkpoints(
                 router_id, interface_id, rx_counter, tx_counter, observed_at_ms, reboot_marker
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(router_id, interface_id) DO NOTHING",
            params![
                checkpoint.router_id,
                checkpoint.interface_id,
                checkpoint.rx_counter,
                checkpoint.tx_counter,
                checkpoint.observed_at_ms,
                checkpoint.reboot_marker,
            ],
        )?;
        Ok(inserted == 1)
    }

    pub fn commit_gap_and_checkpoint(
        &self,
        gap: &TrafficGapInput<'_>,
        checkpoint: &CounterCheckpointInput<'_>,
    ) -> DatabaseResult<bool> {
        validate_gap(gap)?;
        validate_checkpoint(checkpoint)?;
        if gap.interface_id != Some(checkpoint.interface_id)
            || gap.router_id != checkpoint.router_id
            || gap.ended_at_ms != checkpoint.observed_at_ms
        {
            return Err(DatabaseError::InvalidCommand(
                "gap and checkpoint must refer to the same router interface and observation".into(),
            ));
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_interface_owner(&tx, gap.router_id, gap.interface_id)?;

        let existing_gap = gap_details_for_connection(&tx, gap)?;
        let current_checkpoint =
            checkpoint_for_connection(&tx, checkpoint.router_id, checkpoint.interface_id)?;
        if let Some(details) = existing_gap {
            if details != gap.details.unwrap_or("") {
                return Err(DatabaseError::Verification(
                    "duplicate traffic gap key contains different details".into(),
                ));
            }
            let current = current_checkpoint.ok_or_else(|| {
                DatabaseError::Verification(
                    "traffic gap exists without its counter checkpoint".into(),
                )
            })?;
            if current.observed_at_ms < checkpoint.observed_at_ms
                || (current.observed_at_ms == checkpoint.observed_at_ms
                    && !checkpoint_matches(&current, checkpoint))
            {
                return Err(DatabaseError::Verification(
                    "traffic gap conflicts with its counter checkpoint".into(),
                ));
            }
            return Ok(false);
        }
        if current_checkpoint
            .as_ref()
            .is_some_and(|current| current.observed_at_ms >= checkpoint.observed_at_ms)
        {
            return Err(DatabaseError::Verification(
                "counter checkpoint must advance strictly with a new traffic gap".into(),
            ));
        }

        tx.execute(
            "INSERT INTO traffic_gaps(
                 router_id, interface_id, started_at_ms, ended_at_ms,
                 reason, details, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?4)",
            params![
                gap.router_id,
                gap.interface_id,
                gap.started_at_ms,
                gap.ended_at_ms,
                gap.reason,
                gap.details,
            ],
        )?;
        let checkpoint_updates = tx.execute(
            "INSERT INTO counter_checkpoints(
                 router_id, interface_id, rx_counter, tx_counter, observed_at_ms, reboot_marker
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(router_id, interface_id) DO UPDATE SET
                 rx_counter = excluded.rx_counter,
                 tx_counter = excluded.tx_counter,
                 observed_at_ms = excluded.observed_at_ms,
                 reboot_marker = excluded.reboot_marker
             WHERE excluded.observed_at_ms > counter_checkpoints.observed_at_ms",
            params![
                checkpoint.router_id,
                checkpoint.interface_id,
                checkpoint.rx_counter,
                checkpoint.tx_counter,
                checkpoint.observed_at_ms,
                checkpoint.reboot_marker,
            ],
        )?;
        if checkpoint_updates != 1 {
            return Err(DatabaseError::Verification(
                "counter checkpoint did not advance with the inserted traffic gap".into(),
            ));
        }
        tx.commit()?;
        Ok(true)
    }

    /// Roll up one bounded batch so a maintenance tick cannot load the full
    /// raw-retention backlog into memory or monopolize the database indefinitely.
    /// The return value counts raw rows fully removed; a long row can advance
    /// through a remainder update while the returned count remains zero.
    pub fn rollup_exact_samples(
        &self,
        before_ms: i64,
        bucket_size_ms: i64,
    ) -> DatabaseResult<usize> {
        self.rollup_exact_samples_batch(before_ms, bucket_size_ms, ROLLUP_SAMPLE_BATCH_SIZE)
    }

    fn rollup_exact_samples_batch(
        &self,
        before_ms: i64,
        bucket_size_ms: i64,
        batch_size: usize,
    ) -> DatabaseResult<usize> {
        if bucket_size_ms <= 0 {
            return Err(DatabaseError::InvalidCommand(
                "rollup bucket size must be positive".into(),
            ));
        }
        let segment_budget = batch_size.checked_mul(2).ok_or_else(|| {
            DatabaseError::InvalidCommand("rollup segment budget exceeds process limits".into())
        })?;
        let batch_size = i64::try_from(batch_size).map_err(|_| {
            DatabaseError::InvalidCommand("rollup batch size exceeds SQLite limits".into())
        })?;
        if batch_size <= 0 {
            return Err(DatabaseError::InvalidCommand(
                "rollup batch size must be positive".into(),
            ));
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rollup_end_ms = before_ms;
        let samples = {
            let mut statement = tx.prepare(ROLLUP_SAMPLE_BATCH_SQL)?;
            let rows = statement.query_map(params![rollup_end_ms, batch_size], |row| {
                Ok(RawTrafficSample {
                    id: row.get(0)?,
                    router_id: row.get(1)?,
                    interface_id: row.get(2)?,
                    started_at_ms: row.get(3)?,
                    ended_at_ms: row.get(4)?,
                    duration_ms: row.get(5)?,
                    download_bytes: row.get(6)?,
                    upload_bytes: row.get(7)?,
                    quality: row.get(8)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let mut buckets: BTreeMap<(i64, i64, i64), (TrafficBucketAccumulator, i64, i64)> =
            BTreeMap::new();
        let mut fully_consumed = Vec::new();
        let mut remainders = Vec::new();
        let mut remaining_segments = segment_budget;
        for sample in &samples {
            if remaining_segments == 0 {
                break;
            }
            validate_raw_sample_for_rollup(sample)?;
            let planned_consumed_end = sample.ended_at_ms.min(rollup_end_ms);
            if planned_consumed_end <= sample.started_at_ms {
                continue;
            }
            let split_sample = sample.started_at_ms.div_euclid(bucket_size_ms)
                != (planned_consumed_end - 1).div_euclid(bucket_size_ms)
                || planned_consumed_end != sample.ended_at_ms;
            let mut segment_start = sample.started_at_ms;
            while segment_start < planned_consumed_end && remaining_segments > 0 {
                let bucket_start = segment_start.div_euclid(bucket_size_ms) * bucket_size_ms;
                let bucket_end = bucket_start.saturating_add(bucket_size_ms);
                let segment_end = planned_consumed_end.min(bucket_end);
                let download_bytes = proportional_slice(
                    i128::from(sample.download_bytes),
                    sample.duration_ms,
                    segment_start.saturating_sub(sample.started_at_ms),
                    segment_end.saturating_sub(sample.started_at_ms),
                )?;
                let upload_bytes = proportional_slice(
                    i128::from(sample.upload_bytes),
                    sample.duration_ms,
                    segment_start.saturating_sub(sample.started_at_ms),
                    segment_end.saturating_sub(sample.started_at_ms),
                )?;
                let segment_duration = segment_end.saturating_sub(segment_start);
                let (bucket, _, accumulated_end) = buckets
                    .entry((sample.router_id, sample.interface_id, bucket_start))
                    .or_insert_with(|| {
                        (
                            TrafficBucketAccumulator::default(),
                            segment_start,
                            segment_start,
                        )
                    });
                if segment_start < *accumulated_end {
                    return Err(DatabaseError::Verification(
                        "raw traffic samples overlap during rollup".into(),
                    ));
                }
                *accumulated_end = segment_end;
                if sample.quality == "exact" && !split_sample {
                    bucket.exact_download_bytes += download_bytes;
                    bucket.exact_upload_bytes += upload_bytes;
                    bucket.exact_duration_ms =
                        bucket.exact_duration_ms.saturating_add(segment_duration);
                } else {
                    bucket.estimated_download_bytes += download_bytes;
                    bucket.estimated_upload_bytes += upload_bytes;
                    bucket.estimated_duration_ms = bucket
                        .estimated_duration_ms
                        .saturating_add(segment_duration);
                }
                bucket.sample_count = bucket.sample_count.saturating_add(1);
                segment_start = segment_end;
                remaining_segments -= 1;
            }

            let consumed_end = segment_start;
            if consumed_end == sample.ended_at_ms {
                fully_consumed.push(sample.id);
            } else {
                let consumed_download = proportional_slice(
                    i128::from(sample.download_bytes),
                    sample.duration_ms,
                    0,
                    consumed_end.saturating_sub(sample.started_at_ms),
                )?;
                let consumed_upload = proportional_slice(
                    i128::from(sample.upload_bytes),
                    sample.duration_ms,
                    0,
                    consumed_end.saturating_sub(sample.started_at_ms),
                )?;
                remainders.push(RawTrafficRemainder {
                    id: sample.id,
                    started_at_ms: consumed_end,
                    ended_at_ms: sample.ended_at_ms,
                    download_bytes: i128::from(sample.download_bytes) - consumed_download,
                    upload_bytes: i128::from(sample.upload_bytes) - consumed_upload,
                });
            }
        }

        for ((router_id, interface_id, bucket_start), (bucket, batch_start, bucket_end)) in buckets
        {
            let exact_download = i64::try_from(bucket.exact_download_bytes).map_err(|_| {
                DatabaseError::Verification("rollup download byte total overflowed SQLite".into())
            })?;
            let exact_upload = i64::try_from(bucket.exact_upload_bytes).map_err(|_| {
                DatabaseError::Verification("rollup upload byte total overflowed SQLite".into())
            })?;
            let estimated_download =
                i64::try_from(bucket.estimated_download_bytes).map_err(|_| {
                    DatabaseError::Verification(
                        "estimated rollup download byte total overflowed SQLite".into(),
                    )
                })?;
            let estimated_upload = i64::try_from(bucket.estimated_upload_bytes).map_err(|_| {
                DatabaseError::Verification(
                    "estimated rollup upload byte total overflowed SQLite".into(),
                )
            })?;
            let covered_duration = bucket
                .exact_duration_ms
                .saturating_add(bucket.estimated_duration_ms);
            if covered_duration <= 0 || covered_duration > bucket_size_ms {
                return Err(DatabaseError::Verification(
                    "rollup bucket contains invalid or overlapping sample coverage".into(),
                ));
            }
            let changed = tx.execute(
                "INSERT INTO traffic_rollups(
                     router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
                     exact_download_bytes, exact_upload_bytes,
                     estimated_download_bytes, estimated_upload_bytes,
                     exact_duration_ms, estimated_duration_ms, sample_count,
                     download_avg_bps, upload_avg_bps, source, created_at_ms
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     (?6 + ?8) * 8000.0 / MAX(1, ?10 + ?11),
                     (?7 + ?9) * 8000.0 / MAX(1, ?10 + ?11),
                     'raw-rollup', ?13
                 )
                 ON CONFLICT(router_id, interface_id, bucket_size_ms, bucket_start_ms, source)
                 DO UPDATE SET
                     exact_download_bytes = traffic_rollups.exact_download_bytes + excluded.exact_download_bytes,
                     exact_upload_bytes = traffic_rollups.exact_upload_bytes + excluded.exact_upload_bytes,
                     estimated_download_bytes = traffic_rollups.estimated_download_bytes + excluded.estimated_download_bytes,
                     estimated_upload_bytes = traffic_rollups.estimated_upload_bytes + excluded.estimated_upload_bytes,
                     exact_duration_ms = traffic_rollups.exact_duration_ms + excluded.exact_duration_ms,
                     estimated_duration_ms = traffic_rollups.estimated_duration_ms + excluded.estimated_duration_ms,
                     sample_count = traffic_rollups.sample_count + excluded.sample_count,
                     download_avg_bps =
                         (traffic_rollups.exact_download_bytes + traffic_rollups.estimated_download_bytes +
                          excluded.exact_download_bytes + excluded.estimated_download_bytes) * 8000.0 /
                         MAX(1, traffic_rollups.exact_duration_ms + traffic_rollups.estimated_duration_ms +
                                excluded.exact_duration_ms + excluded.estimated_duration_ms),
                     upload_avg_bps =
                         (traffic_rollups.exact_upload_bytes + traffic_rollups.estimated_upload_bytes +
                          excluded.exact_upload_bytes + excluded.estimated_upload_bytes) * 8000.0 /
                         MAX(1, traffic_rollups.exact_duration_ms + traffic_rollups.estimated_duration_ms +
                                excluded.exact_duration_ms + excluded.estimated_duration_ms),
                     bucket_end_ms = MAX(traffic_rollups.bucket_end_ms, excluded.bucket_end_ms),
                     created_at_ms = excluded.created_at_ms
                 WHERE traffic_rollups.exact_duration_ms + traffic_rollups.estimated_duration_ms +
                       excluded.exact_duration_ms + excluded.estimated_duration_ms
                       <= excluded.bucket_size_ms
                   AND ?14 >= traffic_rollups.bucket_end_ms
                   AND traffic_rollups.exact_download_bytes <=
                       9223372036854775807 - excluded.exact_download_bytes
                   AND traffic_rollups.exact_upload_bytes <=
                       9223372036854775807 - excluded.exact_upload_bytes
                   AND traffic_rollups.estimated_download_bytes <=
                       9223372036854775807 - excluded.estimated_download_bytes
                   AND traffic_rollups.estimated_upload_bytes <=
                       9223372036854775807 - excluded.estimated_upload_bytes
                   AND traffic_rollups.sample_count <=
                       9223372036854775807 - excluded.sample_count",
                params![
                    router_id,
                    interface_id,
                    bucket_start,
                    bucket_end,
                    bucket_size_ms,
                    exact_download,
                    exact_upload,
                    estimated_download,
                    estimated_upload,
                    bucket.exact_duration_ms,
                    bucket.estimated_duration_ms,
                    bucket.sample_count,
                    before_ms,
                    batch_start,
                ],
            )?;
            if changed != 1 {
                return Err(DatabaseError::Verification(
                    "rollup bucket update violates coverage ordering or integer limits".into(),
                ));
            }
        }

        for remainder in remainders {
            let duration_ms = remainder
                .ended_at_ms
                .saturating_sub(remainder.started_at_ms);
            let download_bytes = i64::try_from(remainder.download_bytes).map_err(|_| {
                DatabaseError::Verification("raw download remainder overflowed SQLite".into())
            })?;
            let upload_bytes = i64::try_from(remainder.upload_bytes).map_err(|_| {
                DatabaseError::Verification("raw upload remainder overflowed SQLite".into())
            })?;
            let changed = tx.execute(
                "UPDATE traffic_samples
                 SET started_at_ms = ?1, duration_ms = ?2,
                     download_bytes = ?3, upload_bytes = ?4,
                     download_bps = ?3 * 8000.0 / ?2,
                     upload_bps = ?4 * 8000.0 / ?2,
                     quality = 'estimated'
                 WHERE id = ?5",
                params![
                    remainder.started_at_ms,
                    duration_ms,
                    download_bytes,
                    upload_bytes,
                    remainder.id,
                ],
            )?;
            if changed != 1 {
                return Err(DatabaseError::Verification(
                    "raw traffic remainder disappeared during rollup".into(),
                ));
            }
        }
        for id in &fully_consumed {
            if tx.execute("DELETE FROM traffic_samples WHERE id = ?1", params![id])? != 1 {
                return Err(DatabaseError::Verification(
                    "raw traffic sample disappeared during rollup".into(),
                ));
            }
        }
        tx.commit()?;
        Ok(fully_consumed.len())
    }

    /// Delete one bounded batch of v4 history entirely older than the retention boundary.
    /// Each source gets an independent quota, and checkpoints remain intact so the
    /// next counter sample can continue atomically.
    pub fn prune_exact_history(&self, before_ms: i64) -> DatabaseResult<usize> {
        self.prune_exact_history_batch(before_ms, RETENTION_DELETE_BATCH_SIZE)
    }

    fn prune_exact_history_batch(
        &self,
        before_ms: i64,
        batch_size: usize,
    ) -> DatabaseResult<usize> {
        let batch_size = i64::try_from(batch_size).map_err(|_| {
            DatabaseError::InvalidCommand("retention batch size exceeds SQLite limits".into())
        })?;
        if batch_size <= 0 {
            return Err(DatabaseError::InvalidCommand(
                "retention batch size must be positive".into(),
            ));
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let samples = tx.execute(
            PRUNE_TRAFFIC_SAMPLES_BATCH_SQL,
            params![before_ms, batch_size],
        )?;
        let rollups = tx.execute(
            PRUNE_TRAFFIC_ROLLUPS_BATCH_SQL,
            params![before_ms, batch_size],
        )?;
        let gaps = tx.execute(PRUNE_TRAFFIC_GAPS_BATCH_SQL, params![before_ms, batch_size])?;
        tx.commit()?;
        Ok(samples.saturating_add(rollups).saturating_add(gaps))
    }

    /// Find the router whose history should be exposed by the traffic API.
    ///
    /// The configured management target is authoritative once the poller has
    /// resolved it. Before that happens, fall back deterministically to the
    /// most recently observed router that already has traffic. This keeps a
    /// v4-migrated legacy history visible without creating a router as a side
    /// effect of a read request.
    pub fn current_router_for_target(
        &self,
        fallback_target: &str,
    ) -> DatabaseResult<Option<RouterRecord>> {
        let fallback_target = fallback_target.trim();
        if fallback_target.is_empty() {
            return Err(DatabaseError::InvalidCommand(
                "router fallback target must not be empty".into(),
            ));
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if let Some(router) = router_by_fallback_target(&conn, fallback_target)? {
            return Ok(Some(router));
        }

        router_query(
            &conn,
            "SELECT id, internal_uuid, hardware_identity, fallback_target, identity_source,
                    first_seen_at_ms, last_seen_at_ms
             FROM routers AS router
             WHERE EXISTS(
                       SELECT 1 FROM traffic_samples AS sample
                       WHERE sample.router_id = router.id
                   )
                OR EXISTS(
                       SELECT 1 FROM traffic_rollups AS rollup
                       WHERE rollup.router_id = router.id
                   )
             ORDER BY last_seen_at_ms DESC, id DESC
             LIMIT 1",
            params![],
        )
    }

    /// Resolve exactly one interface for a traffic query.
    ///
    /// Omitting `wan_name` selects the synthetic aggregate interface. A WAN
    /// name never falls through to aggregate data, preserving the one-query,
    /// one-interface coverage invariant used by `query_traffic_v4`.
    pub fn traffic_interface_for_query(
        &self,
        router_id: i64,
        wan_name: Option<&str>,
    ) -> DatabaseResult<Option<RouterInterfaceRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let interface = match wan_name {
            Some(name) => conn
                .query_row(
                    "SELECT id, router_id, interface_key, name, kind, hardware_id,
                            first_seen_at_ms, last_seen_at_ms
                     FROM router_interfaces
                     WHERE router_id = ?1 AND name = ?2 AND kind <> 'aggregate'
                     ORDER BY last_seen_at_ms DESC, id DESC
                     LIMIT 1",
                    params![router_id, name],
                    map_interface,
                )
                .optional()?,
            None => conn
                .query_row(
                    "SELECT id, router_id, interface_key, name, kind, hardware_id,
                            first_seen_at_ms, last_seen_at_ms
                     FROM router_interfaces
                     WHERE router_id = ?1 AND kind = 'aggregate'
                     ORDER BY (interface_key = '__aggregate__') DESC,
                              last_seen_at_ms DESC, id DESC
                     LIMIT 1",
                    params![router_id],
                    map_interface,
                )
                .optional()?,
        };
        Ok(interface)
    }

    pub fn traffic_interface_by_key(
        &self,
        router_id: i64,
        interface_key: &str,
    ) -> DatabaseResult<Option<RouterInterfaceRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(conn
            .query_row(
                "SELECT id, router_id, interface_key, name, kind, hardware_id,
                        first_seen_at_ms, last_seen_at_ms
                 FROM router_interfaces
                 WHERE router_id = ?1 AND interface_key = ?2",
                params![router_id, interface_key],
                map_interface,
            )
            .optional()?)
    }

    /// List queryable WAN interfaces for response metadata and selectors.
    pub fn router_wan_interfaces(
        &self,
        router_id: i64,
    ) -> DatabaseResult<Vec<RouterInterfaceRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut statement = conn.prepare(
            "SELECT id, router_id, interface_key, name, kind, hardware_id,
                    first_seen_at_ms, last_seen_at_ms
             FROM router_interfaces
             WHERE router_id = ?1 AND kind <> 'aggregate'
             ORDER BY name COLLATE NOCASE, interface_key, id",
        )?;
        let rows = statement.query_map(params![router_id], map_interface)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn query_traffic_v4(&self, query: &TrafficQuery) -> DatabaseResult<TrafficQueryResult> {
        self.query_traffic_v4_with_options(query, MAX_TRAFFIC_SOURCE_ROWS, None)
    }

    pub(crate) fn query_traffic_v4_cancellable(
        &self,
        query: &TrafficQuery,
        cancelled: Arc<AtomicBool>,
    ) -> DatabaseResult<TrafficQueryResult> {
        self.query_traffic_v4_with_options(query, MAX_TRAFFIC_SOURCE_ROWS, Some(cancelled))
    }

    fn query_traffic_v4_with_options(
        &self,
        query: &TrafficQuery,
        source_row_budget: usize,
        cancelled: Option<Arc<AtomicBool>>,
    ) -> DatabaseResult<TrafficQueryResult> {
        if query.to_ms <= query.from_ms
            || query.max_points == 0
            || query.max_points > 50_000
            || source_row_budget == 0
        {
            return Err(DatabaseError::InvalidCommand(
                "traffic query requires an increasing range, 1..=50000 max_points, and a positive source-row budget"
                    .into(),
            ));
        }
        if cancellation_requested(cancelled.as_deref()) {
            return Err(DatabaseError::TrafficQueryCancelled);
        }

        let conn = self.lock_for_traffic_query(cancelled.as_deref())?;
        if cancellation_requested(cancelled.as_deref()) {
            return Err(DatabaseError::TrafficQueryCancelled);
        }
        let progress_guard = cancelled
            .clone()
            .map(|flag| TrafficQueryProgressGuard::install(&conn, flag));
        let result = query_traffic_v4_on_connection(&conn, query, source_row_budget);
        drop(progress_guard);

        if cancellation_requested(cancelled.as_deref()) {
            Err(DatabaseError::TrafficQueryCancelled)
        } else {
            result
        }
    }

    fn lock_for_traffic_query(
        &self,
        cancelled: Option<&AtomicBool>,
    ) -> DatabaseResult<MutexGuard<'_, Connection>> {
        let Some(cancelled) = cancelled else {
            return self
                .conn
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery.into());
        };

        loop {
            if cancelled.load(Ordering::Relaxed) {
                return Err(DatabaseError::TrafficQueryCancelled);
            }
            match self.conn.try_lock() {
                Ok(conn) => return Ok(conn),
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(TRAFFIC_QUERY_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(rusqlite::Error::InvalidQuery.into());
                }
            }
        }
    }
}

struct TrafficQueryProgressGuard<'a> {
    conn: &'a Connection,
}

impl<'a> TrafficQueryProgressGuard<'a> {
    fn install(conn: &'a Connection, cancelled: Arc<AtomicBool>) -> Self {
        conn.progress_handler(
            TRAFFIC_QUERY_PROGRESS_INTERVAL,
            Some(move || cancelled.load(Ordering::Relaxed)),
        );
        Self { conn }
    }
}

impl Drop for TrafficQueryProgressGuard<'_> {
    fn drop(&mut self) {
        self.conn.progress_handler(0, None::<fn() -> bool>);
    }
}

fn cancellation_requested(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn query_traffic_v4_on_connection(
    conn: &Connection,
    query: &TrafficQuery,
    source_row_budget: usize,
) -> DatabaseResult<TrafficQueryResult> {
    ensure_interface_owner(conn, query.router_id, Some(query.interface_id))?;
    let source_resolution_ms = plan_traffic_sources(conn, query, source_row_budget)?;
    let range = query.to_ms.saturating_sub(query.from_ms);
    let minimum_bucket_size_ms = range
        .saturating_add(query.max_points as i64 - 1)
        .checked_div(query.max_points as i64)
        .unwrap_or(1)
        .max(1);
    let bucket_size_ms = minimum_bucket_size_ms.max(source_resolution_ms);
    let (buckets, totals) =
        fold_traffic_contributions(conn, query, bucket_size_ms, source_row_budget)?;
    if buckets.len() > query.max_points {
        return Err(DatabaseError::Verification(format!(
            "traffic query produced {} points for a {}-point limit",
            buckets.len(),
            query.max_points
        )));
    }
    let gap_count: u64 = conn.query_row(
        "SELECT COUNT(*) FROM traffic_gaps
         WHERE router_id = ?1
           AND (interface_id IS NULL OR interface_id = ?2)
           AND ended_at_ms > ?3 AND started_at_ms < ?4",
        params![
            query.router_id,
            query.interface_id,
            query.from_ms,
            query.to_ms
        ],
        |row| row.get(0),
    )?;

    build_traffic_query_result(query, bucket_size_ms, buckets, totals, gap_count)
}

fn build_traffic_query_result(
    query: &TrafficQuery,
    bucket_size_ms: i64,
    buckets: BTreeMap<i64, TrafficBucketAccumulator>,
    totals: TrafficBucketAccumulator,
    gap_count: u64,
) -> DatabaseResult<TrafficQueryResult> {
    let mut points = Vec::with_capacity(buckets.len());
    for (started_at_ms, bucket) in buckets {
        let duration = bucket
            .exact_duration_ms
            .saturating_add(bucket.estimated_duration_ms)
            .max(1);
        points.push(TrafficBucket {
            started_at_ms,
            ended_at_ms: started_at_ms
                .saturating_add(bucket_size_ms)
                .min(query.to_ms),
            download_bps: (bucket.exact_download_bytes + bucket.estimated_download_bytes) as f64
                * 8000.0
                / duration as f64,
            upload_bps: (bucket.exact_upload_bytes + bucket.estimated_upload_bytes) as f64 * 8000.0
                / duration as f64,
            exact_download_bytes: bucket.exact_download_bytes.to_string(),
            exact_upload_bytes: bucket.exact_upload_bytes.to_string(),
            estimated_download_bytes: bucket.estimated_download_bytes.to_string(),
            estimated_upload_bytes: bucket.estimated_upload_bytes.to_string(),
            exact_duration_ms: bucket.exact_duration_ms,
            estimated_duration_ms: bucket.estimated_duration_ms,
            sample_count: bucket.sample_count,
        });
    }

    let range = query.to_ms.saturating_sub(query.from_ms);
    let covered_duration = totals
        .exact_duration_ms
        .saturating_add(totals.estimated_duration_ms);
    if covered_duration > range {
        return Err(DatabaseError::Verification(format!(
            "traffic coverage {covered_duration}ms exceeds requested range {range}ms"
        )));
    }
    let completeness = (covered_duration as f64 / range as f64).clamp(0.0, 1.0);
    Ok(TrafficQueryResult {
        bucket_size_ms,
        points,
        totals: TrafficTotals {
            download_bytes: (totals.exact_download_bytes + totals.estimated_download_bytes)
                .to_string(),
            upload_bytes: (totals.exact_upload_bytes + totals.estimated_upload_bytes).to_string(),
            exact_download_bytes: totals.exact_download_bytes.to_string(),
            exact_upload_bytes: totals.exact_upload_bytes.to_string(),
            estimated_download_bytes: totals.estimated_download_bytes.to_string(),
            estimated_upload_bytes: totals.estimated_upload_bytes.to_string(),
        },
        coverage: TrafficCoverage {
            requested_duration_ms: range,
            exact_duration_ms: totals.exact_duration_ms,
            estimated_duration_ms: totals.estimated_duration_ms,
            covered_duration_ms: covered_duration,
            completeness,
            gap_count,
        },
    })
}

#[derive(Debug)]
struct TrafficContribution {
    started_at_ms: i64,
    ended_at_ms: i64,
    exact_download_bytes: i128,
    exact_upload_bytes: i128,
    estimated_download_bytes: i128,
    estimated_upload_bytes: i128,
    exact_duration_ms: i64,
    estimated_duration_ms: i64,
    sample_count: i64,
}

impl TrafficContribution {
    fn order_key(&self) -> (i64, i64) {
        (self.ended_at_ms, self.started_at_ms)
    }

    fn duration_ms(&self) -> i64 {
        self.ended_at_ms.saturating_sub(self.started_at_ms)
    }

    fn covered_duration_ms(&self) -> i64 {
        self.exact_duration_ms
            .saturating_add(self.estimated_duration_ms)
    }
}

#[derive(Debug, Default)]
struct TrafficBucketAccumulator {
    exact_download_bytes: i128,
    exact_upload_bytes: i128,
    estimated_download_bytes: i128,
    estimated_upload_bytes: i128,
    exact_duration_ms: i64,
    estimated_duration_ms: i64,
    sample_count: i64,
}

impl TrafficBucketAccumulator {
    fn add_segment(
        &mut self,
        contribution: &TrafficContribution,
        segment_start: i64,
        segment_end: i64,
    ) -> DatabaseResult<()> {
        let source_duration = contribution.duration_ms();
        let relative_start = segment_start.saturating_sub(contribution.started_at_ms);
        let relative_end = segment_end.saturating_sub(contribution.started_at_ms);
        let whole_contribution =
            segment_start == contribution.started_at_ms && segment_end == contribution.ended_at_ms;

        if whole_contribution {
            self.exact_download_bytes += contribution.exact_download_bytes;
            self.exact_upload_bytes += contribution.exact_upload_bytes;
            self.estimated_download_bytes += contribution.estimated_download_bytes;
            self.estimated_upload_bytes += contribution.estimated_upload_bytes;
            self.exact_duration_ms = self
                .exact_duration_ms
                .saturating_add(contribution.exact_duration_ms);
            self.estimated_duration_ms = self
                .estimated_duration_ms
                .saturating_add(contribution.estimated_duration_ms);
        } else {
            let download_bytes = proportional_slice(
                contribution.exact_download_bytes + contribution.estimated_download_bytes,
                source_duration,
                relative_start,
                relative_end,
            )?;
            let upload_bytes = proportional_slice(
                contribution.exact_upload_bytes + contribution.estimated_upload_bytes,
                source_duration,
                relative_start,
                relative_end,
            )?;
            let covered_duration = proportional_slice(
                i128::from(contribution.covered_duration_ms()),
                source_duration,
                relative_start,
                relative_end,
            )?;
            let covered_duration = i64::try_from(covered_duration).map_err(|_| {
                DatabaseError::Verification("traffic duration allocation overflowed".into())
            })?;
            self.estimated_download_bytes += download_bytes;
            self.estimated_upload_bytes += upload_bytes;
            self.estimated_duration_ms = self
                .estimated_duration_ms
                .saturating_add(covered_duration.min(segment_end.saturating_sub(segment_start)));
        }
        self.sample_count = self.sample_count.saturating_add(contribution.sample_count);
        Ok(())
    }
}

fn proportional_slice(
    value: i128,
    duration_ms: i64,
    relative_start_ms: i64,
    relative_end_ms: i64,
) -> DatabaseResult<i128> {
    if value < 0
        || duration_ms <= 0
        || relative_start_ms < 0
        || relative_end_ms < relative_start_ms
        || relative_end_ms > duration_ms
    {
        return Err(DatabaseError::Verification(
            "traffic contribution cannot be proportionally allocated".into(),
        ));
    }
    let duration = i128::from(duration_ms);
    let before = value
        .checked_mul(i128::from(relative_start_ms))
        .ok_or_else(|| DatabaseError::Verification("traffic allocation overflowed".into()))?
        / duration;
    let after = value
        .checked_mul(i128::from(relative_end_ms))
        .ok_or_else(|| DatabaseError::Verification("traffic allocation overflowed".into()))?
        / duration;
    Ok(after - before)
}

#[derive(Debug)]
struct TrafficSourceSummary {
    row_count: usize,
    max_duration_ms: i64,
}

fn plan_traffic_sources(
    conn: &Connection,
    query: &TrafficQuery,
    source_row_budget: usize,
) -> DatabaseResult<i64> {
    let sample_limit = source_row_budget.saturating_add(1);
    let samples = bounded_sample_summary(conn, query, sample_limit)?;
    if samples.row_count > source_row_budget {
        return Err(DatabaseError::TrafficQueryTooLarge {
            max_source_rows: source_row_budget,
        });
    }

    let remaining = source_row_budget - samples.row_count;
    let rollups = bounded_rollup_summary(conn, query, remaining.saturating_add(1))?;
    if rollups.row_count > remaining {
        return Err(DatabaseError::TrafficQueryTooLarge {
            max_source_rows: source_row_budget,
        });
    }

    Ok(samples.max_duration_ms.max(rollups.max_duration_ms).max(1))
}

fn bounded_sample_summary(
    conn: &Connection,
    query: &TrafficQuery,
    limit: usize,
) -> DatabaseResult<TrafficSourceSummary> {
    bounded_source_summary(
        conn,
        "SELECT COUNT(*), COALESCE(MAX(source_duration_ms), 1)
         FROM (
             SELECT ended_at_ms - started_at_ms AS source_duration_ms
             FROM traffic_samples
             WHERE router_id = ?1 AND interface_id = ?2
               AND ended_at_ms > ?3 AND started_at_ms < ?4
             LIMIT ?5
         )",
        query,
        limit,
    )
}

fn bounded_rollup_summary(
    conn: &Connection,
    query: &TrafficQuery,
    limit: usize,
) -> DatabaseResult<TrafficSourceSummary> {
    bounded_source_summary(
        conn,
        "SELECT COUNT(*), COALESCE(MAX(source_duration_ms), 1)
         FROM (
             SELECT bucket_end_ms - bucket_start_ms AS source_duration_ms
             FROM traffic_rollups
             WHERE router_id = ?1 AND interface_id = ?2
               AND bucket_end_ms > ?3 AND bucket_start_ms < ?4
             LIMIT ?5
         )",
        query,
        limit,
    )
}

fn bounded_source_summary(
    conn: &Connection,
    sql: &str,
    query: &TrafficQuery,
    limit: usize,
) -> DatabaseResult<TrafficSourceSummary> {
    let limit = i64::try_from(limit).map_err(|_| {
        DatabaseError::InvalidCommand("traffic source-row budget cannot be represented".into())
    })?;
    let (row_count, max_duration_ms) = conn.query_row(
        sql,
        params![
            query.router_id,
            query.interface_id,
            query.from_ms,
            query.to_ms,
            limit
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let row_count = usize::try_from(row_count)
        .map_err(|_| DatabaseError::Verification("traffic source-row count is invalid".into()))?;
    Ok(TrafficSourceSummary {
        row_count,
        max_duration_ms,
    })
}

fn fold_traffic_contributions(
    conn: &Connection,
    query: &TrafficQuery,
    bucket_size_ms: i64,
    source_row_budget: usize,
) -> DatabaseResult<(
    BTreeMap<i64, TrafficBucketAccumulator>,
    TrafficBucketAccumulator,
)> {
    // With positive intervals, ordering by end time is chronological for valid
    // data and still makes any overlap fail against the immediately prior end.
    // It also lets SQLite stream raw samples through the existing range index.
    let mut sample_statement = conn.prepare(
        "SELECT started_at_ms, ended_at_ms,
                CASE WHEN quality = 'exact' THEN download_bytes ELSE 0 END,
                CASE WHEN quality = 'exact' THEN upload_bytes ELSE 0 END,
                CASE WHEN quality = 'estimated' THEN download_bytes ELSE 0 END,
                CASE WHEN quality = 'estimated' THEN upload_bytes ELSE 0 END,
                CASE WHEN quality = 'exact' THEN duration_ms ELSE 0 END,
                CASE WHEN quality = 'estimated' THEN duration_ms ELSE 0 END,
                1
         FROM traffic_samples
         WHERE router_id = ?1 AND interface_id = ?2
           AND ended_at_ms > ?3 AND started_at_ms < ?4
         ORDER BY ended_at_ms, started_at_ms, id",
    )?;
    let mut rollup_statement = conn.prepare(
        "SELECT bucket_start_ms, bucket_end_ms,
                exact_download_bytes, exact_upload_bytes,
                estimated_download_bytes, estimated_upload_bytes,
                exact_duration_ms, estimated_duration_ms, sample_count
         FROM traffic_rollups
         WHERE router_id = ?1 AND interface_id = ?2
           AND bucket_end_ms > ?3 AND bucket_start_ms < ?4
         ORDER BY bucket_end_ms, bucket_start_ms, id",
    )?;
    let query_params = params![
        query.router_id,
        query.interface_id,
        query.from_ms,
        query.to_ms
    ];
    let mut sample_rows = sample_statement.query(query_params)?;
    let mut rollup_rows = rollup_statement.query(params![
        query.router_id,
        query.interface_id,
        query.from_ms,
        query.to_ms
    ])?;
    let mut next_sample = next_traffic_contribution(&mut sample_rows)?;
    let mut next_rollup = next_traffic_contribution(&mut rollup_rows)?;
    let mut previous_end = None;
    let mut processed_rows = 0usize;
    let mut buckets = BTreeMap::new();
    let mut totals = TrafficBucketAccumulator::default();

    while next_sample.is_some() || next_rollup.is_some() {
        let take_sample = match (next_sample.as_ref(), next_rollup.as_ref()) {
            (Some(sample), Some(rollup)) => sample.order_key() <= rollup.order_key(),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let contribution = if take_sample {
            let contribution = next_sample.take().ok_or_else(|| {
                DatabaseError::Verification("traffic sample merge lost its next row".into())
            })?;
            next_sample = next_traffic_contribution(&mut sample_rows)?;
            contribution
        } else {
            let contribution = next_rollup.take().ok_or_else(|| {
                DatabaseError::Verification("traffic rollup merge lost its next row".into())
            })?;
            next_rollup = next_traffic_contribution(&mut rollup_rows)?;
            contribution
        };
        processed_rows = processed_rows.saturating_add(1);
        if processed_rows > source_row_budget {
            return Err(DatabaseError::TrafficQueryTooLarge {
                max_source_rows: source_row_budget,
            });
        }
        validate_traffic_contribution(&contribution, previous_end)?;
        previous_end = Some(contribution.ended_at_ms);
        accumulate_traffic_contribution(
            &contribution,
            query,
            bucket_size_ms,
            &mut buckets,
            &mut totals,
        )?;
    }

    Ok((buckets, totals))
}

fn next_traffic_contribution(rows: &mut Rows<'_>) -> DatabaseResult<Option<TrafficContribution>> {
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(TrafficContribution {
        started_at_ms: row.get(0)?,
        ended_at_ms: row.get(1)?,
        exact_download_bytes: i128::from(row.get::<_, i64>(2)?),
        exact_upload_bytes: i128::from(row.get::<_, i64>(3)?),
        estimated_download_bytes: i128::from(row.get::<_, i64>(4)?),
        estimated_upload_bytes: i128::from(row.get::<_, i64>(5)?),
        exact_duration_ms: row.get(6)?,
        estimated_duration_ms: row.get(7)?,
        sample_count: row.get(8)?,
    }))
}

fn validate_traffic_contribution(
    contribution: &TrafficContribution,
    previous_end: Option<i64>,
) -> DatabaseResult<()> {
    let duration = contribution.duration_ms();
    let bytes_are_valid = contribution.exact_download_bytes >= 0
        && contribution.exact_upload_bytes >= 0
        && contribution.estimated_download_bytes >= 0
        && contribution.estimated_upload_bytes >= 0;
    let coverage_is_valid = contribution.exact_duration_ms >= 0
        && contribution.estimated_duration_ms >= 0
        && contribution.covered_duration_ms() <= duration;
    if duration <= 0
        || !bytes_are_valid
        || !coverage_is_valid
        || contribution.sample_count <= 0
        || (contribution.covered_duration_ms() == 0
            && (contribution.exact_download_bytes
                + contribution.exact_upload_bytes
                + contribution.estimated_download_bytes
                + contribution.estimated_upload_bytes
                > 0))
    {
        return Err(DatabaseError::Verification(
            "stored traffic contribution has invalid bytes, duration, or sample count".into(),
        ));
    }
    if previous_end.is_some_and(|end| contribution.started_at_ms < end) {
        return Err(DatabaseError::Verification(
            "stored traffic contributions overlap for one interface".into(),
        ));
    }
    Ok(())
}

fn accumulate_traffic_contribution(
    contribution: &TrafficContribution,
    query: &TrafficQuery,
    bucket_size_ms: i64,
    buckets: &mut BTreeMap<i64, TrafficBucketAccumulator>,
    totals: &mut TrafficBucketAccumulator,
) -> DatabaseResult<()> {
    let clipped_start = contribution.started_at_ms.max(query.from_ms);
    let clipped_end = contribution.ended_at_ms.min(query.to_ms);
    totals.add_segment(contribution, clipped_start, clipped_end)?;
    let mut segment_start = clipped_start;
    while segment_start < clipped_end {
        let bucket_index = segment_start.saturating_sub(query.from_ms) / bucket_size_ms;
        let bucket_start = query
            .from_ms
            .saturating_add(bucket_index.saturating_mul(bucket_size_ms));
        let bucket_end = bucket_start.saturating_add(bucket_size_ms).min(query.to_ms);
        let segment_end = clipped_end.min(bucket_end);
        if segment_end <= segment_start {
            return Err(DatabaseError::Verification(
                "traffic bucket boundaries did not advance".into(),
            ));
        }
        buckets.entry(bucket_start).or_default().add_segment(
            contribution,
            segment_start,
            segment_end,
        )?;
        segment_start = segment_end;
    }
    Ok(())
}

fn validate_sample(sample: &TrafficSampleInput<'_>) -> DatabaseResult<()> {
    if sample.ended_at_ms <= sample.started_at_ms
        || sample.duration_ms != sample.ended_at_ms.saturating_sub(sample.started_at_ms)
        || sample.download_bytes < 0
        || sample.upload_bytes < 0
        || !sample.download_bps.is_finite()
        || !sample.upload_bps.is_finite()
        || sample.download_bps < 0.0
        || sample.upload_bps < 0.0
        || sample.source.trim().is_empty()
    {
        return Err(DatabaseError::InvalidCommand(
            "traffic sample contains an invalid range, counter delta, rate, or source".into(),
        ));
    }
    Ok(())
}

fn validate_raw_sample_for_rollup(sample: &RawTrafficSample) -> DatabaseResult<()> {
    if sample.ended_at_ms <= sample.started_at_ms
        || sample.duration_ms != sample.ended_at_ms.saturating_sub(sample.started_at_ms)
        || sample.download_bytes < 0
        || sample.upload_bytes < 0
        || !matches!(sample.quality.as_str(), "exact" | "estimated")
    {
        return Err(DatabaseError::Verification(
            "raw traffic sample is invalid during rollup".into(),
        ));
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &CounterCheckpointInput<'_>) -> DatabaseResult<()> {
    let valid_counter =
        |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    if !valid_counter(checkpoint.rx_counter) || !valid_counter(checkpoint.tx_counter) {
        return Err(DatabaseError::InvalidCommand(
            "counter checkpoints must be unsigned decimal strings".into(),
        ));
    }
    Ok(())
}

fn validate_gap(gap: &TrafficGapInput<'_>) -> DatabaseResult<()> {
    if gap.ended_at_ms <= gap.started_at_ms || gap.reason.trim().is_empty() {
        return Err(DatabaseError::InvalidCommand(
            "traffic gap requires an increasing time range and a reason".into(),
        ));
    }
    Ok(())
}

fn ensure_interface_owner(
    conn: &rusqlite::Connection,
    router_id: i64,
    interface_id: Option<i64>,
) -> DatabaseResult<()> {
    let valid: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM routers AS router
             WHERE router.id = ?1
               AND (
                   ?2 IS NULL OR EXISTS(
                       SELECT 1 FROM router_interfaces AS interface
                       WHERE interface.id = ?2 AND interface.router_id = router.id
                   )
               )
         )",
        params![router_id, interface_id],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(DatabaseError::InvalidCommand(
            "traffic record references an unknown router interface".into(),
        ));
    }
    Ok(())
}

fn gap_details_for_connection(
    conn: &rusqlite::Connection,
    gap: &TrafficGapInput<'_>,
) -> DatabaseResult<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT COALESCE(details, '') FROM traffic_gaps
             WHERE router_id = ?1
               AND interface_id IS ?2
               AND started_at_ms = ?3
               AND ended_at_ms = ?4
               AND reason = ?5",
            params![
                gap.router_id,
                gap.interface_id,
                gap.started_at_ms,
                gap.ended_at_ms,
                gap.reason
            ],
            |row| row.get(0),
        )
        .optional()?)
}

fn checkpoint_for_connection(
    conn: &rusqlite::Connection,
    router_id: i64,
    interface_id: i64,
) -> DatabaseResult<Option<CounterCheckpoint>> {
    Ok(conn
        .query_row(
            "SELECT router_id, interface_id, rx_counter, tx_counter,
                    observed_at_ms, reboot_marker
             FROM counter_checkpoints WHERE router_id = ?1 AND interface_id = ?2",
            params![router_id, interface_id],
            |row| {
                Ok(CounterCheckpoint {
                    router_id: row.get(0)?,
                    interface_id: row.get(1)?,
                    rx_counter: row.get(2)?,
                    tx_counter: row.get(3)?,
                    observed_at_ms: row.get(4)?,
                    reboot_marker: row.get(5)?,
                })
            },
        )
        .optional()?)
}

fn checkpoint_matches(current: &CounterCheckpoint, candidate: &CounterCheckpointInput<'_>) -> bool {
    current.router_id == candidate.router_id
        && current.interface_id == candidate.interface_id
        && current.rx_counter == candidate.rx_counter
        && current.tx_counter == candidate.tx_counter
        && current.observed_at_ms == candidate.observed_at_ms
        && current.reboot_marker.as_deref() == candidate.reboot_marker
}

fn adopt_legacy_history(
    conn: &rusqlite::Connection,
    target_router_id: i64,
    observed_at_ms: i64,
) -> DatabaseResult<()> {
    let legacy_router_ids = {
        let mut statement = conn.prepare(
            "SELECT id FROM routers
             WHERE fallback_target = 'legacy://unidentified' AND id <> ?1
             ORDER BY id",
        )?;
        let rows = statement.query_map(params![target_router_id], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    for legacy_router_id in legacy_router_ids {
        let legacy_interfaces = {
            let mut statement = conn.prepare(
                "SELECT id, interface_key FROM router_interfaces
                 WHERE router_id = ?1 ORDER BY id",
            )?;
            let rows = statement.query_map(params![legacy_router_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        for (legacy_interface_id, interface_key) in legacy_interfaces {
            let target_interface_id = conn
                .query_row(
                    "SELECT id FROM router_interfaces
                     WHERE router_id = ?1 AND interface_key = ?2",
                    params![target_router_id, interface_key],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;

            if let Some(target_interface_id) = target_interface_id {
                for table in ["traffic_samples", "traffic_rollups", "traffic_gaps"] {
                    conn.execute(
                        &format!(
                            "UPDATE {table} SET router_id = ?1, interface_id = ?2
                             WHERE router_id = ?3 AND interface_id = ?4"
                        ),
                        params![
                            target_router_id,
                            target_interface_id,
                            legacy_router_id,
                            legacy_interface_id
                        ],
                    )?;
                }
                conn.execute(
                    "DELETE FROM counter_checkpoints
                     WHERE router_id = ?1 AND interface_id = ?2",
                    params![legacy_router_id, legacy_interface_id],
                )?;
                conn.execute(
                    "DELETE FROM router_interfaces WHERE id = ?1",
                    params![legacy_interface_id],
                )?;
            } else {
                conn.execute(
                    "UPDATE router_interfaces
                     SET router_id = ?1, last_seen_at_ms = MAX(last_seen_at_ms, ?2)
                     WHERE id = ?3",
                    params![target_router_id, observed_at_ms, legacy_interface_id],
                )?;
                for table in [
                    "traffic_samples",
                    "traffic_rollups",
                    "traffic_gaps",
                    "counter_checkpoints",
                ] {
                    conn.execute(
                        &format!(
                            "UPDATE {table} SET router_id = ?1
                             WHERE router_id = ?2 AND interface_id = ?3"
                        ),
                        params![target_router_id, legacy_router_id, legacy_interface_id],
                    )?;
                }
            }
        }

        conn.execute(
            "UPDATE traffic_gaps SET router_id = ?1
             WHERE router_id = ?2 AND interface_id IS NULL",
            params![target_router_id, legacy_router_id],
        )?;
        conn.execute(
            "UPDATE routers
             SET first_seen_at_ms = MIN(
                     first_seen_at_ms,
                     COALESCE((SELECT first_seen_at_ms FROM routers WHERE id = ?2), first_seen_at_ms)
                 ),
                 last_seen_at_ms = MAX(last_seen_at_ms, ?3)
             WHERE id = ?1",
            params![target_router_id, legacy_router_id, observed_at_ms],
        )?;
        conn.execute(
            "DELETE FROM routers WHERE id = ?1",
            params![legacy_router_id],
        )?;
    }
    Ok(())
}

fn insert_router(
    conn: &rusqlite::Connection,
    hardware_identity: Option<&str>,
    fallback_target: &str,
    identity_source: &str,
    observed_at_ms: i64,
) -> DatabaseResult<i64> {
    conn.execute(
        "INSERT INTO routers(
             internal_uuid, hardware_identity, fallback_target, identity_source,
             first_seen_at_ms, last_seen_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            uuid::Uuid::new_v4().to_string(),
            hardware_identity,
            fallback_target,
            identity_source,
            observed_at_ms,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn router_by_hardware_identity(
    conn: &rusqlite::Connection,
    hardware_identity: &str,
) -> DatabaseResult<Option<RouterRecord>> {
    router_query(
        conn,
        "SELECT id, internal_uuid, hardware_identity, fallback_target, identity_source,
                first_seen_at_ms, last_seen_at_ms
         FROM routers WHERE hardware_identity = ?1",
        [hardware_identity],
    )
}

fn router_by_fallback_only(
    conn: &rusqlite::Connection,
    fallback_target: &str,
) -> DatabaseResult<Option<RouterRecord>> {
    router_query(
        conn,
        "SELECT id, internal_uuid, hardware_identity, fallback_target, identity_source,
                first_seen_at_ms, last_seen_at_ms
         FROM routers
         WHERE fallback_target = ?1 AND hardware_identity IS NULL
         ORDER BY id LIMIT 1",
        [fallback_target],
    )
}

fn router_by_fallback_target(
    conn: &rusqlite::Connection,
    fallback_target: &str,
) -> DatabaseResult<Option<RouterRecord>> {
    router_query(
        conn,
        "SELECT id, internal_uuid, hardware_identity, fallback_target, identity_source,
                first_seen_at_ms, last_seen_at_ms
         FROM routers
         WHERE fallback_target = ?1
         ORDER BY last_seen_at_ms DESC, id DESC LIMIT 1",
        [fallback_target],
    )
}

fn router_by_id(conn: &rusqlite::Connection, id: i64) -> DatabaseResult<Option<RouterRecord>> {
    Ok(conn
        .query_row(
            "SELECT id, internal_uuid, hardware_identity, fallback_target, identity_source,
                    first_seen_at_ms, last_seen_at_ms
             FROM routers WHERE id = ?1",
            params![id],
            map_router,
        )
        .optional()?)
}

fn router_query<P: rusqlite::Params>(
    conn: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> DatabaseResult<Option<RouterRecord>> {
    Ok(conn.query_row(sql, params, map_router).optional()?)
}

fn map_router(row: &rusqlite::Row<'_>) -> rusqlite::Result<RouterRecord> {
    Ok(RouterRecord {
        id: row.get(0)?,
        internal_uuid: row.get(1)?,
        hardware_identity: row.get(2)?,
        fallback_target: row.get(3)?,
        identity_source: row.get(4)?,
        first_seen_at_ms: row.get(5)?,
        last_seen_at_ms: row.get(6)?,
    })
}

fn interface_by_key(
    conn: &rusqlite::Connection,
    router_id: i64,
    interface_key: &str,
) -> DatabaseResult<Option<RouterInterfaceRecord>> {
    Ok(conn
        .query_row(
            "SELECT id, router_id, interface_key, name, kind, hardware_id,
                    first_seen_at_ms, last_seen_at_ms
             FROM router_interfaces WHERE router_id = ?1 AND interface_key = ?2",
            params![router_id, interface_key],
            map_interface,
        )
        .optional()?)
}

fn map_interface(row: &rusqlite::Row<'_>) -> rusqlite::Result<RouterInterfaceRecord> {
    Ok(RouterInterfaceRecord {
        id: row.get(0)?,
        router_id: row.get(1)?,
        interface_key: row.get(2)?,
        name: row.get(3)?,
        kind: row.get(4)?,
        hardware_id: row.get(5)?,
        first_seen_at_ms: row.get(6)?,
        last_seen_at_ms: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn database() -> TrafficDb {
        TrafficDb::open(&PathBuf::from(":memory:")).unwrap()
    }

    fn insert_sample(
        db: &TrafficDb,
        router_id: i64,
        interface_id: i64,
        started_at_ms: i64,
        quality: TrafficQuality,
    ) {
        let ended_at_ms = started_at_ms + 5_000;
        assert!(db
            .commit_sample_and_checkpoint(
                &TrafficSampleInput {
                    router_id,
                    interface_id,
                    started_at_ms,
                    ended_at_ms,
                    duration_ms: 5_000,
                    download_bytes: 1_000,
                    upload_bytes: 500,
                    download_bps: 1_600.0,
                    upload_bps: 800.0,
                    quality,
                    source: "fixture",
                },
                &CounterCheckpointInput {
                    router_id,
                    interface_id,
                    rx_counter: &format!("{}", ended_at_ms + 10_000),
                    tx_counter: &format!("{}", ended_at_ms + 20_000),
                    observed_at_ms: ended_at_ms,
                    reboot_marker: Some("boot-a"),
                },
            )
            .unwrap());
    }

    fn seed_retention_history(db: &TrafficDb, ended_at_values: &[i64]) -> (i64, i64) {
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let conn = db.conn.lock().unwrap();
        for &ended_at_ms in ended_at_values {
            let started_at_ms = ended_at_ms - 1_000;
            conn.execute(
                "INSERT INTO traffic_samples(
                     router_id, interface_id, started_at_ms, ended_at_ms, duration_ms,
                     download_bytes, upload_bytes, download_bps, upload_bps,
                     quality, source, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 1000, 1000, 500, 8000, 4000,
                           'exact', 'retention-fixture', ?4)",
                params![router.id, interface.id, started_at_ms, ended_at_ms],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO traffic_rollups(
                     router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
                     exact_download_bytes, exact_upload_bytes, exact_duration_ms, sample_count,
                     download_avg_bps, upload_avg_bps, source, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 1000, 1000, 500, 1000, 1,
                           8000, 4000, 'retention-fixture', ?4)",
                params![router.id, interface.id, started_at_ms, ended_at_ms],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO traffic_gaps(
                     router_id, interface_id, started_at_ms, ended_at_ms,
                     reason, details, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'retention-fixture', NULL, ?4)",
                params![router.id, interface.id, started_at_ms, ended_at_ms],
            )
            .unwrap();
        }
        let observed_at_ms = ended_at_values.iter().copied().max().unwrap();
        conn.execute(
            "INSERT INTO counter_checkpoints(
                 router_id, interface_id, rx_counter, tx_counter, observed_at_ms, reboot_marker
             ) VALUES (?1, ?2, '1000', '500', ?3, 'boot-a')",
            params![router.id, interface.id, observed_at_ms],
        )
        .unwrap();
        (router.id, interface.id)
    }

    #[test]
    fn router_identity_sample_checkpoint_rollup_and_query_are_consistent() {
        let db = database();
        let router = db
            .resolve_router(Some("serial-a"), "192.0.2.1", 1_000)
            .unwrap();
        let same_router = db
            .resolve_router(Some("serial-a"), "192.0.2.2", 2_000)
            .unwrap();
        let replacement = db
            .resolve_router(Some("serial-b"), "192.0.2.2", 3_000)
            .unwrap();
        assert_eq!(router.id, same_router.id);
        assert_ne!(router.id, replacement.id);

        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", Some("*1"), 1_000)
            .unwrap();
        insert_sample(&db, router.id, interface.id, 10_000, TrafficQuality::Exact);
        insert_sample(
            &db,
            router.id,
            interface.id,
            15_000,
            TrafficQuality::Estimated,
        );
        assert_eq!(
            db.counter_checkpoint(router.id, interface.id)
                .unwrap()
                .unwrap()
                .observed_at_ms,
            20_000
        );

        assert_eq!(db.rollup_exact_samples(30_000, 60_000).unwrap(), 2);
        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 60_000,
                max_points: 60,
            })
            .unwrap();
        assert_eq!(result.totals.download_bytes, "2000");
        assert_eq!(result.totals.exact_download_bytes, "1000");
        assert_eq!(result.totals.estimated_download_bytes, "1000");
        assert_eq!(result.coverage.exact_duration_ms, 5_000);
        assert_eq!(result.coverage.estimated_duration_ms, 5_000);
    }

    #[test]
    fn rollup_splits_cutoff_and_bucket_boundaries_without_overlap_or_byte_loss() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let sample = TrafficSampleInput {
            router_id: router.id,
            interface_id: interface.id,
            started_at_ms: 50_000,
            ended_at_ms: 70_000,
            duration_ms: 20_000,
            download_bytes: 1_001,
            upload_bytes: 501,
            download_bps: 400.4,
            upload_bps: 200.4,
            quality: TrafficQuality::Exact,
            source: "fixture",
        };
        let checkpoint = CounterCheckpointInput {
            router_id: router.id,
            interface_id: interface.id,
            rx_counter: "1001",
            tx_counter: "501",
            observed_at_ms: 70_000,
            reboot_marker: Some("boot-a"),
        };
        assert!(db
            .commit_sample_and_checkpoint(&sample, &checkpoint)
            .unwrap());

        assert_eq!(db.rollup_exact_samples(63_000, 60_000).unwrap(), 0);
        assert_eq!(db.rollup_exact_samples(63_000, 60_000).unwrap(), 0);
        let partially_rolled = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 70_000,
                max_points: 100,
            })
            .unwrap();
        assert_eq!(partially_rolled.totals.download_bytes, "1001");
        assert_eq!(partially_rolled.totals.upload_bytes, "501");
        assert_eq!(partially_rolled.coverage.covered_duration_ms, 20_000);
        assert_eq!(partially_rolled.totals.exact_download_bytes, "0");

        assert_eq!(db.rollup_exact_samples(80_000, 60_000).unwrap(), 1);
        let fully_rolled = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 80_000,
                max_points: 100,
            })
            .unwrap();
        assert_eq!(fully_rolled.totals.download_bytes, "1001");
        assert_eq!(fully_rolled.totals.upload_bytes, "501");
        assert_eq!(fully_rolled.coverage.covered_duration_ms, 20_000);
    }

    #[test]
    fn rollup_batches_bound_work_without_losing_bucket_precision() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        for index in 0..5 {
            insert_sample(
                &db,
                router.id,
                interface.id,
                index * 5_000,
                TrafficQuality::Exact,
            );
        }

        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 2).unwrap(), 2);
        let remaining: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM traffic_samples", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 3);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 2).unwrap(), 2);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 2).unwrap(), 1);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 2).unwrap(), 0);

        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 60_000,
                max_points: 60,
            })
            .unwrap();
        assert_eq!(result.totals.download_bytes, "5000");
        assert_eq!(result.totals.upload_bytes, "2500");
        assert_eq!(result.coverage.exact_duration_ms, 25_000);
        assert_eq!(result.points.len(), 1);
        assert_eq!(result.points[0].sample_count, 5);
    }

    #[test]
    fn rollup_batches_isolate_interleaved_router_interfaces() {
        let db = database();
        let first_router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let second_router = db.resolve_router(None, "192.0.2.2", 1_000).unwrap();
        let streams = [
            (
                first_router.id,
                db.upsert_router_interface(first_router.id, "ether1", "WAN 1", "wan", None, 1_000)
                    .unwrap()
                    .id,
            ),
            (
                first_router.id,
                db.upsert_router_interface(first_router.id, "ether2", "WAN 2", "wan", None, 1_000)
                    .unwrap()
                    .id,
            ),
            (
                second_router.id,
                db.upsert_router_interface(second_router.id, "ether1", "WAN 1", "wan", None, 1_000)
                    .unwrap()
                    .id,
            ),
            (
                second_router.id,
                db.upsert_router_interface(second_router.id, "ether2", "WAN 2", "wan", None, 1_000)
                    .unwrap()
                    .id,
            ),
        ];
        for started_at_ms in [0, 5_000] {
            for (router_id, interface_id) in streams {
                insert_sample(
                    &db,
                    router_id,
                    interface_id,
                    started_at_ms,
                    TrafficQuality::Exact,
                );
            }
        }

        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 3).unwrap(), 3);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 3).unwrap(), 3);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 3).unwrap(), 2);
        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 3).unwrap(), 0);

        for (router_id, interface_id) in streams {
            let result = db
                .query_traffic_v4(&TrafficQuery {
                    router_id,
                    interface_id,
                    from_ms: 0,
                    to_ms: 60_000,
                    max_points: 60,
                })
                .unwrap();
            assert_eq!(result.totals.download_bytes, "2000");
            assert_eq!(result.totals.upload_bytes, "1000");
            assert_eq!(result.coverage.exact_duration_ms, 10_000);
            assert_eq!(result.points.len(), 1);
            assert_eq!(result.points[0].sample_count, 2);
        }
    }

    #[test]
    fn rollup_batch_query_uses_cutoff_index_without_a_temp_sort() {
        let db = database();
        let conn = db.conn.lock().unwrap();
        let plan = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {ROLLUP_SAMPLE_BATCH_SQL}"))
            .unwrap()
            .query_map(params![60_000, 10], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(plan.iter().any(|detail| {
            detail.contains("SEARCH traffic_samples")
                && detail.contains("idx_traffic_samples_rollup_cutoff")
                && detail.contains("started_at_ms<?")
        }));
        assert!(!plan
            .iter()
            .any(|detail| detail.contains("SCAN traffic_samples")));
        assert!(!plan.iter().any(|detail| detail.contains("TEMP B-TREE")));
    }

    #[test]
    fn rollup_batches_reject_overlaps_even_below_bucket_coverage() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        for (started_at_ms, ended_at_ms, counter) in
            [(20_000, 40_000, "4000"), (30_000, 50_000, "8000")]
        {
            assert!(db
                .commit_sample_and_checkpoint(
                    &TrafficSampleInput {
                        router_id: router.id,
                        interface_id: interface.id,
                        started_at_ms,
                        ended_at_ms,
                        duration_ms: 20_000,
                        download_bytes: 2_000,
                        upload_bytes: 1_000,
                        download_bps: 800.0,
                        upload_bps: 400.0,
                        quality: TrafficQuality::Exact,
                        source: "overlap-fixture",
                    },
                    &CounterCheckpointInput {
                        router_id: router.id,
                        interface_id: interface.id,
                        rx_counter: counter,
                        tx_counter: counter,
                        observed_at_ms: ended_at_ms,
                        reboot_marker: Some("boot-a"),
                    },
                )
                .unwrap());
        }

        let same_batch_error = db
            .rollup_exact_samples_batch(60_000, 60_000, 2)
            .unwrap_err();
        assert!(same_batch_error
            .to_string()
            .contains("raw traffic samples overlap"));
        let (raw_samples, rollups): (i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM traffic_samples),
                        (SELECT COUNT(*) FROM traffic_rollups)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((raw_samples, rollups), (2, 0));

        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 1).unwrap(), 1);
        let error = db
            .rollup_exact_samples_batch(60_000, 60_000, 1)
            .unwrap_err();
        assert!(error.to_string().contains("coverage ordering"));
        let (raw_samples, rollups): (i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM traffic_samples),
                        (SELECT COUNT(*) FROM traffic_rollups)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((raw_samples, rollups), (1, 1));
    }

    #[test]
    fn rollup_batches_reject_cumulative_sqlite_integer_overflow() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let bytes_per_sample = i64::MAX / 2 + 1;
        for index in 0..2 {
            let started_at_ms = index * 5_000;
            let ended_at_ms = started_at_ms + 5_000;
            let counter = (index + 1).to_string();
            assert!(db
                .commit_sample_and_checkpoint(
                    &TrafficSampleInput {
                        router_id: router.id,
                        interface_id: interface.id,
                        started_at_ms,
                        ended_at_ms,
                        duration_ms: 5_000,
                        download_bytes: bytes_per_sample,
                        upload_bytes: 0,
                        download_bps: bytes_per_sample as f64 * 1.6,
                        upload_bps: 0.0,
                        quality: TrafficQuality::Exact,
                        source: "overflow-fixture",
                    },
                    &CounterCheckpointInput {
                        router_id: router.id,
                        interface_id: interface.id,
                        rx_counter: &counter,
                        tx_counter: &counter,
                        observed_at_ms: ended_at_ms,
                        reboot_marker: Some("boot-a"),
                    },
                )
                .unwrap());
        }

        assert_eq!(db.rollup_exact_samples_batch(60_000, 60_000, 1).unwrap(), 1);
        let error = db
            .rollup_exact_samples_batch(60_000, 60_000, 1)
            .unwrap_err();
        assert!(error.to_string().contains("integer limits"));
        let (raw_samples, stored_bytes): (i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM traffic_samples), exact_download_bytes
                 FROM traffic_rollups",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(raw_samples, 1);
        assert_eq!(stored_bytes, bytes_per_sample);
    }

    #[test]
    fn rollup_segment_budget_splits_long_samples_without_byte_loss() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        assert!(db
            .commit_sample_and_checkpoint(
                &TrafficSampleInput {
                    router_id: router.id,
                    interface_id: interface.id,
                    started_at_ms: 0,
                    ended_at_ms: 180_000,
                    duration_ms: 180_000,
                    download_bytes: 1_801,
                    upload_bytes: 901,
                    download_bps: 80.04444444444445,
                    upload_bps: 40.044444444444444,
                    quality: TrafficQuality::Exact,
                    source: "long-fixture",
                },
                &CounterCheckpointInput {
                    router_id: router.id,
                    interface_id: interface.id,
                    rx_counter: "1801",
                    tx_counter: "901",
                    observed_at_ms: 180_000,
                    reboot_marker: Some("boot-a"),
                },
            )
            .unwrap());

        assert_eq!(
            db.rollup_exact_samples_batch(180_000, 60_000, 1).unwrap(),
            0
        );
        let remainder_start: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT started_at_ms FROM traffic_samples", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remainder_start, 120_000);
        let partial = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 180_000,
                max_points: 180,
            })
            .unwrap();
        assert_eq!(partial.totals.download_bytes, "1801");
        assert_eq!(partial.totals.upload_bytes, "901");
        assert_eq!(partial.coverage.covered_duration_ms, 180_000);

        assert_eq!(
            db.rollup_exact_samples_batch(180_000, 60_000, 1).unwrap(),
            1
        );
        let completed = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 180_000,
                max_points: 180,
            })
            .unwrap();
        assert_eq!(completed.totals.download_bytes, "1801");
        assert_eq!(completed.totals.upload_bytes, "901");
        assert_eq!(completed.coverage.covered_duration_ms, 180_000);
    }

    #[test]
    fn retention_batches_delete_each_source_oldest_first_and_keep_checkpoints() {
        let db = database();
        let (router_id, interface_id) =
            seed_retention_history(&db, &[5_000, 10_000, 15_000, 30_000]);

        let error = db.prune_exact_history_batch(15_000, 0).unwrap_err();
        assert!(error.to_string().contains("batch size must be positive"));
        assert_eq!(db.prune_exact_history_batch(15_000, 2).unwrap(), 6);
        let remaining: (i64, i64, i64, i64, i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM traffic_samples WHERE ended_at_ms <= 15000),
                     (SELECT MIN(ended_at_ms) FROM traffic_samples WHERE ended_at_ms <= 15000),
                     (SELECT COUNT(*) FROM traffic_rollups WHERE bucket_end_ms <= 15000),
                     (SELECT MIN(bucket_end_ms) FROM traffic_rollups WHERE bucket_end_ms <= 15000),
                     (SELECT COUNT(*) FROM traffic_gaps WHERE ended_at_ms <= 15000),
                     (SELECT MIN(ended_at_ms) FROM traffic_gaps WHERE ended_at_ms <= 15000)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(remaining, (1, 15_000, 1, 15_000, 1, 15_000));

        assert_eq!(db.prune_exact_history_batch(15_000, 2).unwrap(), 3);
        assert_eq!(db.prune_exact_history_batch(15_000, 2).unwrap(), 0);
        let retained: (i64, i64, i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM traffic_samples),
                     (SELECT COUNT(*) FROM traffic_rollups),
                     (SELECT COUNT(*) FROM traffic_gaps),
                     (SELECT observed_at_ms FROM counter_checkpoints
                      WHERE router_id = ?1 AND interface_id = ?2)",
                params![router_id, interface_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(retained, (1, 1, 1, 30_000));
    }

    #[test]
    fn retention_batch_rolls_back_all_sources_when_one_delete_fails() {
        let db = database();
        seed_retention_history(&db, &[5_000]);
        db.conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_rollup_retention
                 BEFORE DELETE ON traffic_rollups
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .unwrap();

        assert!(db.prune_exact_history_batch(5_000, 1).is_err());
        let counts: (i64, i64, i64) = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM traffic_samples),
                     (SELECT COUNT(*) FROM traffic_rollups),
                     (SELECT COUNT(*) FROM traffic_gaps)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (1, 1, 1));
    }

    #[test]
    fn retention_batch_queries_use_cutoff_indexes_without_temp_sorts() {
        let db = database();
        let conn = db.conn.lock().unwrap();
        for (sql, table, index, cutoff) in [
            (
                PRUNE_TRAFFIC_SAMPLES_BATCH_SQL,
                "traffic_samples",
                "idx_traffic_samples_retention",
                "ended_at_ms<?",
            ),
            (
                PRUNE_TRAFFIC_ROLLUPS_BATCH_SQL,
                "traffic_rollups",
                "idx_traffic_rollups_retention",
                "bucket_end_ms<?",
            ),
            (
                PRUNE_TRAFFIC_GAPS_BATCH_SQL,
                "traffic_gaps",
                "idx_traffic_gaps_retention",
                "ended_at_ms<?",
            ),
        ] {
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(params![15_000, 2], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(plan.iter().any(|detail| {
                detail.contains(&format!("SEARCH {table}"))
                    && detail.contains(index)
                    && detail.contains(cutoff)
            }));
            assert!(!plan
                .iter()
                .any(|detail| detail.contains(&format!("SCAN {table}"))));
            assert!(!plan.iter().any(|detail| detail.contains("TEMP B-TREE")));
        }
    }

    #[test]
    fn transiently_missing_hardware_identity_reuses_router_history() {
        let db = database();
        let identified = db
            .resolve_router(Some("serial-a"), "192.0.2.1", 1_000)
            .unwrap();
        let unavailable = db.resolve_router(None, "192.0.2.1", 2_000).unwrap();
        let restored = db
            .resolve_router(Some("serial-a"), "192.0.2.1", 3_000)
            .unwrap();

        assert_eq!(unavailable.id, identified.id);
        assert_eq!(restored.id, identified.id);
        assert_eq!(restored.last_seen_at_ms, 3_000);
    }

    #[test]
    fn partial_range_is_proportioned_and_marked_estimated() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        insert_sample(&db, router.id, interface.id, 10_000, TrafficQuality::Exact);

        let result = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 12_000,
                to_ms: 14_000,
                max_points: 100,
            })
            .unwrap();

        assert_eq!(result.points.len(), 1);
        assert_eq!(result.points[0].started_at_ms, 12_000);
        assert_eq!(result.points[0].ended_at_ms, 14_000);
        assert_eq!(result.totals.download_bytes, "400");
        assert_eq!(result.totals.exact_download_bytes, "0");
        assert_eq!(result.totals.estimated_download_bytes, "400");
        assert_eq!(result.coverage.exact_duration_ms, 0);
        assert_eq!(result.coverage.estimated_duration_ms, 2_000);
        assert_eq!(result.coverage.completeness, 1.0);
    }

    #[test]
    fn downsampling_does_not_change_exact_totals_or_coverage() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let sample = TrafficSampleInput {
            router_id: router.id,
            interface_id: interface.id,
            started_at_ms: 5_000,
            ended_at_ms: 15_000,
            duration_ms: 10_000,
            download_bytes: 2_000,
            upload_bytes: 1_000,
            download_bps: 1_600.0,
            upload_bps: 800.0,
            quality: TrafficQuality::Exact,
            source: "fixture",
        };
        let checkpoint = CounterCheckpointInput {
            router_id: router.id,
            interface_id: interface.id,
            rx_counter: "2000",
            tx_counter: "1000",
            observed_at_ms: 15_000,
            reboot_marker: Some("boot-a"),
        };
        db.commit_sample_and_checkpoint(&sample, &checkpoint)
            .unwrap();

        let query = |max_points| {
            db.query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 20_000,
                max_points,
            })
            .unwrap()
        };
        let one_bucket = query(1);
        let split_buckets = query(2);
        assert_eq!(one_bucket.totals.exact_download_bytes, "2000");
        assert_eq!(split_buckets.totals.exact_download_bytes, "2000");
        assert_eq!(one_bucket.totals.estimated_download_bytes, "0");
        assert_eq!(split_buckets.totals.estimated_download_bytes, "0");
        assert_eq!(one_bucket.coverage.exact_duration_ms, 10_000);
        assert_eq!(split_buckets.coverage.exact_duration_ms, 10_000);
    }

    #[test]
    fn source_row_budget_rejects_instead_of_truncating_exact_totals() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        for started_at_ms in [0, 5_000, 10_000, 15_000] {
            insert_sample(
                &db,
                router.id,
                interface.id,
                started_at_ms,
                TrafficQuality::Exact,
            );
        }

        let wide_query = TrafficQuery {
            router_id: router.id,
            interface_id: interface.id,
            from_ms: 0,
            to_ms: 20_000,
            max_points: 2,
        };
        let error = db
            .query_traffic_v4_with_options(&wide_query, 3, None)
            .unwrap_err();
        assert!(matches!(
            error,
            DatabaseError::TrafficQueryTooLarge { max_source_rows: 3 }
        ));

        let narrowed = db
            .query_traffic_v4_with_options(
                &TrafficQuery {
                    to_ms: 15_000,
                    ..wide_query
                },
                3,
                None,
            )
            .unwrap();
        assert_eq!(narrowed.totals.exact_download_bytes, "3000");
        assert_eq!(narrowed.coverage.exact_duration_ms, 15_000);
        assert!(narrowed.points.len() <= 2);
    }

    #[test]
    fn cancelled_query_stops_waiting_for_the_database_lock() {
        let db = Arc::new(database());
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let query = TrafficQuery {
            router_id: router.id,
            interface_id: interface.id,
            from_ms: 0,
            to_ms: 20_000,
            max_points: 2,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let conn_guard = db.conn.lock().unwrap();
        let worker_db = db.clone();
        let worker_cancelled = cancelled.clone();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = worker_db.query_traffic_v4_cancellable(&query, worker_cancelled);
            let _ = result_tx.send(result);
        });

        std::thread::sleep(Duration::from_millis(20));
        cancelled.store(true, Ordering::Relaxed);
        let result = result_rx.recv_timeout(Duration::from_secs(1));
        drop(conn_guard);
        worker.join().unwrap();

        assert!(matches!(
            result.unwrap().unwrap_err(),
            DatabaseError::TrafficQueryCancelled
        ));
    }

    #[test]
    fn sqlite_progress_handler_interrupts_and_is_removed_after_query() {
        let conn = Connection::open_in_memory().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let guard = TrafficQueryProgressGuard::install(&conn, cancelled.clone());
        cancelled.store(true, Ordering::Relaxed);
        let error = conn
            .query_row(
                "WITH RECURSIVE counter(value) AS (
                     VALUES(1) UNION ALL SELECT value + 1 FROM counter WHERE value < 100000
                 ) SELECT SUM(value) FROM counter",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OperationInterrupted)
        );
        drop(guard);
        assert_eq!(
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn duplicate_sample_is_idempotent_but_conflicting_checkpoint_is_rejected() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        let sample = TrafficSampleInput {
            router_id: router.id,
            interface_id: interface.id,
            started_at_ms: 10_000,
            ended_at_ms: 15_000,
            duration_ms: 5_000,
            download_bytes: 1_000,
            upload_bytes: 500,
            download_bps: 1_600.0,
            upload_bps: 800.0,
            quality: TrafficQuality::Exact,
            source: "fixture",
        };
        let checkpoint = CounterCheckpointInput {
            router_id: router.id,
            interface_id: interface.id,
            rx_counter: "11000",
            tx_counter: "12000",
            observed_at_ms: 15_000,
            reboot_marker: Some("boot-a"),
        };

        assert!(db
            .commit_sample_and_checkpoint(&sample, &checkpoint)
            .unwrap());
        assert!(!db
            .commit_sample_and_checkpoint(&sample, &checkpoint)
            .unwrap());
        let conflicting = CounterCheckpointInput {
            rx_counter: "11001",
            ..checkpoint
        };
        assert!(db
            .commit_sample_and_checkpoint(&sample, &conflicting)
            .is_err());
        assert_eq!(
            db.counter_checkpoint(router.id, interface.id)
                .unwrap()
                .unwrap()
                .rx_counter,
            "11000"
        );
    }

    #[test]
    fn gap_and_checkpoint_commit_atomically_and_retry_idempotently() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        insert_sample(&db, router.id, interface.id, 10_000, TrafficQuality::Exact);
        let gap = TrafficGapInput {
            router_id: router.id,
            interface_id: Some(interface.id),
            started_at_ms: 15_000,
            ended_at_ms: 20_000,
            reason: "counter_reset",
            details: Some("router counter moved backwards"),
        };
        let checkpoint = CounterCheckpointInput {
            router_id: router.id,
            interface_id: interface.id,
            rx_counter: "5",
            tx_counter: "8",
            observed_at_ms: 20_000,
            reboot_marker: Some("boot-a"),
        };

        assert!(db.commit_gap_and_checkpoint(&gap, &checkpoint).unwrap());
        assert!(!db.commit_gap_and_checkpoint(&gap, &checkpoint).unwrap());
        assert_eq!(
            db.conn
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM traffic_gaps", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn overlapping_sources_are_rejected_instead_of_double_counted() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        insert_sample(&db, router.id, interface.id, 10_000, TrafficQuality::Exact);
        db.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO traffic_rollups(
                     router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
                     estimated_download_bytes, estimated_upload_bytes, estimated_duration_ms,
                     sample_count, source, created_at_ms
                 ) VALUES (?1, ?2, 0, 60000, 60000, 2000, 1000, 60000, 1, 'overlap', 60000)",
                params![router.id, interface.id],
            )
            .unwrap();

        let error = db
            .query_traffic_v4(&TrafficQuery {
                router_id: router.id,
                interface_id: interface.id,
                from_ms: 0,
                to_ms: 60_000,
                max_points: 100,
            })
            .unwrap_err();
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn failed_rollup_keeps_raw_samples() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let interface = db
            .upsert_router_interface(router.id, "ether1", "WAN", "wan", None, 1_000)
            .unwrap();
        insert_sample(&db, router.id, interface.id, 10_000, TrafficQuality::Exact);
        db.conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_rollup BEFORE INSERT ON traffic_rollups
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .unwrap();

        assert!(db.rollup_exact_samples(30_000, 60_000).is_err());
        let raw_count: u64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM traffic_samples", [], |row| row.get(0))
            .unwrap();
        assert_eq!(raw_count, 1);
    }

    #[test]
    fn traffic_router_selection_prefers_configured_target_and_falls_back_to_history() {
        let db = database();
        let legacy = db
            .resolve_router(None, "legacy://unidentified", 2_000)
            .unwrap();
        let legacy_aggregate = db
            .upsert_router_interface(
                legacy.id,
                "__aggregate__",
                "Aggregate",
                "aggregate",
                None,
                2_000,
            )
            .unwrap();
        insert_sample(
            &db,
            legacy.id,
            legacy_aggregate.id,
            10_000,
            TrafficQuality::Estimated,
        );

        let fallback = db.current_router_for_target("192.0.2.1").unwrap().unwrap();
        assert_eq!(fallback.id, legacy.id);

        let configured = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let selected = db.current_router_for_target("192.0.2.1").unwrap().unwrap();
        assert_eq!(selected.id, configured.id);
        let adopted_aggregate = db
            .traffic_interface_for_query(configured.id, None)
            .unwrap()
            .unwrap();
        let adopted_history = db
            .query_traffic_v4(&TrafficQuery {
                router_id: configured.id,
                interface_id: adopted_aggregate.id,
                from_ms: 10_000,
                to_ms: 15_000,
                max_points: 10,
            })
            .unwrap();
        assert_eq!(adopted_history.totals.estimated_download_bytes, "1000");
        assert_eq!(adopted_history.coverage.estimated_duration_ms, 5_000);
    }

    #[test]
    fn traffic_interface_selection_never_conflates_wan_and_aggregate() {
        let db = database();
        let router = db.resolve_router(None, "192.0.2.1", 1_000).unwrap();
        let aggregate = db
            .upsert_router_interface(
                router.id,
                "__aggregate__",
                "Aggregate",
                "aggregate",
                None,
                1_000,
            )
            .unwrap();
        let stale_wan = db
            .upsert_router_interface(router.id, "*1", "WAN", "wan", None, 1_000)
            .unwrap();
        let current_wan = db
            .upsert_router_interface(router.id, "*2", "WAN", "wan", None, 2_000)
            .unwrap();
        db.upsert_router_interface(router.id, "*3", "Backup", "wan", None, 2_000)
            .unwrap();

        assert_eq!(
            db.traffic_interface_for_query(router.id, None)
                .unwrap()
                .unwrap()
                .id,
            aggregate.id
        );
        let selected_wan = db
            .traffic_interface_for_query(router.id, Some("WAN"))
            .unwrap()
            .unwrap();
        assert_ne!(selected_wan.id, stale_wan.id);
        assert_eq!(selected_wan.id, current_wan.id);
        assert!(db
            .traffic_interface_for_query(router.id, Some("Aggregate"))
            .unwrap()
            .is_none());

        let interfaces = db.router_wan_interfaces(router.id).unwrap();
        assert_eq!(
            interfaces
                .iter()
                .map(|interface| interface.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Backup", "WAN", "WAN"]
        );
    }
}
