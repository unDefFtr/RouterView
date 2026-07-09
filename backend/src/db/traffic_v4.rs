use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::types::{DatabaseError, DatabaseResult};
use super::TrafficDb;

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

    pub fn record_traffic_gap(&self, gap: &TrafficGapInput<'_>) -> DatabaseResult<bool> {
        validate_gap(gap)?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        ensure_interface_owner(&conn, gap.router_id, gap.interface_id)?;
        let inserted = conn.execute(
            "INSERT INTO traffic_gaps(
                 router_id, interface_id, started_at_ms, ended_at_ms,
                 reason, details, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?4)
             ON CONFLICT(router_id, interface_id, started_at_ms, ended_at_ms, reason)
             DO NOTHING",
            params![
                gap.router_id,
                gap.interface_id,
                gap.started_at_ms,
                gap.ended_at_ms,
                gap.reason,
                gap.details,
            ],
        )?;
        if inserted == 0
            && gap_details_for_connection(&conn, gap)?.as_deref() != Some(gap.details.unwrap_or(""))
        {
            return Err(DatabaseError::Verification(
                "duplicate traffic gap key contains different details".into(),
            ));
        }
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

    pub fn rollup_exact_samples(
        &self,
        before_ms: i64,
        bucket_size_ms: i64,
    ) -> DatabaseResult<usize> {
        if bucket_size_ms <= 0 {
            return Err(DatabaseError::InvalidCommand(
                "rollup bucket size must be positive".into(),
            ));
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO traffic_rollups(
                 router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
                 exact_download_bytes, exact_upload_bytes,
                 estimated_download_bytes, estimated_upload_bytes,
                 exact_duration_ms, estimated_duration_ms, sample_count,
                 download_avg_bps, upload_avg_bps, source, created_at_ms
             )
             SELECT router_id, interface_id,
                    ((ended_at_ms - 1) / ?2) * ?2 AS bucket_start,
                    (((ended_at_ms - 1) / ?2) + 1) * ?2 AS bucket_end,
                    ?2,
                    SUM(CASE WHEN quality = 'exact' THEN download_bytes ELSE 0 END),
                    SUM(CASE WHEN quality = 'exact' THEN upload_bytes ELSE 0 END),
                    SUM(CASE WHEN quality = 'estimated' THEN download_bytes ELSE 0 END),
                    SUM(CASE WHEN quality = 'estimated' THEN upload_bytes ELSE 0 END),
                    SUM(CASE WHEN quality = 'exact' THEN duration_ms ELSE 0 END),
                    SUM(CASE WHEN quality = 'estimated' THEN duration_ms ELSE 0 END),
                    COUNT(*),
                    SUM(download_bytes) * 8000.0 / MAX(1, SUM(duration_ms)),
                    SUM(upload_bytes) * 8000.0 / MAX(1, SUM(duration_ms)),
                    'raw-rollup', ?1
             FROM traffic_samples
             WHERE ended_at_ms < ?1
             GROUP BY router_id, interface_id, bucket_start
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
                 bucket_end_ms = excluded.bucket_end_ms,
                 created_at_ms = excluded.created_at_ms",
            params![before_ms, bucket_size_ms],
        )?;
        let deleted = tx.execute(
            "DELETE FROM traffic_samples WHERE ended_at_ms < ?1",
            params![before_ms],
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    pub fn query_traffic_v4(&self, query: &TrafficQuery) -> DatabaseResult<TrafficQueryResult> {
        if query.to_ms <= query.from_ms || query.max_points == 0 || query.max_points > 50_000 {
            return Err(DatabaseError::InvalidCommand(
                "traffic query requires an increasing range and 1..=50000 max_points".into(),
            ));
        }
        let range = query.to_ms.saturating_sub(query.from_ms);
        let minimum_bucket_size_ms = range
            .saturating_add(query.max_points as i64 - 1)
            .checked_div(query.max_points as i64)
            .unwrap_or(1)
            .max(1);
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        ensure_interface_owner(&conn, query.router_id, Some(query.interface_id))?;
        let mut contributions = load_traffic_contributions(&conn, query)?;
        contributions.sort_by_key(|item| (item.started_at_ms, item.ended_at_ms));
        validate_non_overlapping_contributions(&contributions)?;
        let source_resolution_ms = contributions
            .iter()
            .map(TrafficContribution::duration_ms)
            .max()
            .unwrap_or(1);
        let bucket_size_ms = minimum_bucket_size_ms.max(source_resolution_ms);

        let mut buckets: BTreeMap<i64, TrafficBucketAccumulator> = BTreeMap::new();
        for contribution in &contributions {
            let clipped_start = contribution.started_at_ms.max(query.from_ms);
            let clipped_end = contribution.ended_at_ms.min(query.to_ms);
            let mut segment_start = clipped_start;
            while segment_start < clipped_end {
                let bucket_index = (segment_start - query.from_ms) / bucket_size_ms;
                let bucket_start = query.from_ms + bucket_index * bucket_size_ms;
                let bucket_end = bucket_start.saturating_add(bucket_size_ms).min(query.to_ms);
                let segment_end = clipped_end.min(bucket_end);
                let accumulator = buckets.entry(bucket_start).or_default();
                accumulator.add_segment(contribution, segment_start, segment_end)?;
                segment_start = segment_end;
            }
        }

        let mut points = Vec::with_capacity(buckets.len());
        let mut exact_download = 0_i128;
        let mut exact_upload = 0_i128;
        let mut estimated_download = 0_i128;
        let mut estimated_upload = 0_i128;
        let mut exact_duration = 0_i64;
        let mut estimated_duration = 0_i64;
        for (started_at_ms, bucket) in buckets {
            exact_download += bucket.exact_download_bytes;
            exact_upload += bucket.exact_upload_bytes;
            estimated_download += bucket.estimated_download_bytes;
            estimated_upload += bucket.estimated_upload_bytes;
            exact_duration = exact_duration.saturating_add(bucket.exact_duration_ms);
            estimated_duration = estimated_duration.saturating_add(bucket.estimated_duration_ms);
            let duration = bucket
                .exact_duration_ms
                .saturating_add(bucket.estimated_duration_ms)
                .max(1);
            points.push(TrafficBucket {
                started_at_ms,
                ended_at_ms: started_at_ms
                    .saturating_add(bucket_size_ms)
                    .min(query.to_ms),
                download_bps: (bucket.exact_download_bytes + bucket.estimated_download_bytes)
                    as f64
                    * 8000.0
                    / duration as f64,
                upload_bps: (bucket.exact_upload_bytes + bucket.estimated_upload_bytes) as f64
                    * 8000.0
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
        let covered_duration = exact_duration.saturating_add(estimated_duration);
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
                download_bytes: (exact_download + estimated_download).to_string(),
                upload_bytes: (exact_upload + estimated_upload).to_string(),
                exact_download_bytes: exact_download.to_string(),
                exact_upload_bytes: exact_upload.to_string(),
                estimated_download_bytes: estimated_download.to_string(),
                estimated_upload_bytes: estimated_upload.to_string(),
            },
            coverage: TrafficCoverage {
                requested_duration_ms: range,
                exact_duration_ms: exact_duration,
                estimated_duration_ms: estimated_duration,
                covered_duration_ms: covered_duration,
                completeness,
                gap_count,
            },
        })
    }
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

fn load_traffic_contributions(
    conn: &rusqlite::Connection,
    query: &TrafficQuery,
) -> DatabaseResult<Vec<TrafficContribution>> {
    let mut statement = conn.prepare(
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
         UNION ALL
         SELECT bucket_start_ms, bucket_end_ms,
                exact_download_bytes, exact_upload_bytes,
                estimated_download_bytes, estimated_upload_bytes,
                exact_duration_ms, estimated_duration_ms, sample_count
         FROM traffic_rollups
         WHERE router_id = ?1 AND interface_id = ?2
           AND bucket_end_ms > ?3 AND bucket_start_ms < ?4",
    )?;
    let rows = statement.query_map(
        params![
            query.router_id,
            query.interface_id,
            query.from_ms,
            query.to_ms
        ],
        |row| {
            Ok(TrafficContribution {
                started_at_ms: row.get(0)?,
                ended_at_ms: row.get(1)?,
                exact_download_bytes: i128::from(row.get::<_, i64>(2)?),
                exact_upload_bytes: i128::from(row.get::<_, i64>(3)?),
                estimated_download_bytes: i128::from(row.get::<_, i64>(4)?),
                estimated_upload_bytes: i128::from(row.get::<_, i64>(5)?),
                exact_duration_ms: row.get(6)?,
                estimated_duration_ms: row.get(7)?,
                sample_count: row.get(8)?,
            })
        },
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn validate_non_overlapping_contributions(
    contributions: &[TrafficContribution],
) -> DatabaseResult<()> {
    let mut previous_end = None;
    for contribution in contributions {
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
        previous_end = Some(contribution.ended_at_ms);
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
            |row| {
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
            },
        )
        .optional()?)
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
}
