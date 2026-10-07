//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use std::{fs, path::Path, str::FromStr};

use chrono::Utc;
use cron::Schedule;

use tokio::{
    sync::broadcast,
    task::JoinHandle,
    time::{interval, interval_at, sleep, Duration, Instant, MissedTickBehavior},
};

use crate::backup::{region_is_healthy, S3ClientWrapper};
use crate::config::OnlineBackup;
use crate::{CoreAction, TaskName};

use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use kubidm_proto::backup::{PitrManifest, ReplicationConfig, S3Config};
use kubidmd_lib::constants::PURGE_FREQUENCY;
use kubidmd_lib::event::{
    OnlineBackupEvent, PurgeDeleteAfterEvent, PurgeRecycledEvent, PurgeTombstoneEvent,
};

pub(crate) struct IntervalActor;

impl IntervalActor {
    pub fn start(
        server: &'static QueryServerWriteV1,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut inter = interval(Duration::from_secs(PURGE_FREQUENCY));
            inter.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                server
                    .handle_purgetombstoneevent(PurgeTombstoneEvent::new())
                    .await;
                server
                    .handle_purgerecycledevent(PurgeRecycledEvent::new())
                    .await;
                server
                    .handle_purge_delete_after_event(PurgeDeleteAfterEvent::new())
                    .await;

                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => continue,
                        }
                    }
                    _ = inter.tick() => {
                        // Next iter.
                        continue
                    }
                }
            }

            info!("Stopped {}", super::TaskName::IntervalActor);
        })
    }

    /// Start the scheduled online backup and, when the S3 configuration enables
    /// cross-region replication, the replication health monitor next to it. Returns the
    /// handles of the started tasks.
    // Allow this because result is the only way to map and ? to bubble up, but we aren't
    // returning an op-error here because this is in early start up.
    #[allow(clippy::result_unit_err)]
    pub fn start_online_backup(
        server: &'static QueryServerReadV1,
        online_backup_config: &OnlineBackup,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> Result<Vec<(TaskName, JoinHandle<()>)>, ()> {
        let outpath = online_backup_config.path.to_owned();
        let has_local_path = outpath.is_some();
        let has_s3_config = online_backup_config.s3.is_some();

        if !has_local_path && !has_s3_config {
            error!("Online backup output path is not set and S3 is not configured.");
            return Err(());
        }

        let versions = online_backup_config.versions;
        let crono_expr = online_backup_config.schedule.as_str().to_string();
        let mut crono_expr_values = crono_expr.split_ascii_whitespace().collect::<Vec<&str>>();
        let chrono_expr_uses_standard_syntax = crono_expr_values.len() == 5;
        if chrono_expr_uses_standard_syntax {
            // we add a 0 element at the beginning to simulate the standard crono syntax which always runs
            // commands at seconds 00
            crono_expr_values.insert(0, "0");
            crono_expr_values.push("*");
        }
        let crono_expr_schedule = crono_expr_values.join(" ");
        if chrono_expr_uses_standard_syntax {
            info!(
                "Provided online backup schedule is: {}, now being transformed to: {}",
                crono_expr, crono_expr_schedule
            );
        }
        // Cron expression handling
        let cron_expr = Schedule::from_str(crono_expr_schedule.as_str()).map_err(|e| {
            error!("Online backup schedule parse error: {}", e);
            error!("valid formats are:");
            error!("sec  min   hour   day of month   month   day of week   year");
            error!("min   hour   day of month   month   day of week");
            error!("@hourly | @daily | @weekly");
        })?;

        info!("Online backup schedule parsed as: {}", cron_expr);

        if cron_expr.upcoming(Utc).next().is_none() {
            error!(
                "Online backup schedule error: '{}' will not match any date.",
                cron_expr
            );
            return Err(());
        }

        // Output path handling - only for local backups
        if let Some(ref path) = outpath {
            let op = Path::new(path);

            // does the path exist and is a directory?
            if !op.exists() {
                info!(
                    "Online backup output folder '{}' does not exist, trying to create it.",
                    path.display()
                );
                fs::create_dir_all(path).map_err(|e| {
                    error!(
                        "Online backup failed to create output directory '{}': {}",
                        path.display(),
                        e
                    )
                })?;
            }

            if !op.is_dir() {
                error!("Online backup output '{}' is not a directory or we are missing permissions to access it.", path.display());
                return Err(());
            }
        }

        let backup_compression = online_backup_config.compression;
        let s3_config = online_backup_config.s3.clone();
        let wal_archive_config = online_backup_config.wal_archive.clone();

        let mut handles = Vec::with_capacity(2);

        // The health monitor is a separate task with its own shutdown receiver, so a slow
        // or unreachable region can never delay the backup schedule.
        if let Some(replication) = s3_config
            .as_ref()
            .and_then(|s3| s3.replication.clone())
            .filter(|replication| replication.enabled)
        {
            if let Some(s3_cfg) = &s3_config {
                handles.push((
                    TaskName::BackupReplicationMonitor,
                    Self::start_replication_monitor(s3_cfg.clone(), replication, rx.resubscribe()),
                ));
            }
        }

        let handle = tokio::spawn(async move {
            for next_time in cron_expr.upcoming(Utc) {
                let wait_seconds = 1 + (next_time - Utc::now()).num_seconds() as u64;
                info!(
                    "Online backup next run on {}, wait_time = {}s",
                    next_time, wait_seconds
                );

                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => {}
                        }
                    }
                    _ = sleep(Duration::from_secs(wait_seconds)) => {
                        let backup_timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
                        let backup_id = format!("backup-{}.json", backup_timestamp);

                        // Perform local backup if path is configured
                        if let Some(ref path) = outpath {
                            if let Err(e) = server
                                .handle_online_backup(
                                    OnlineBackupEvent::new(),
                                    path,
                                    versions,
                                    backup_compression,
                                    None,
                                )
                                .await
                            {
                                error!(?e, "An online backup error occurred.");
                            }
                        }

                        // Perform S3 backup if configured
                        if let Some(s3_cfg) = &s3_config {
                            match S3ClientWrapper::new(s3_cfg.clone()).await {
                                Ok(s3_client) => {
                                    // Update PITR manifest after successful S3 backup
                                    if let Some(wal_cfg) = &wal_archive_config {
                                        if wal_cfg.enabled {
                                            if let Err(e) = update_pitr_manifest(&s3_client, &backup_id, &backup_timestamp).await {
                                                error!(?e, "Failed to update PITR manifest.");
                                            }
                                        }
                                    }

                                    if let Err(e) = server
                                        .handle_online_backup(
                                            OnlineBackupEvent::new(),
                                            &std::path::PathBuf::from("s3://backup"),
                                            versions,
                                            backup_compression,
                                            Some(s3_client),
                                        )
                                        .await
                                    {
                                        error!(?e, "An S3 backup error occurred.");
                                    }
                                }
                                Err(e) => {
                                    error!(?e, "Failed to create S3 client.");
                                }
                            }
                        }
                    }
                }
            }
            info!("Stopped {}", TaskName::BackupActor);
        });
        handles.push((TaskName::BackupActor, handle));

        Ok(handles)
    }

    /// Check the cross-region replication health every `sync_interval_seconds` and log a
    /// warning for every region that misses or disagrees on a primary backup, or that can
    /// not be reached. The first check runs one interval after start up: nothing can be
    /// behind before the first backup of this process has been replicated.
    fn start_replication_monitor(
        s3_config: S3Config,
        replication: ReplicationConfig,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> JoinHandle<()> {
        let period = replication_monitor_period(&replication);
        tokio::spawn(async move {
            let mut ticks = interval_at(Instant::now() + period, period);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

            info!(
                "Backup replication monitor checks {} region(s) every {}s",
                replication.regions.len(),
                period.as_secs()
            );

            loop {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => {}
                        }
                    }
                    _ = ticks.tick() => {
                        report_replication_health(&s3_config, &replication).await;
                    }
                }
            }
            info!("Stopped {}", TaskName::BackupReplicationMonitor);
        })
    }
}

/// The period of the replication health monitor. The configuration rejects a zero
/// interval, but a zero period would panic in `interval_at`, so it is clamped here too.
fn replication_monitor_period(replication: &ReplicationConfig) -> Duration {
    Duration::from_secs(replication.sync_interval_seconds.max(1))
}

/// One run of the replication health monitor: a warning per unhealthy region, an info
/// line per healthy one. Never fails; a primary that can not be listed is a warning too.
async fn report_replication_health(s3_config: &S3Config, replication: &ReplicationConfig) {
    let client = match S3ClientWrapper::new(s3_config.clone()).await {
        Ok(client) => client,
        Err(err) => {
            warn!(
                "Backup replication health check skipped: unable to create the S3 client: {}",
                err
            );
            return;
        }
    };

    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let health = match client
        .check_replication_health(replication, Some(&now))
        .await
    {
        Ok(health) => health,
        Err(err) => {
            warn!(
                "Backup replication health check skipped: unable to list the primary backups \
                 in {}: {}",
                client.location(),
                err
            );
            return;
        }
    };

    for region in &health.regions {
        if region_is_healthy(region) {
            info!(
                "Backup replication to region {} (bucket {}) is healthy: {} backups replicated, \
                 newest {}",
                region.region,
                region.bucket,
                region.backups_replicated,
                region.last_sync_backup_id.as_deref().unwrap_or("none")
            );
        } else {
            warn!(
                "Backup replication to region {} (bucket {}) is unhealthy: {}; {} backups \
                 pending, lag {}",
                region.region,
                region.bucket,
                region.status,
                region.pending_backups,
                region
                    .lag_seconds
                    .map(|lag| format!("{lag}s"))
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
    }

    if health.unhealthy_regions > 0 {
        warn!(
            "Backup replication health: {} ({} regions healthy, {} unhealthy, max lag {}s)",
            health.overall_status,
            health.healthy_regions,
            health.unhealthy_regions,
            health.max_lag_seconds
        );
    } else {
        info!(
            "Backup replication health: {} ({} regions healthy, max lag {}s)",
            health.overall_status, health.healthy_regions, health.max_lag_seconds
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replication_monitor_period_follows_the_sync_interval() {
        let replication = ReplicationConfig {
            sync_interval_seconds: 600,
            ..ReplicationConfig::default()
        };
        assert_eq!(
            replication_monitor_period(&replication),
            Duration::from_secs(600)
        );

        // A zero interval is rejected by the configuration; the monitor never panics on it.
        let replication = ReplicationConfig {
            sync_interval_seconds: 0,
            ..ReplicationConfig::default()
        };
        assert_eq!(
            replication_monitor_period(&replication),
            Duration::from_secs(1)
        );
    }
}

async fn update_pitr_manifest(
    s3_client: &S3ClientWrapper,
    backup_id: &str,
    backup_timestamp: &str,
) -> Result<(), String> {
    use uuid::Uuid;

    let manifest_key = "pitr-manifest.json";

    let existing_manifest = match s3_client.download_backup(manifest_key).await {
        Ok((data, _)) => serde_json::from_slice::<PitrManifest>(&data).ok(),
        Err(_) => None,
    };

    let server_uuid = Uuid::new_v4();

    let mut manifest = existing_manifest.unwrap_or_else(|| {
        PitrManifest::new(
            server_uuid,
            backup_id.to_string(),
            backup_timestamp.to_string(),
        )
    });

    manifest.base_backup_id = backup_id.to_string();
    manifest.base_backup_timestamp = backup_timestamp.to_string();

    if !manifest.segments.is_empty() {
        manifest.earliest_recoverable_time = manifest
            .segments
            .first()
            .map(|s| s.created_at.clone())
            .unwrap_or_else(|| backup_timestamp.to_string());
    }
    manifest.latest_recoverable_time = backup_timestamp.to_string();

    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|e| format!("Failed to serialize PITR manifest: {}", e))?;

    s3_client
        .upload_backup(
            manifest_json.as_bytes(),
            manifest_key,
            backup_timestamp,
            kubidm_proto::backup::BackupCompression::NoCompression,
        )
        .await
        .map_err(|e| format!("Failed to upload PITR manifest: {}", e))?;

    info!("Updated PITR manifest with base backup: {}", backup_id);
    Ok(())
}
