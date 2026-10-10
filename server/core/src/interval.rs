//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use std::{fs, future::Future, path::Path, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use cron::Schedule;

use tokio::{
    sync::broadcast,
    task::JoinHandle,
    time::{interval, interval_at, sleep, Duration, Instant, MissedTickBehavior},
};

use crate::backup::metrics::{BackupDestination, BackupMetrics};
use crate::backup::online::OnlineBackupJob;
use crate::backup::pitr::PitrArchive;
use crate::backup::{region_is_healthy, RegionSyncOutcome, S3BackupError, S3ClientWrapper};
use crate::config::OnlineBackup;
use crate::{CoreAction, TaskName};

use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use kubidm_proto::backup::{ReplicationConfig, S3Config};
use kubidmd_lib::constants::PURGE_FREQUENCY;
use kubidmd_lib::event::{PurgeDeleteAfterEvent, PurgeRecycledEvent, PurgeTombstoneEvent};
use kubidmd_lib::prelude::duration_from_epoch_now;

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
        pitr_archive: Option<Arc<PitrArchive>>,
        metrics: Arc<BackupMetrics>,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> Result<Vec<(TaskName, JoinHandle<()>)>, ()> {
        let outpath = online_backup_config.path.to_owned();
        let has_local_path = outpath.is_some();
        let has_s3_config = online_backup_config.s3.is_some();

        if !has_local_path && !has_s3_config {
            error!("Online backup output path is not set and S3 is not configured.");
            return Err(());
        }

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

        let job = OnlineBackupJob::from_config(online_backup_config, pitr_archive, metrics.clone());
        let s3_config = online_backup_config.s3.clone();

        let mut handles = Vec::with_capacity(2);

        // The replication monitor is a separate task with its own shutdown receiver. It is
        // the only place that retries the copies to a region: the backup run makes a single
        // attempt per region and never waits for one.
        if let Some(replication) = s3_config
            .as_ref()
            .and_then(|s3| s3.replication.clone())
            .filter(|replication| replication.enabled)
        {
            if let Some(s3_cfg) = &s3_config {
                handles.push((
                    TaskName::BackupReplicationMonitor,
                    Self::start_replication_monitor(
                        s3_cfg.clone(),
                        replication,
                        metrics,
                        rx.resubscribe(),
                    ),
                ));
            }
        }

        let handle = tokio::spawn(async move {
            let mut last_run = None;
            loop {
                let now = Utc::now();
                let Some(next_time) = next_backup_time(&cron_expr, now, last_run) else {
                    info!("Online backup schedule '{}' has no further runs", cron_expr);
                    break;
                };
                let wait = wait_until(next_time, now);
                info!(
                    "Online backup next run on {}, wait_time = {}s",
                    next_time,
                    wait.as_secs()
                );

                tokio::select! {
                    action = rx.recv() => match action {
                        Ok(CoreAction::Shutdown) | Err(broadcast::error::RecvError::Closed) => {
                            break
                        }
                        // The schedule does not change on a reload: wait for the same run.
                        Ok(CoreAction::Reload) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            continue
                        }
                    },
                    _ = sleep(wait) => {}
                }

                last_run = Some(next_time);
                match run_until_shutdown(job.run(server), &mut rx).await {
                    Some(Ok(())) => {}
                    Some(Err(err)) => error!(?err, "An online backup error occurred."),
                    None => {
                        warn!(
                            "Online backup abandoned: the server is shutting down. The WAL \
                             archive is still synchronised, and the next scheduled run takes \
                             a new backup"
                        );
                        break;
                    }
                }
            }
            info!("Stopped {}", TaskName::BackupActor);
        });
        handles.push((TaskName::BackupActor, handle));

        Ok(handles)
    }

    /// Every `sync_interval_seconds`, copy to every region the primary backups it misses
    /// or holds a differing copy of, then check the replication health and log a warning
    /// for every region that is still behind or can not be reached. The first run happens
    /// one interval after start up. A run in progress is abandoned on shutdown.
    fn start_replication_monitor(
        s3_config: S3Config,
        replication: ReplicationConfig,
        metrics: Arc<BackupMetrics>,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> JoinHandle<()> {
        let period = replication_monitor_period(&replication);
        tokio::spawn(async move {
            let mut ticks = interval_at(Instant::now() + period, period);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

            info!(
                "Backup replication monitor syncs and checks {} region(s) every {}s",
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
                        let run = sync_and_report_replication(&s3_config, &replication, &metrics);
                        if run_until_shutdown(run, &mut rx).await.is_none() {
                            break;
                        }
                    }
                }
            }
            info!("Stopped {}", TaskName::BackupReplicationMonitor);
        })
    }
}

/// Drive `run` to completion unless the server shuts down first, in which case `run` is
/// dropped and None is returned. A reload does not interrupt it.
///
/// The backup actor and the replication monitor run their work through this so that a
/// shutdown never waits for a backup, an upload or a region copy in progress: the
/// shutdown has to reach the final WAL archive synchronisation before the service
/// manager's stop timeout. Blocking work already handed to the blocking thread pool
/// finishes on its own.
async fn run_until_shutdown<F: Future>(
    run: F,
    rx: &mut broadcast::Receiver<CoreAction>,
) -> Option<F::Output> {
    tokio::pin!(run);
    loop {
        tokio::select! {
            output = &mut run => return Some(output),
            action = rx.recv() => match action {
                Ok(CoreAction::Shutdown) | Err(broadcast::error::RecvError::Closed) => {
                    return None
                }
                Ok(CoreAction::Reload) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            },
        }
    }
}

/// The next scheduled backup: the first time of `schedule` after `now`, and after
/// `last_run`, the time of the previous run, when there was one.
///
/// It is computed from the current time on every iteration rather than taken from an
/// iterator built once, so a run that outlasted the gap to the next scheduled time skips
/// the times that are already past instead of falling behind for good. Starting after
/// `last_run` as well means a wall clock that lags the timer slightly can never run the
/// same scheduled time twice.
fn next_backup_time(
    schedule: &Schedule,
    now: DateTime<Utc>,
    last_run: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    let from = last_run.map_or(now, |last_run| last_run.max(now));
    schedule.after(&from).next()
}

/// How long to wait from `now` until `next_time`: zero when it is already past.
fn wait_until(next_time: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    (next_time - now).to_std().unwrap_or(Duration::ZERO)
}

/// The period of the replication health monitor. The configuration rejects a zero
/// interval, but a zero period would panic in `interval_at`, so it is clamped here too.
fn replication_monitor_period(replication: &ReplicationConfig) -> Duration {
    Duration::from_secs(replication.sync_interval_seconds.max(1))
}

/// One run of the replication monitor: copy what every region misses and report the
/// resulting health, a warning per unhealthy region and an info line per healthy one.
/// Never fails; a primary that can not be listed is a warning too.
async fn sync_and_report_replication(
    s3_config: &S3Config,
    replication: &ReplicationConfig,
    metrics: &BackupMetrics,
) {
    let client = match S3ClientWrapper::new(s3_config.clone()).await {
        Ok(client) => client,
        Err(err) => {
            warn!(
                "Backup replication sync skipped: unable to create the S3 client: {}",
                err
            );
            return;
        }
    };

    // One comparison per region serves both the copies and the health report, and every
    // region client is built once per run.
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let report = match client
        .sync_and_check_replication(replication, Some(&now))
        .await
    {
        Ok(report) => report,
        Err(err) => {
            warn!(
                "Backup replication sync skipped: unable to list the primary backups in {}: {}",
                client.location(),
                err
            );
            return;
        }
    };

    record_region_syncs(metrics, &report.synced, duration_from_epoch_now());

    for (region, result) in &report.synced {
        match result {
            Ok(outcome) => {
                if !outcome.copied.is_empty() {
                    info!(
                        "Backup replication sync copied {} backup(s) to region {}: {}",
                        outcome.copied.len(),
                        region,
                        outcome.copied.join(", ")
                    );
                }
                for (key, err) in &outcome.failed {
                    warn!(
                        "Backup replication sync failed to copy {} to region {}: {}",
                        key, region, err
                    );
                }
            }
            Err(err) => warn!(
                "Backup replication sync skipped region {}: unable to list it: {}",
                region, err
            ),
        }
    }

    let health = report.health;
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

/// Record in `metrics` what a replication sync did in every region at `now`. A copy is a
/// backup stored in the region, as the copy of the backup run is; a copy that failed, or a
/// region that could not be listed, is a failed one. A region that missed nothing is left
/// as it is.
fn record_region_syncs(
    metrics: &BackupMetrics,
    synced: &[(String, Result<RegionSyncOutcome, S3BackupError>)],
    now: Duration,
) {
    for (region, result) in synced {
        let destination = BackupDestination::S3Region(region.clone());
        match result {
            Ok(outcome) if !outcome.failed.is_empty() => metrics.backup_failed(&destination, now),
            Ok(outcome) if !outcome.copied.is_empty() => {
                metrics.backup_succeeded(&destination, now)
            }
            Ok(_) => {}
            Err(_) => metrics.backup_failed(&destination, now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, hour, minute, second)
            .single()
            .expect("valid time")
    }

    #[test]
    fn next_backup_time_skips_times_a_long_run_overran() {
        // Every five minutes.
        let schedule = Schedule::from_str("0 */5 * * * * *").expect("schedule");

        // The run scheduled at 10:00 took seven minutes, so 10:05 is already past. The
        // next run is 10:10, three minutes away, not 10:05 with a negative wait.
        let next = next_backup_time(&schedule, at(10, 7, 0), Some(at(10, 0, 0)));
        assert_eq!(next, Some(at(10, 10, 0)));
        assert_eq!(
            wait_until(at(10, 10, 0), at(10, 7, 0)),
            Duration::from_secs(180)
        );
    }

    #[test]
    fn next_backup_time_never_repeats_the_last_run() {
        let schedule = Schedule::from_str("0 */5 * * * * *").expect("schedule");

        // The timer fired a little before the wall clock reached 10:05.
        let next = next_backup_time(&schedule, at(10, 4, 59), Some(at(10, 5, 0)));
        assert_eq!(next, Some(at(10, 10, 0)));

        // Without a previous run the next time after now is taken.
        assert_eq!(
            next_backup_time(&schedule, at(10, 4, 59), None),
            Some(at(10, 5, 0))
        );
    }

    #[test]
    fn next_backup_time_is_stable_across_a_reload() {
        // A reload re-enters the wait: the same pending run must still be the next one.
        let schedule = Schedule::from_str("0 0 22 * * * *").expect("schedule");
        let before = next_backup_time(&schedule, at(9, 0, 0), Some(at(8, 0, 0)));
        let after_reload = next_backup_time(&schedule, at(9, 30, 0), Some(at(8, 0, 0)));
        assert_eq!(before, Some(at(22, 0, 0)));
        assert_eq!(after_reload, before);
    }

    #[tokio::test]
    async fn run_until_shutdown_abandons_the_run_on_shutdown() {
        let (tx, mut rx) = broadcast::channel(4);
        let run = async {
            // A backup stuck on an unreachable region.
            std::future::pending::<()>().await;
            "finished"
        };
        let sender = tokio::spawn(async move {
            tx.send(CoreAction::Reload).expect("send reload");
            tx.send(CoreAction::Shutdown).expect("send shutdown");
            tx
        });
        let outcome =
            tokio::time::timeout(Duration::from_secs(10), run_until_shutdown(run, &mut rx))
                .await
                .expect("a shutdown must not wait for the run");
        assert_eq!(outcome, None);
        drop(sender.await.expect("sender"));
    }

    #[tokio::test]
    async fn run_until_shutdown_completes_the_run_across_a_reload() {
        let (tx, mut rx) = broadcast::channel(4);
        tx.send(CoreAction::Reload).expect("send reload");
        let run = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            "finished"
        };
        assert_eq!(run_until_shutdown(run, &mut rx).await, Some("finished"));

        // A closed channel means the server is gone.
        drop(tx);
        let run = std::future::pending::<()>();
        assert_eq!(run_until_shutdown(run, &mut rx).await, None);
    }

    #[test]
    fn replication_syncs_record_the_regions_they_copied_to() {
        let metrics = BackupMetrics::new(None);
        let outcome = |copied: &[&str], failed: &[&str]| RegionSyncOutcome {
            copied: copied.iter().map(|key| key.to_string()).collect(),
            failed: failed
                .iter()
                .map(|key| (key.to_string(), "denied".to_string()))
                .collect(),
        };
        let synced = vec![
            ("copied".to_string(), Ok(outcome(&["backup-a"], &[]))),
            (
                "partial".to_string(),
                Ok(outcome(&["backup-a"], &["backup-b"])),
            ),
            ("current".to_string(), Ok(outcome(&[], &[]))),
            (
                "unreachable".to_string(),
                Err(S3BackupError::SdkError("timeout".to_string())),
            ),
        ];
        record_region_syncs(&metrics, &synced, Duration::from_secs(42));

        let text = metrics.render();
        let success = |region: &str| {
            format!(
                "kubidm_backup_last_success_timestamp_seconds{{destination=\"s3_region\",region=\"{region}\"}}"
            )
        };
        let failures = |region: &str| {
            format!("kubidm_backup_failures_total{{destination=\"s3_region\",region=\"{region}\"}}")
        };
        assert!(
            text.contains(&format!("{} 42.000", success("copied"))),
            "{text}"
        );
        assert!(text.contains(&format!("{} 0", failures("copied"))));
        assert!(text.contains(&format!("{} 0\n", success("partial"))));
        assert!(text.contains(&format!("{} 1", failures("partial"))));
        assert!(text.contains(&format!("{} 1", failures("unreachable"))));
        // A region that was already current saw no event.
        assert!(!text.contains("region=\"current\""));
    }

    #[test]
    fn wait_until_a_past_time_is_zero() {
        // The old computation wrapped a negative wait to about 1.8e19 seconds, or
        // overflowed at exactly -1s.
        assert_eq!(wait_until(at(10, 0, 0), at(10, 0, 1)), Duration::ZERO);
        assert_eq!(wait_until(at(10, 0, 0), at(12, 0, 0)), Duration::ZERO);
        assert_eq!(wait_until(at(10, 0, 0), at(10, 0, 0)), Duration::ZERO);
    }

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
