//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use std::{fs, path::Path, str::FromStr, sync::Arc};

use chrono::Utc;
use cron::Schedule;

use tokio::{
    sync::broadcast,
    time::{interval, sleep, Duration, MissedTickBehavior},
};

use crate::backup::pitr::{BaseLocation, PitrArchive};
use crate::backup::S3ClientWrapper;
use crate::config::OnlineBackup;
use crate::CoreAction;

use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
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

    // Allow this because result is the only way to map and ? to bubble up, but we aren't
    // returning an op-error here because this is in early start up.
    #[allow(clippy::result_unit_err)]
    pub fn start_online_backup(
        server: &'static QueryServerReadV1,
        online_backup_config: &OnlineBackup,
        pitr_archive: Option<Arc<PitrArchive>>,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> Result<tokio::task::JoinHandle<()>, ()> {
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
                        // Perform local backup if path is configured
                        if let Some(ref path) = outpath {
                            match server
                                .handle_online_backup(
                                    OnlineBackupEvent::new(),
                                    path,
                                    versions,
                                    backup_compression,
                                    None,
                                )
                                .await
                            {
                                Ok(outcome) => {
                                    // Index the backup as a base for point-in-time recovery.
                                    if let Some(archive) = &pitr_archive {
                                        archive
                                            .register_base_backup_logged(
                                                &BaseLocation::Local(path.clone()),
                                                &outcome.key,
                                                &outcome.timestamp,
                                                &outcome.report,
                                            )
                                            .await;
                                    }
                                }
                                Err(e) => error!(?e, "An online backup error occurred."),
                            }
                        }

                        // Perform S3 backup if configured
                        if let Some(s3_cfg) = &s3_config {
                            match S3ClientWrapper::new(s3_cfg.clone()).await {
                                Ok(s3_client) => {
                                    match server
                                        .handle_online_backup(
                                            OnlineBackupEvent::new(),
                                            &std::path::PathBuf::from("s3://backup"),
                                            versions,
                                            backup_compression,
                                            Some(s3_client),
                                        )
                                        .await
                                    {
                                        Ok(outcome) => {
                                            if let Some(archive) = &pitr_archive {
                                                archive
                                                    .register_base_backup_logged(
                                                        &BaseLocation::S3(s3_cfg.clone()),
                                                        &outcome.key,
                                                        &outcome.timestamp,
                                                        &outcome.report,
                                                    )
                                                    .await;
                                            }
                                        }
                                        Err(e) => error!(?e, "An S3 backup error occurred."),
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
            info!("Stopped {}", super::TaskName::BackupActor);
        });

        Ok(handle)
    }
}
