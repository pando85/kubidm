//! Backup metrics: when every backup location last received a backup, when its newest
//! artifact last passed the scheduled full verification and when the WAL archive last
//! synchronised, as Prometheus gauges and counters.
//!
//! The timestamps survive a restart, so that an alert on a stale timestamp does not fire
//! because the server restarted:
//!
//! - every timestamp is written to a small state file next to the database
//!   ([`metrics_state_file`]) whenever it changes, and read back when the server starts;
//! - the last success of every destination is also taken, at start up, from the newest
//!   complete backup it holds (by the time in its name), which covers a server that had no
//!   state file yet ([`seed_from_backups`]).
//!
//! The counters start at 0 with every server start, as Prometheus counters do. They are
//! served in the Prometheus text exposition format on `GET /metrics` when
//! `online_backup.metrics_endpoint` is enabled.
//!
//! Every recording takes the current time from its caller, so that the values are
//! testable.

use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::pitr::{BaseLocation, PitrSyncReport};
use super::retention::backup_artifact_time;
use super::verify::newest_local_backup;
use super::{run_blocking, S3ClientWrapper};
use crate::config::{Configuration, OnlineBackup};

/// The `Content-Type` of the Prometheus text exposition format.
pub const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The suffix of the state file of the metrics: `<database file><suffix>`, next to the
/// database.
pub const METRICS_STATE_FILE_SUFFIX: &str = ".backup-metrics.json";

/// Where the server described by `config` keeps the state of its backup metrics: next to
/// its database, named after the database file, so that it is per server even when
/// several servers keep their databases in one directory or share a backup directory.
/// None for a server without a database file.
pub fn metrics_state_file(config: &Configuration) -> Option<PathBuf> {
    let db_path = config.db_path.as_ref()?;
    let mut name = db_path.as_os_str().to_os_string();
    name.push(METRICS_STATE_FILE_SUFFIX);
    Some(PathBuf::from(name))
}

/// Where a backup is stored: the label set of its metrics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupDestination {
    /// The local online backup directory, `online_backup.path`.
    Local,
    /// The `[online_backup.s3]` location.
    S3,
    /// A replication region of `[online_backup.s3]`, by its name.
    S3Region(String),
}

impl BackupDestination {
    /// The Prometheus labels of the destination, without braces.
    fn labels(&self) -> String {
        match self {
            BackupDestination::Local => "destination=\"local\"".to_string(),
            BackupDestination::S3 => "destination=\"s3\"".to_string(),
            BackupDestination::S3Region(name) => format!(
                "destination=\"s3_region\",region=\"{}\"",
                escape_label_value(name)
            ),
        }
    }

    /// The key of the destination in the state file.
    fn state_key(&self) -> String {
        match self {
            BackupDestination::Local => "local".to_string(),
            BackupDestination::S3 => "s3".to_string(),
            BackupDestination::S3Region(name) => format!("s3_region/{name}"),
        }
    }

    /// Whether the newest artifact of the destination is verified by the scheduled full
    /// verification. A region holds a copy of the S3 artifact, which is verified instead.
    fn is_verified(&self) -> bool {
        !matches!(self, BackupDestination::S3Region(_))
    }
}

impl From<&BaseLocation> for BackupDestination {
    fn from(location: &BaseLocation) -> Self {
        match location {
            BaseLocation::Local(_) => BackupDestination::Local,
            BaseLocation::S3(_) => BackupDestination::S3,
        }
    }
}

impl fmt::Display for BackupDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupDestination::Local => write!(f, "local"),
            BackupDestination::S3 => write!(f, "s3"),
            BackupDestination::S3Region(name) => write!(f, "s3 region {name}"),
        }
    }
}

/// The time of the last event and how many events there were since the server started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Events {
    last: Option<Duration>,
    total: u64,
}

impl Events {
    fn record(&mut self, now: Duration) {
        self.last = Some(now);
        self.total = self.total.saturating_add(1);
    }

    /// Take `time` as the last event when it is newer than the one known, without counting
    /// an event: it happened before the server started.
    fn seed(&mut self, time: Option<Duration>) {
        if let Some(time) = time {
            if self.last.is_none_or(|last| last < time) {
                self.last = Some(time);
            }
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DestinationMetrics {
    backups: Events,
    backup_failures: Events,
    verifications: Events,
    verification_failures: Events,
    verification_errors: Events,
}

impl DestinationMetrics {
    fn has_verification_events(&self) -> bool {
        self.verifications.last.is_some()
            || self.verification_failures.last.is_some()
            || self.verification_errors.last.is_some()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PitrMetrics {
    syncs: Events,
    failures: Events,
}

#[derive(Debug, Default)]
struct MetricsState {
    destinations: BTreeMap<BackupDestination, DestinationMetrics>,
    /// Whether the full verification is scheduled, so that its series exist from the start.
    full_verification: bool,
    /// The WAL archive synchronisations, when the archive is enabled.
    pitr: Option<PitrMetrics>,
}

/// The timestamps of one destination in the state file, in milliseconds since the epoch.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredDestination {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_success_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_failure_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_last_success_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_last_failure_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_last_error_ms: Option<u64>,
}

/// The WAL archive timestamps in the state file, in milliseconds since the epoch.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPitr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_success_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_failure_ms: Option<u64>,
}

/// The content of the state file: the timestamps of the metrics, never the counters.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredState {
    #[serde(default)]
    destinations: BTreeMap<String, StoredDestination>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pitr: Option<StoredPitr>,
}

fn to_ms(time: Option<Duration>) -> Option<u64> {
    time.map(|time| u64::try_from(time.as_millis()).unwrap_or(u64::MAX))
}

fn from_ms(ms: Option<u64>) -> Option<Duration> {
    ms.map(Duration::from_millis)
}

/// The backup metrics of one running server. Shared by the online backup, the replication
/// monitor, the scheduled verification, the WAL archive task and the `/metrics` endpoint.
#[derive(Debug, Default)]
pub struct BackupMetrics {
    state: Mutex<MetricsState>,
    /// Where the timestamps are kept across restarts, if anywhere.
    state_file: Option<PathBuf>,
    /// Whether a timestamp changed since the state file was last written.
    dirty: AtomicBool,
    /// Wakes the task that writes the state file.
    changed: Notify,
    /// Serialises the writes of the state file.
    write_lock: tokio::sync::Mutex<()>,
}

impl BackupMetrics {
    /// The metrics of a server running with `online_backup`: every destination it
    /// configures is reported from the start, with 0 until its first known event, so that
    /// an alert on a stale backup also fires when a destination never received one.
    pub fn new(online_backup: Option<&OnlineBackup>) -> Self {
        let mut state = MetricsState::default();
        if let Some(config) = online_backup.filter(|config| config.enabled) {
            for destination in configured_destinations(config) {
                state
                    .destinations
                    .insert(destination, DestinationMetrics::default());
            }
            state.full_verification = config.verify_schedule.is_some();
            if config.wal_archive.as_ref().is_some_and(|wal| wal.enabled) {
                state.pitr = Some(PitrMetrics::default());
            }
        }
        Self {
            state: Mutex::new(state),
            ..Self::default()
        }
    }

    /// Keep the timestamps in the state file at `path` across restarts.
    pub fn with_state_file(mut self, path: Option<PathBuf>) -> Self {
        self.state_file = path;
        self
    }

    fn with_state<T>(&self, work: impl FnOnce(&mut MetricsState) -> T) -> T {
        // The state is plain data that every update leaves consistent, so a panic while
        // the lock was held can not have left it half written.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        work(&mut state)
    }

    /// Change the state and have the state file written.
    fn update(&self, work: impl FnOnce(&mut MetricsState)) {
        self.with_state(work);
        self.dirty.store(true, Ordering::Release);
        self.changed.notify_one();
    }

    fn with_destination(
        &self,
        destination: &BackupDestination,
        work: impl FnOnce(&mut DestinationMetrics),
    ) {
        self.update(|state| work(state.destinations.entry(destination.clone()).or_default()))
    }

    /// A backup was stored in `destination` at `now`.
    pub fn backup_succeeded(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| metrics.backups.record(now));
    }

    /// A backup could not be stored in `destination` at `now`.
    pub fn backup_failed(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| metrics.backup_failures.record(now));
    }

    /// The newest artifact of `destination` passed the full verification at `now`.
    pub fn verification_succeeded(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| metrics.verifications.record(now));
    }

    /// The newest artifact of `destination` failed the full verification at `now`: it can
    /// not be restored.
    pub fn verification_failed(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| {
            metrics.verification_failures.record(now)
        });
    }

    /// The full verification of `destination` could not run at `now` (its backups could
    /// not be listed or read, or the scratch space was unusable). It says nothing about the
    /// artifact.
    pub fn verification_errored(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| {
            metrics.verification_errors.record(now)
        });
    }

    /// The WAL archive synchronised at `now`.
    pub fn pitr_sync_succeeded(&self, now: Duration) {
        self.update(|state| state.pitr.get_or_insert_default().syncs.record(now));
    }

    /// A WAL archive synchronisation failed at `now`.
    pub fn pitr_sync_failed(&self, now: Duration) {
        self.update(|state| state.pitr.get_or_insert_default().failures.record(now));
    }

    /// Record the outcome of a WAL archive synchronisation that ended at `now`. A
    /// synchronisation that could not write its closed segments, or could not mirror the
    /// archive to every replication region, failed: part of the archive is not where it
    /// is configured to be.
    pub fn record_pitr_sync<E>(&self, result: &Result<PitrSyncReport, E>, now: Duration) {
        match result {
            Ok(report) if !report.flush_failed && report.region_errors == 0 => {
                self.pitr_sync_succeeded(now)
            }
            _ => self.pitr_sync_failed(now),
        }
    }

    /// Take `time` as the last success of `destination` when it is newer than the one
    /// known: the time of the newest backup found in it at start up. Counts no event.
    pub fn seed_last_success(&self, destination: &BackupDestination, time: Duration) {
        self.with_state(|state| {
            if let Some(metrics) = state.destinations.get_mut(destination) {
                metrics.backups.seed(Some(time));
            }
        });
    }

    /// The timestamps to keep across restarts.
    fn stored(&self) -> StoredState {
        self.with_state(|state| StoredState {
            destinations: state
                .destinations
                .iter()
                .map(|(destination, metrics)| {
                    (
                        destination.state_key(),
                        StoredDestination {
                            last_success_ms: to_ms(metrics.backups.last),
                            last_failure_ms: to_ms(metrics.backup_failures.last),
                            verification_last_success_ms: to_ms(metrics.verifications.last),
                            verification_last_failure_ms: to_ms(metrics.verification_failures.last),
                            verification_last_error_ms: to_ms(metrics.verification_errors.last),
                        },
                    )
                })
                .collect(),
            pitr: state.pitr.map(|pitr| StoredPitr {
                last_success_ms: to_ms(pitr.syncs.last),
                last_failure_ms: to_ms(pitr.failures.last),
            }),
        })
    }

    /// Take the timestamps of `stored` that are newer than the ones known, for the
    /// destinations the configuration still names.
    fn restore(&self, stored: &StoredState) {
        self.with_state(|state| {
            for (destination, metrics) in state.destinations.iter_mut() {
                let Some(stored) = stored.destinations.get(&destination.state_key()) else {
                    continue;
                };
                metrics.backups.seed(from_ms(stored.last_success_ms));
                metrics
                    .backup_failures
                    .seed(from_ms(stored.last_failure_ms));
                metrics
                    .verifications
                    .seed(from_ms(stored.verification_last_success_ms));
                metrics
                    .verification_failures
                    .seed(from_ms(stored.verification_last_failure_ms));
                metrics
                    .verification_errors
                    .seed(from_ms(stored.verification_last_error_ms));
            }
            if let (Some(pitr), Some(stored)) = (state.pitr.as_mut(), stored.pitr.as_ref()) {
                pitr.syncs.seed(from_ms(stored.last_success_ms));
                pitr.failures.seed(from_ms(stored.last_failure_ms));
            }
        });
    }

    /// Read the timestamps of the previous run of the server from the state file. A
    /// missing file is a first start; a file that can not be read or parsed is logged and
    /// ignored, it only costs the timestamps of the previous run.
    pub async fn load_state_file(&self) {
        let Some(path) = self.state_file.clone() else {
            return;
        };
        let read_path = path.clone();
        let content = match run_blocking(move || std::fs::read(read_path)).await {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(%err, "Unable to read the backup metrics state {}", path.display());
                return;
            }
        };
        match serde_json::from_slice::<StoredState>(&content) {
            Ok(stored) => self.restore(&stored),
            Err(err) => warn!(
                %err,
                "Ignoring the backup metrics state {}: it can not be parsed",
                path.display()
            ),
        }
    }

    /// Write the timestamps to the state file when they changed since it was last written.
    /// The file is replaced atomically, so that a crash leaves the previous version whole.
    pub async fn save_state_file(&self) {
        let Some(path) = self.state_file.clone() else {
            return;
        };
        let _writing = self.write_lock.lock().await;
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let content = match serde_json::to_vec_pretty(&self.stored()) {
            Ok(content) => content,
            Err(err) => {
                error!(%err, "Unable to serialise the backup metrics state");
                return;
            }
        };
        let write_path = path.clone();
        if let Err(err) = run_blocking(move || write_atomically(&write_path, &content)).await {
            // Kept dirty: the next change, or the shutdown, tries again.
            self.dirty.store(true, Ordering::Release);
            warn!(
                %err,
                "Unable to write the backup metrics state {}; after a restart the metrics \
                 start from the backups found instead",
                path.display()
            );
        }
    }

    /// Wait until a timestamp changed since the state file was last written.
    pub async fn changed(&self) {
        self.changed.notified().await
    }

    /// The metrics in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        self.with_state(|state| render(state))
    }
}

/// Write `content` to `path` through a temporary file in the same directory, renamed over
/// it once it is on disk.
fn write_atomically(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".kubidm-backup-metrics")
        .tempfile_in(dir)?;
    std::io::Write::write_all(&mut file, content)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    Ok(())
}

/// Every destination `config` stores backups in: the local directory, the S3 prefix and
/// its enabled replication regions.
fn configured_destinations(config: &OnlineBackup) -> Vec<BackupDestination> {
    let mut destinations = Vec::new();
    if config.path.is_some() {
        destinations.push(BackupDestination::Local);
    }
    if let Some(s3) = &config.s3 {
        destinations.push(BackupDestination::S3);
        destinations.extend(
            s3.replication
                .iter()
                .filter(|replication| replication.enabled)
                .flat_map(|replication| replication.regions.iter())
                .map(|region| BackupDestination::S3Region(region.name().to_string())),
        );
    }
    destinations
}

/// The time in the name of the backup `name`, None when it is not a backup name or the
/// time is before the epoch.
fn backup_name_time(name: &str) -> Option<Duration> {
    let millis = backup_artifact_time(name)?.timestamp_millis();
    u64::try_from(millis).ok().map(Duration::from_millis)
}

/// Take the last success of every destination of `config` from the newest complete
/// backup it holds, by the time in its name: the newest artifact of the local directory,
/// and the newest backup with a metadata sidecar of the S3 prefix and of every replication
/// region. A destination that can not be listed keeps what it had, with a warning.
pub async fn seed_from_backups(metrics: &BackupMetrics, config: &OnlineBackup) {
    if let Some(dir) = config.path.clone() {
        let listed_dir = dir.clone();
        match run_blocking(move || newest_local_backup(&listed_dir)).await {
            Ok(Some(name)) => {
                if let Some(time) = backup_name_time(&name) {
                    metrics.seed_last_success(&BackupDestination::Local, time);
                }
            }
            Ok(None) => {}
            Err(err) => warn!(
                %err,
                "Backup metrics: unable to list the backups of {}",
                dir.display()
            ),
        }
    }

    let Some(s3) = &config.s3 else {
        return;
    };
    let mut locations = vec![(BackupDestination::S3, s3.clone())];
    for region in s3
        .replication
        .iter()
        .filter(|replication| replication.enabled)
        .flat_map(|replication| replication.regions.iter())
    {
        locations.push((
            BackupDestination::S3Region(region.name().to_string()),
            region.to_s3_config(),
        ));
    }
    for (destination, location) in locations {
        let newest = match S3ClientWrapper::new(location).await {
            Ok(client) => client.list_backup_artifacts().await,
            Err(err) => Err(err),
        };
        match newest {
            Ok(keys) => {
                if let Some(time) = keys
                    .last()
                    .and_then(|key| backup_name_time(key.rsplit('/').next().unwrap_or(key)))
                {
                    metrics.seed_last_success(&destination, time);
                }
            }
            Err(err) => warn!(
                %err,
                "Backup metrics: unable to list the {destination} backups; its last success \
                 is the one recorded before the restart"
            ),
        }
    }
}

/// One metric family: its name, type, help and samples, each sample being its labels and
/// its value.
struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    samples: Vec<(String, String)>,
}

impl Family {
    fn gauge(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            kind: "gauge",
            help,
            samples: Vec::new(),
        }
    }

    fn counter(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            kind: "counter",
            help,
            samples: Vec::new(),
        }
    }

    fn timestamp(&mut self, labels: String, events: &Events) {
        self.samples.push((labels, timestamp_value(events.last)));
    }

    fn total(&mut self, labels: String, events: &Events) {
        self.samples.push((labels, events.total.to_string()));
    }

    fn write_to(&self, out: &mut String) {
        if self.samples.is_empty() {
            return;
        }
        // Writing to a String never fails.
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} {}", self.name, self.kind);
        for (labels, value) in &self.samples {
            if labels.is_empty() {
                let _ = writeln!(out, "{} {value}", self.name);
            } else {
                let _ = writeln!(out, "{}{{{labels}}} {value}", self.name);
            }
        }
    }
}

/// A Unix time in seconds, 0 for never.
fn timestamp_value(time: Option<Duration>) -> String {
    match time {
        Some(time) => format!("{}.{:03}", time.as_secs(), time.subsec_millis()),
        None => "0".to_string(),
    }
}

/// Escape a label value as the text exposition format requires.
fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            c => escaped.push(c),
        }
    }
    escaped
}

// Every family is named `kubidm_backup_[<subject>_]last_<event>_timestamp_seconds` or
// `kubidm_backup_[<subject>_]<event>s_total`, the subject being the backup itself, its
// verification or the WAL archive synchronisation.
fn render(state: &MetricsState) -> String {
    let mut last_success = Family::gauge(
        "kubidm_backup_last_success_timestamp_seconds",
        "Unix time of the newest backup stored in the destination, 0 when none is known.",
    );
    let mut last_failure = Family::gauge(
        "kubidm_backup_last_failure_timestamp_seconds",
        "Unix time of the last backup that could not be stored in the destination, 0 when none is known.",
    );
    let mut failures = Family::counter(
        "kubidm_backup_failures_total",
        "Backups that could not be stored in the destination since the server started.",
    );
    let mut verification_last_success = Family::gauge(
        "kubidm_backup_verification_last_success_timestamp_seconds",
        "Unix time the newest artifact of the destination last passed the full verification, 0 when none is known.",
    );
    let mut verification_last_failure = Family::gauge(
        "kubidm_backup_verification_last_failure_timestamp_seconds",
        "Unix time the newest artifact of the destination last failed the full verification (it can not be restored), 0 when none is known.",
    );
    let mut verification_failures = Family::counter(
        "kubidm_backup_verification_failures_total",
        "Full verifications the newest artifact of the destination failed since the server started.",
    );
    let mut verification_last_error = Family::gauge(
        "kubidm_backup_verification_last_error_timestamp_seconds",
        "Unix time the full verification of the destination last could not run (listing, download, I/O or scratch space), 0 when none is known.",
    );
    let mut verification_errors = Family::counter(
        "kubidm_backup_verification_errors_total",
        "Full verifications of the destination that could not run since the server started.",
    );

    for (destination, metrics) in &state.destinations {
        let labels = destination.labels();
        last_success.timestamp(labels.clone(), &metrics.backups);
        last_failure.timestamp(labels.clone(), &metrics.backup_failures);
        failures.total(labels.clone(), &metrics.backup_failures);

        // The verification series exist when it is scheduled, or once it ran.
        if destination.is_verified()
            && (state.full_verification || metrics.has_verification_events())
        {
            verification_last_success.timestamp(labels.clone(), &metrics.verifications);
            verification_last_failure.timestamp(labels.clone(), &metrics.verification_failures);
            verification_failures.total(labels.clone(), &metrics.verification_failures);
            verification_last_error.timestamp(labels.clone(), &metrics.verification_errors);
            verification_errors.total(labels, &metrics.verification_errors);
        }
    }

    let mut pitr_last_success = Family::gauge(
        "kubidm_backup_pitr_sync_last_success_timestamp_seconds",
        "Unix time of the last successful WAL archive synchronisation, 0 when none is known.",
    );
    let mut pitr_last_failure = Family::gauge(
        "kubidm_backup_pitr_sync_last_failure_timestamp_seconds",
        "Unix time of the last failed WAL archive synchronisation, including one that could not reach a replication region, 0 when none is known.",
    );
    let mut pitr_failures = Family::counter(
        "kubidm_backup_pitr_sync_failures_total",
        "Failed WAL archive synchronisations since the server started.",
    );
    if let Some(pitr) = &state.pitr {
        pitr_last_success.timestamp(String::new(), &pitr.syncs);
        pitr_last_failure.timestamp(String::new(), &pitr.failures);
        pitr_failures.total(String::new(), &pitr.failures);
    }

    let mut out = String::new();
    for family in [
        last_success,
        last_failure,
        failures,
        verification_last_success,
        verification_last_failure,
        verification_failures,
        verification_last_error,
        verification_errors,
        pitr_last_success,
        pitr_last_failure,
        pitr_failures,
    ] {
        family.write_to(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kubidm_proto::backup::{
        ReplicationConfig, ReplicationRegionConfig, S3Config, WalArchiveConfig,
    };

    use super::*;

    fn secs(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    /// The value of the sample `name{labels}` of `text`, None when it is missing.
    fn sample(text: &str, name: &str, labels: &str) -> Option<String> {
        let series = if labels.is_empty() {
            name.to_string()
        } else {
            format!("{name}{{{labels}}}")
        };
        text.lines()
            .filter_map(|line| line.strip_prefix(&series))
            .find_map(|rest| rest.strip_prefix(' '))
            .map(str::to_string)
    }

    fn region(name: &str) -> ReplicationRegionConfig {
        ReplicationRegionConfig {
            name: Some(name.to_string()),
            region: "eu-west-1".to_string(),
            endpoint: None,
            bucket: format!("bucket-{name}"),
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        }
    }

    fn full_config() -> OnlineBackup {
        OnlineBackup {
            path: Some(PathBuf::from("/backups")),
            s3: Some(S3Config {
                bucket: "primary".to_string(),
                region: None,
                endpoint: None,
                path_prefix: None,
                credentials: None,
                server_side_encryption: None,
                storage_class: "STANDARD".to_string(),
                replication: Some(ReplicationConfig {
                    enabled: true,
                    regions: vec![region("eu"), region("weird\"name")],
                    ..ReplicationConfig::default()
                }),
            }),
            wal_archive: Some(WalArchiveConfig {
                enabled: true,
                ..WalArchiveConfig::default()
            }),
            verify_schedule: Some("@daily".to_string()),
            ..OnlineBackup::default()
        }
    }

    const LAST_SUCCESS: &str = "kubidm_backup_last_success_timestamp_seconds";
    const VERIFIED: &str = "kubidm_backup_verification_last_success_timestamp_seconds";
    const VERIFICATION_FAILURES: &str = "kubidm_backup_verification_failures_total";
    const VERIFICATION_ERRORS: &str = "kubidm_backup_verification_errors_total";
    const PITR_LAST_SUCCESS: &str = "kubidm_backup_pitr_sync_last_success_timestamp_seconds";
    const PITR_FAILURES: &str = "kubidm_backup_pitr_sync_failures_total";

    #[test]
    fn configured_destinations_are_reported_from_the_start() {
        let text = BackupMetrics::new(Some(&full_config())).render();

        for labels in [
            "destination=\"local\"",
            "destination=\"s3\"",
            "destination=\"s3_region\",region=\"eu\"",
            "destination=\"s3_region\",region=\"weird\\\"name\"",
        ] {
            assert_eq!(
                sample(&text, LAST_SUCCESS, labels).as_deref(),
                Some("0"),
                "{labels} in\n{text}"
            );
            assert_eq!(
                sample(&text, "kubidm_backup_failures_total", labels).as_deref(),
                Some("0")
            );
        }
        for labels in ["destination=\"local\"", "destination=\"s3\""] {
            for name in [VERIFIED, VERIFICATION_FAILURES, VERIFICATION_ERRORS] {
                assert_eq!(
                    sample(&text, name, labels).as_deref(),
                    Some("0"),
                    "{name}{{{labels}}} in\n{text}"
                );
            }
        }
        // A region is never verified on its own.
        assert!(!text.contains(&format!("{VERIFIED}{{destination=\"s3_region\"")));
        assert_eq!(sample(&text, PITR_LAST_SUCCESS, "").as_deref(), Some("0"));
        assert!(text.contains("# TYPE kubidm_backup_failures_total counter"));
        assert!(text.contains("# TYPE kubidm_backup_last_success_timestamp_seconds gauge"));
    }

    #[test]
    fn nothing_is_reported_without_an_enabled_online_backup() {
        assert_eq!(BackupMetrics::new(None).render(), "");
        let disabled = OnlineBackup {
            enabled: false,
            ..full_config()
        };
        assert_eq!(BackupMetrics::new(Some(&disabled)).render(), "");
    }

    #[test]
    fn the_verification_is_only_reported_when_scheduled_or_run() {
        let config = OnlineBackup {
            verify_schedule: None,
            ..full_config()
        };
        let metrics = BackupMetrics::new(Some(&config));
        let text = metrics.render();
        assert!(!text.contains("kubidm_backup_verification"), "{text}");

        // A run triggered without a schedule is reported all the same.
        metrics.verification_failed(&BackupDestination::Local, secs(5));
        let text = metrics.render();
        let local = "destination=\"local\"";
        assert_eq!(
            sample(&text, VERIFICATION_FAILURES, local).as_deref(),
            Some("1")
        );
        assert_eq!(sample(&text, VERIFIED, local).as_deref(), Some("0"));
        assert_eq!(sample(&text, VERIFIED, "destination=\"s3\""), None);
    }

    #[test]
    fn events_update_their_timestamps_and_counters() {
        let metrics = BackupMetrics::new(Some(&full_config()));
        let local = BackupDestination::Local;
        let eu = BackupDestination::S3Region("eu".to_string());

        metrics.backup_succeeded(&local, Duration::from_millis(1_700_000_000_250));
        metrics.backup_failed(&eu, secs(1_700_000_100));
        metrics.backup_failed(&eu, secs(1_700_000_200));
        metrics.backup_succeeded(&eu, secs(1_700_000_300));
        metrics.verification_succeeded(&local, secs(1_700_000_400));
        metrics.verification_errored(&local, secs(1_700_000_450));
        metrics.pitr_sync_succeeded(secs(1_700_000_500));
        metrics.pitr_sync_failed(secs(1_700_000_600));

        let text = metrics.render();
        let value = |name: &str, labels: &str| sample(&text, name, labels);
        let local_labels = "destination=\"local\"";
        assert_eq!(
            value(LAST_SUCCESS, local_labels).as_deref(),
            Some("1700000000.250")
        );
        assert_eq!(
            value(VERIFIED, local_labels).as_deref(),
            Some("1700000400.000")
        );
        // Could not run: an error, never a failure of the artifact.
        assert_eq!(
            value(VERIFICATION_ERRORS, local_labels).as_deref(),
            Some("1")
        );
        assert_eq!(
            value(
                "kubidm_backup_verification_last_error_timestamp_seconds",
                local_labels
            )
            .as_deref(),
            Some("1700000450.000")
        );
        assert_eq!(
            value(VERIFICATION_FAILURES, local_labels).as_deref(),
            Some("0")
        );
        let eu_labels = "destination=\"s3_region\",region=\"eu\"";
        assert_eq!(
            value("kubidm_backup_failures_total", eu_labels).as_deref(),
            Some("2")
        );
        assert_eq!(
            value("kubidm_backup_last_failure_timestamp_seconds", eu_labels).as_deref(),
            Some("1700000200.000")
        );
        assert_eq!(
            value(LAST_SUCCESS, eu_labels).as_deref(),
            Some("1700000300.000")
        );
        assert_eq!(
            value(PITR_LAST_SUCCESS, "").as_deref(),
            Some("1700000500.000")
        );
        assert_eq!(value(PITR_FAILURES, "").as_deref(), Some("1"));
        // The S3 primary saw nothing.
        assert_eq!(
            value(LAST_SUCCESS, "destination=\"s3\"").as_deref(),
            Some("0")
        );
    }

    #[test]
    fn a_wal_archive_sync_that_misses_a_region_or_a_flush_is_a_failure() {
        let metrics = BackupMetrics::new(Some(&full_config()));
        let ok: Result<PitrSyncReport, ()> = Ok(PitrSyncReport::default());
        metrics.record_pitr_sync(&ok, secs(10));
        let region_errors: Result<PitrSyncReport, ()> = Ok(PitrSyncReport {
            region_errors: 1,
            ..PitrSyncReport::default()
        });
        metrics.record_pitr_sync(&region_errors, secs(20));
        let flush_failed: Result<PitrSyncReport, ()> = Ok(PitrSyncReport {
            flush_failed: true,
            ..PitrSyncReport::default()
        });
        metrics.record_pitr_sync(&flush_failed, secs(30));
        metrics.record_pitr_sync(&Err::<PitrSyncReport, ()>(()), secs(40));

        let text = metrics.render();
        assert_eq!(
            sample(&text, PITR_LAST_SUCCESS, "").as_deref(),
            Some("10.000")
        );
        assert_eq!(sample(&text, PITR_FAILURES, "").as_deref(), Some("3"));
        assert_eq!(
            sample(
                &text,
                "kubidm_backup_pitr_sync_last_failure_timestamp_seconds",
                ""
            )
            .as_deref(),
            Some("40.000")
        );
    }

    #[test]
    fn a_destination_that_was_not_configured_is_added_by_its_first_event() {
        // The test hooks back up to locations the configuration does not name.
        let metrics = BackupMetrics::new(None);
        metrics.backup_succeeded(&BackupDestination::S3, secs(10));
        let text = metrics.render();
        assert_eq!(
            sample(&text, LAST_SUCCESS, "destination=\"s3\"").as_deref(),
            Some("10.000")
        );
        assert!(!text.contains("pitr"));
    }

    #[test]
    fn every_family_has_help_and_type_before_its_samples() {
        let metrics = BackupMetrics::new(Some(&full_config()));
        let text = metrics.render();
        let mut declared = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                declared.push(rest.split(' ').next().unwrap_or_default().to_string());
            } else if !line.starts_with('#') {
                let name = line
                    .split(['{', ' '])
                    .next()
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(declared.last(), Some(&name), "{line}");
            }
        }
        assert!(text.ends_with('\n'));
        // One naming scheme: counters end in _total, gauges are timestamps.
        for line in text.lines().filter(|line| line.starts_with("# TYPE ")) {
            assert!(
                line.ends_with("_total counter") || line.ends_with("_timestamp_seconds gauge"),
                "{line}"
            );
        }
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label_value("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        assert_eq!(escape_label_value("eu-west-1"), "eu-west-1");
    }

    #[tokio::test]
    async fn the_timestamps_survive_a_restart_and_the_counters_do_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(format!("kubidm.db{METRICS_STATE_FILE_SUFFIX}"));
        let config = full_config();
        let local = BackupDestination::Local;
        let eu = BackupDestination::S3Region("eu".to_string());

        let before = BackupMetrics::new(Some(&config)).with_state_file(Some(path.clone()));
        // Nothing changed: nothing is written.
        before.save_state_file().await;
        assert!(!path.exists());

        before.backup_succeeded(&local, secs(100));
        before.backup_failed(&eu, secs(110));
        before.verification_succeeded(&local, secs(120));
        before.verification_failed(&BackupDestination::S3, secs(130));
        before.verification_errored(&local, secs(140));
        before.pitr_sync_succeeded(secs(150));
        before.save_state_file().await;
        let expected = before.render();

        let after = BackupMetrics::new(Some(&config)).with_state_file(Some(path.clone()));
        after.load_state_file().await;
        let text = after.render();
        for (name, labels) in [
            (LAST_SUCCESS, "destination=\"local\""),
            (
                "kubidm_backup_last_failure_timestamp_seconds",
                "destination=\"s3_region\",region=\"eu\"",
            ),
            (VERIFIED, "destination=\"local\""),
            (
                "kubidm_backup_verification_last_failure_timestamp_seconds",
                "destination=\"s3\"",
            ),
            (
                "kubidm_backup_verification_last_error_timestamp_seconds",
                "destination=\"local\"",
            ),
            (PITR_LAST_SUCCESS, ""),
        ] {
            assert_eq!(
                sample(&text, name, labels),
                sample(&expected, name, labels),
                "{name}{{{labels}}} in\n{text}"
            );
            assert_ne!(sample(&text, name, labels).as_deref(), Some("0"));
        }
        // Counters restart at 0, as Prometheus expects of a restarted process.
        assert_eq!(
            sample(&text, VERIFICATION_FAILURES, "destination=\"s3\"").as_deref(),
            Some("0")
        );

        // A newer event wins over the stored one, an older seed never moves it back.
        after.backup_succeeded(&local, secs(200));
        after.seed_last_success(&local, secs(150));
        assert_eq!(
            sample(&after.render(), LAST_SUCCESS, "destination=\"local\"").as_deref(),
            Some("200.000")
        );

        // A destination the configuration no longer names is dropped.
        let only_local = OnlineBackup {
            s3: None,
            ..config.clone()
        };
        let reconfigured = BackupMetrics::new(Some(&only_local)).with_state_file(Some(path));
        reconfigured.load_state_file().await;
        assert!(!reconfigured.render().contains("destination=\"s3"));
    }

    #[tokio::test]
    async fn a_damaged_state_file_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(format!("kubidm.db{METRICS_STATE_FILE_SUFFIX}"));
        std::fs::write(&path, b"{ not json").expect("write");
        let metrics = BackupMetrics::new(Some(&full_config())).with_state_file(Some(path));
        metrics.load_state_file().await;
        assert_eq!(
            sample(&metrics.render(), LAST_SUCCESS, "destination=\"local\"").as_deref(),
            Some("0")
        );
    }

    #[tokio::test]
    async fn the_last_success_is_seeded_from_the_newest_local_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in [
            "backup-2026-01-01T10:00:00Z.json.gz",
            "backup-2026-01-02T10:00:00.5Z.json.gz.enc",
            // Never a backup.
            ".backup-2027-01-01T00:00:00Z.json.gz.partial",
        ] {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        let config = OnlineBackup {
            path: Some(dir.path().to_path_buf()),
            ..OnlineBackup::default()
        };
        let metrics = BackupMetrics::new(Some(&config));
        seed_from_backups(&metrics, &config).await;
        let expected =
            backup_name_time("backup-2026-01-02T10:00:00.5Z.json.gz.enc").expect("a backup name");
        assert_eq!(
            sample(&metrics.render(), LAST_SUCCESS, "destination=\"local\""),
            Some(timestamp_value(Some(expected)))
        );
        // Seeding counts no backup.
        assert_eq!(
            sample(
                &metrics.render(),
                "kubidm_backup_failures_total",
                "destination=\"local\""
            )
            .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn the_state_file_lives_next_to_the_database() {
        let mut config = Configuration::new_for_test();
        config.db_path = None;
        assert_eq!(metrics_state_file(&config), None);
        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        assert_eq!(
            metrics_state_file(&config),
            Some(PathBuf::from(
                "/var/lib/kubidm/kubidm.db.backup-metrics.json"
            ))
        );
        config.db_path = Some(PathBuf::from("kubidm.db"));
        assert_eq!(
            metrics_state_file(&config),
            Some(PathBuf::from("kubidm.db.backup-metrics.json"))
        );
    }

    /// Two servers whose databases share a directory (a test or staging pair on one host)
    /// keep their metrics apart: a shared state file would report the backups of one as
    /// those of the other after a restart, which hides a stale backup.
    #[tokio::test]
    async fn servers_whose_databases_share_a_directory_keep_their_own_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_file = |db: &str| {
            let mut config = Configuration::new_for_test();
            config.db_path = Some(dir.path().join(db));
            metrics_state_file(&config).expect("state file")
        };
        let (a, b) = (state_file("a.db"), state_file("b.db"));
        assert_ne!(a, b);

        let config = full_config();
        let local = BackupDestination::Local;
        let server_a = BackupMetrics::new(Some(&config)).with_state_file(Some(a.clone()));
        server_a.backup_succeeded(&local, Duration::from_secs(1_700_000_000));
        server_a.save_state_file().await;
        assert!(a.is_file());

        // The restarted server b never saw a backup: it reports none.
        let server_b = BackupMetrics::new(Some(&config)).with_state_file(Some(b));
        server_b.load_state_file().await;
        assert_eq!(
            sample(&server_b.render(), LAST_SUCCESS, "destination=\"local\"").as_deref(),
            Some("0")
        );
    }
}
