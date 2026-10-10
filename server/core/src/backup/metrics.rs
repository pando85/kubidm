//! Backup metrics: when every backup location last received a backup, when its newest
//! artifact was last verified and when the WAL archive last synchronised, as Prometheus
//! gauges and counters.
//!
//! The values live in memory and start empty at every server start: a destination that
//! has not had a backup, a verification or a failure since then reports 0 for the
//! timestamp and the counter. They are served in the Prometheus text exposition format on
//! `GET /metrics` when `online_backup.metrics_endpoint` is enabled.
//!
//! Every recording takes the current time from its caller, so that the values are
//! testable.

use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::sync::Mutex;
use std::time::Duration;

use super::pitr::BaseLocation;
use crate::config::OnlineBackup;

/// The `Content-Type` of the Prometheus text exposition format.
pub const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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

    /// Whether the artifacts of the destination are verified by the online backup. A
    /// region holds a copy of the S3 artifact, which was verified before it was uploaded.
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

/// How deeply an artifact was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationLevel {
    /// The structural check every online backup runs on its artifact before it is stored.
    Structural,
    /// The restore of the artifact into a scratch database, its boot and the consistency
    /// checks, as `kubidmd database verify-backup` runs them; scheduled with
    /// `online_backup.verify_schedule`.
    Full,
}

impl VerificationLevel {
    fn label(self) -> &'static str {
        match self {
            VerificationLevel::Structural => "structural",
            VerificationLevel::Full => "full",
        }
    }
}

/// The time of the last event and how many events there were.
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
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DestinationMetrics {
    successes: Events,
    failures: Events,
    verified: BTreeMap<VerificationLevel, Events>,
    verification_failures: BTreeMap<VerificationLevel, Events>,
}

#[derive(Debug, Default)]
struct MetricsState {
    destinations: BTreeMap<BackupDestination, DestinationMetrics>,
    /// Whether the full verification is scheduled, so that its series exist from the start.
    full_verification: bool,
    /// The WAL archive synchronisations, when the archive is enabled.
    pitr: Option<PitrMetrics>,
}

#[derive(Debug, Default, Clone, Copy)]
struct PitrMetrics {
    syncs: Events,
    failures: Events,
}

/// The backup metrics of one running server. Shared by the online backup, the replication
/// monitor, the scheduled verification, the WAL archive task and the `/metrics` endpoint.
#[derive(Debug, Default)]
pub struct BackupMetrics {
    state: Mutex<MetricsState>,
}

impl BackupMetrics {
    /// The metrics of a server running with `online_backup`: every destination it
    /// configures is reported from the start, with 0 until its first event, so that an
    /// alert on a stale backup also fires when a destination never received one.
    pub fn new(online_backup: Option<&OnlineBackup>) -> Self {
        let mut state = MetricsState::default();
        if let Some(config) = online_backup.filter(|config| config.enabled) {
            if config.path.is_some() {
                state
                    .destinations
                    .insert(BackupDestination::Local, DestinationMetrics::default());
            }
            if let Some(s3) = &config.s3 {
                state
                    .destinations
                    .insert(BackupDestination::S3, DestinationMetrics::default());
                for region in s3
                    .replication
                    .iter()
                    .filter(|replication| replication.enabled)
                    .flat_map(|replication| replication.regions.iter())
                {
                    state.destinations.insert(
                        BackupDestination::S3Region(region.name().to_string()),
                        DestinationMetrics::default(),
                    );
                }
            }
            state.full_verification = config.verify_schedule.is_some();
            if config.wal_archive.as_ref().is_some_and(|wal| wal.enabled) {
                state.pitr = Some(PitrMetrics::default());
            }
        }
        Self {
            state: Mutex::new(state),
        }
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

    fn with_destination(
        &self,
        destination: &BackupDestination,
        work: impl FnOnce(&mut DestinationMetrics),
    ) {
        self.with_state(|state| work(state.destinations.entry(destination.clone()).or_default()))
    }

    /// A backup was stored in `destination` at `now`.
    pub fn backup_succeeded(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| metrics.successes.record(now));
    }

    /// A backup could not be stored in `destination` at `now`.
    pub fn backup_failed(&self, destination: &BackupDestination, now: Duration) {
        self.with_destination(destination, |metrics| metrics.failures.record(now));
    }

    /// The newest artifact of `destination` passed a verification at `level` at `now`.
    pub fn verification_succeeded(
        &self,
        destination: &BackupDestination,
        level: VerificationLevel,
        now: Duration,
    ) {
        self.with_destination(destination, |metrics| {
            metrics.verified.entry(level).or_default().record(now)
        });
    }

    /// The newest artifact of `destination` failed a verification at `level` at `now`.
    pub fn verification_failed(
        &self,
        destination: &BackupDestination,
        level: VerificationLevel,
        now: Duration,
    ) {
        self.with_destination(destination, |metrics| {
            metrics
                .verification_failures
                .entry(level)
                .or_default()
                .record(now)
        });
    }

    /// The WAL archive synchronised at `now`.
    pub fn pitr_sync_succeeded(&self, now: Duration) {
        self.with_state(|state| state.pitr.get_or_insert_default().syncs.record(now));
    }

    /// A WAL archive synchronisation failed at `now`.
    pub fn pitr_sync_failed(&self, now: Duration) {
        self.with_state(|state| state.pitr.get_or_insert_default().failures.record(now));
    }

    /// Record the outcome of a WAL archive synchronisation that ended at `now`.
    pub fn record_pitr_sync<T, E>(&self, result: &Result<T, E>, now: Duration) {
        match result {
            Ok(_) => self.pitr_sync_succeeded(now),
            Err(_) => self.pitr_sync_failed(now),
        }
    }

    /// The metrics in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        self.with_state(|state| render(state))
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

    fn timestamp(&mut self, labels: String, events: Option<&Events>) {
        self.samples.push((
            labels,
            timestamp_value(events.and_then(|events| events.last)),
        ));
    }

    fn total(&mut self, labels: String, events: Option<&Events>) {
        self.samples
            .push((labels, events.map_or(0, |events| events.total).to_string()));
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

fn render(state: &MetricsState) -> String {
    let mut last_success = Family::gauge(
        "kubidm_backup_last_success_timestamp_seconds",
        "Unix time of the last backup stored in the destination, 0 when none was stored since the server started.",
    );
    let mut last_failure = Family::gauge(
        "kubidm_backup_last_failure_timestamp_seconds",
        "Unix time of the last backup that could not be stored in the destination, 0 when none failed since the server started.",
    );
    let mut failures = Family::counter(
        "kubidm_backup_failures_total",
        "Backups that could not be stored in the destination since the server started.",
    );
    let mut last_verified = Family::gauge(
        "kubidm_backup_last_verified_timestamp_seconds",
        "Unix time the newest artifact of the destination last passed a verification of the level, 0 when none passed since the server started.",
    );
    let mut last_verification_failure = Family::gauge(
        "kubidm_backup_verification_last_failure_timestamp_seconds",
        "Unix time the newest artifact of the destination last failed a scheduled verification of the level, 0 when none failed since the server started.",
    );
    let mut verification_failures = Family::counter(
        "kubidm_backup_verification_failures_total",
        "Scheduled verifications of the level the newest artifact of the destination failed since the server started.",
    );

    for (destination, metrics) in &state.destinations {
        let labels = destination.labels();
        last_success.timestamp(labels.clone(), Some(&metrics.successes));
        last_failure.timestamp(labels.clone(), Some(&metrics.failures));
        failures.total(labels.clone(), Some(&metrics.failures));

        if !destination.is_verified() {
            continue;
        }
        for level in [VerificationLevel::Structural, VerificationLevel::Full] {
            let scheduled = level == VerificationLevel::Full;
            let reported = !scheduled
                || state.full_verification
                || metrics.verified.contains_key(&level)
                || metrics.verification_failures.contains_key(&level);
            if !reported {
                continue;
            }
            let labels = format!("{labels},level=\"{}\"", level.label());
            last_verified.timestamp(labels.clone(), metrics.verified.get(&level));
            // A structural verification that fails is a failed backup, counted above.
            if scheduled {
                let failed = metrics.verification_failures.get(&level);
                last_verification_failure.timestamp(labels.clone(), failed);
                verification_failures.total(labels, failed);
            }
        }
    }

    let mut pitr_last_sync = Family::gauge(
        "kubidm_backup_pitr_last_sync_timestamp_seconds",
        "Unix time of the last successful WAL archive synchronisation, 0 when none succeeded since the server started.",
    );
    let mut pitr_last_failure = Family::gauge(
        "kubidm_backup_pitr_last_sync_failure_timestamp_seconds",
        "Unix time of the last failed WAL archive synchronisation, 0 when none failed since the server started.",
    );
    let mut pitr_failures = Family::counter(
        "kubidm_backup_pitr_sync_failures_total",
        "Failed WAL archive synchronisations since the server started.",
    );
    if let Some(pitr) = &state.pitr {
        pitr_last_sync.timestamp(String::new(), Some(&pitr.syncs));
        pitr_last_failure.timestamp(String::new(), Some(&pitr.failures));
        pitr_failures.total(String::new(), Some(&pitr.failures));
    }

    let mut out = String::new();
    for family in [
        last_success,
        last_failure,
        failures,
        last_verified,
        last_verification_failure,
        verification_failures,
        pitr_last_sync,
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
                sample(
                    &text,
                    "kubidm_backup_last_success_timestamp_seconds",
                    labels
                )
                .as_deref(),
                Some("0"),
                "{labels} in\n{text}"
            );
            assert_eq!(
                sample(&text, "kubidm_backup_failures_total", labels).as_deref(),
                Some("0")
            );
        }
        for labels in [
            "destination=\"local\",level=\"structural\"",
            "destination=\"local\",level=\"full\"",
            "destination=\"s3\",level=\"structural\"",
            "destination=\"s3\",level=\"full\"",
        ] {
            assert_eq!(
                sample(
                    &text,
                    "kubidm_backup_last_verified_timestamp_seconds",
                    labels
                )
                .as_deref(),
                Some("0"),
                "{labels} in\n{text}"
            );
        }
        // A region is never verified on its own.
        assert!(!text
            .contains("kubidm_backup_last_verified_timestamp_seconds{destination=\"s3_region\""));
        assert_eq!(
            sample(&text, "kubidm_backup_pitr_last_sync_timestamp_seconds", "").as_deref(),
            Some("0")
        );
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
    fn full_verification_is_only_reported_when_scheduled_or_run() {
        let config = OnlineBackup {
            verify_schedule: None,
            ..full_config()
        };
        let metrics = BackupMetrics::new(Some(&config));
        let text = metrics.render();
        assert!(!text.contains("level=\"full\""), "{text}");
        assert!(!text.contains("kubidm_backup_verification_failures_total"));

        // A run triggered without a schedule is reported all the same.
        metrics.verification_failed(&BackupDestination::Local, VerificationLevel::Full, secs(5));
        let text = metrics.render();
        assert_eq!(
            sample(
                &text,
                "kubidm_backup_verification_failures_total",
                "destination=\"local\",level=\"full\""
            )
            .as_deref(),
            Some("1")
        );
        assert_eq!(
            sample(
                &text,
                "kubidm_backup_last_verified_timestamp_seconds",
                "destination=\"local\",level=\"full\""
            )
            .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn events_update_their_timestamps_and_counters() {
        let metrics = BackupMetrics::new(Some(&full_config()));
        let local = BackupDestination::Local;
        let eu = BackupDestination::S3Region("eu".to_string());

        metrics.backup_succeeded(&local, Duration::from_millis(1_700_000_000_250));
        metrics.verification_succeeded(&local, VerificationLevel::Structural, secs(1_700_000_000));
        metrics.backup_failed(&eu, secs(1_700_000_100));
        metrics.backup_failed(&eu, secs(1_700_000_200));
        metrics.backup_succeeded(&eu, secs(1_700_000_300));
        metrics.verification_succeeded(&local, VerificationLevel::Full, secs(1_700_000_400));
        metrics.pitr_sync_succeeded(secs(1_700_000_500));
        metrics.pitr_sync_failed(secs(1_700_000_600));

        let text = metrics.render();
        let value = |name: &str, labels: &str| sample(&text, name, labels);
        assert_eq!(
            value(
                "kubidm_backup_last_success_timestamp_seconds",
                "destination=\"local\""
            )
            .as_deref(),
            Some("1700000000.250")
        );
        assert_eq!(
            value(
                "kubidm_backup_last_verified_timestamp_seconds",
                "destination=\"local\",level=\"structural\""
            )
            .as_deref(),
            Some("1700000000.000")
        );
        assert_eq!(
            value(
                "kubidm_backup_last_verified_timestamp_seconds",
                "destination=\"local\",level=\"full\""
            )
            .as_deref(),
            Some("1700000400.000")
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
            value("kubidm_backup_last_success_timestamp_seconds", eu_labels).as_deref(),
            Some("1700000300.000")
        );
        assert_eq!(
            value("kubidm_backup_pitr_last_sync_timestamp_seconds", "").as_deref(),
            Some("1700000500.000")
        );
        assert_eq!(
            value("kubidm_backup_pitr_sync_failures_total", "").as_deref(),
            Some("1")
        );
        // The S3 primary saw nothing.
        assert_eq!(
            value(
                "kubidm_backup_last_success_timestamp_seconds",
                "destination=\"s3\""
            )
            .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn a_destination_that_was_not_configured_is_added_by_its_first_event() {
        // The test hooks back up to locations the configuration does not name.
        let metrics = BackupMetrics::new(None);
        metrics.backup_succeeded(&BackupDestination::S3, secs(10));
        let text = metrics.render();
        assert_eq!(
            sample(
                &text,
                "kubidm_backup_last_success_timestamp_seconds",
                "destination=\"s3\""
            )
            .as_deref(),
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
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label_value("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        assert_eq!(escape_label_value("eu-west-1"), "eu-west-1");
    }
}
