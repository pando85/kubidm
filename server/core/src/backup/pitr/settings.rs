//! Where the archive and the base backups are, derived from the configuration.

use std::fmt;
use std::path::PathBuf;

use kubidm_proto::backup::{
    BackupEncryptionConfig, ReplicationConfig, ReplicationRegionConfig, S3Config, WalArchiveConfig,
};

use super::PitrError;
use crate::config::Configuration;

/// Where closed segments and the manifest are kept.
// Built once from the configuration; boxing the S3 variant would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PitrLocation {
    /// No S3 location is configured: segments stay in the local WAL directory and the
    /// manifest is written next to them.
    Local(PathBuf),
    /// Segments are uploaded under `<path_prefix>/wal/` and the manifest to
    /// `<path_prefix>/pitr-manifest.json`.
    S3(S3Config),
}

impl fmt::Display for PitrLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PitrLocation::Local(dir) => write!(f, "{}", dir.display()),
            PitrLocation::S3(config) => fmt_s3_location(f, config),
        }
    }
}

/// Where the online backup writes the base backups recovery starts from.
// Built once from the configuration; boxing the S3 variant would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseLocation {
    /// The local online backup directory (`online_backup.path`).
    Local(PathBuf),
    /// The online backup S3 location (`[online_backup.s3]`).
    S3(S3Config),
}

impl fmt::Display for BaseLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseLocation::Local(dir) => write!(f, "{}", dir.display()),
            BaseLocation::S3(config) => fmt_s3_location(f, config),
        }
    }
}

fn fmt_s3_location(f: &mut fmt::Formatter<'_>, config: &S3Config) -> fmt::Result {
    match config
        .path_prefix
        .as_deref()
        .map(|prefix| prefix.trim_matches('/'))
        .filter(|prefix| !prefix.is_empty())
    {
        Some(prefix) => write!(f, "s3://{}/{prefix}", config.bucket),
        None => write!(f, "s3://{}", config.bucket),
    }
}

/// The settings PITR derives from the server configuration.
#[derive(Debug, Clone)]
pub struct PitrSettings {
    pub wal: WalArchiveConfig,
    /// Where the backend writes closed segments.
    pub local_dir: PathBuf,
    /// Where segments and the manifest are archived.
    pub location: PitrLocation,
    /// Where the base backups are. S3 when `[online_backup.s3]` is configured, since an
    /// off-host copy is what disaster recovery needs; the local directory otherwise.
    pub bases: BaseLocation,
    /// The backup encryption settings. When enabled, archived segments are encrypted with
    /// them exactly like backups.
    pub encryption: BackupEncryptionConfig,
}

impl PitrSettings {
    /// The PITR settings of `config`, or None when WAL archiving is not enabled.
    pub fn from_config(config: &Configuration) -> Result<Option<Self>, PitrError> {
        let Some(online_backup) = config.online_backup.as_ref() else {
            return Ok(None);
        };
        let Some(wal) = online_backup.wal_archive.as_ref().filter(|w| w.enabled) else {
            return Ok(None);
        };

        let local_dir = match &wal.local_path {
            Some(path) => path.clone(),
            None => {
                let db_path = config.db_path.as_ref().ok_or_else(|| {
                    PitrError::Config(
                        "wal_archive.local_path must be set when db_path is unset".to_string(),
                    )
                })?;
                db_path
                    .parent()
                    .map(|parent| parent.join("wal"))
                    .ok_or_else(|| {
                        PitrError::Config(
                            "db_path has no parent directory; set wal_archive.local_path"
                                .to_string(),
                        )
                    })?
            }
        };

        let location = match wal.s3.clone().or_else(|| online_backup.s3.clone()) {
            Some(s3) => PitrLocation::S3(s3),
            None => PitrLocation::Local(local_dir.clone()),
        };

        let bases = match (&online_backup.s3, &online_backup.path) {
            (Some(s3), _) => BaseLocation::S3(s3.clone()),
            (None, Some(path)) => BaseLocation::Local(path.clone()),
            (None, None) => return Err(PitrError::Config(
                "WAL archiving needs base backups: set online_backup.path or [online_backup.s3]"
                    .to_string(),
            )),
        };

        Ok(Some(PitrSettings {
            wal: wal.clone(),
            local_dir,
            location,
            bases,
            encryption: online_backup.encryption.clone(),
        }))
    }

    /// The replication section the archive is mirrored with: the enabled replication of
    /// the S3 location the archive is uploaded to. A local archive is never replicated.
    pub fn replication(&self) -> Option<&ReplicationConfig> {
        match &self.location {
            PitrLocation::S3(config) => config
                .replication
                .as_ref()
                .filter(|replication| replication.enabled),
            PitrLocation::Local(_) => None,
        }
    }

    /// These settings with the archive, and the base backups when they are in S3, read from
    /// the copies held by the replication region `name`. The region is looked up whether or
    /// not replication is enabled, so that a replica stays a recovery source after
    /// replication was switched off, as for `restore-s3 --region`.
    pub fn for_region(&self, name: &str) -> Result<Self, PitrError> {
        let PitrLocation::S3(wal_s3) = &self.location else {
            return Err(PitrError::Config(format!(
                "the WAL archive is kept in the local directory {}; only an archive in S3 is \
                 replicated to regions",
                self.local_dir.display()
            )));
        };
        let wal_region = find_region(wal_s3, name).ok_or_else(|| {
            PitrError::Config(format!(
                "no replication region named '{name}' is configured for the S3 location of \
                 the WAL archive ({})",
                self.location
            ))
        })?;
        let bases = match &self.bases {
            BaseLocation::S3(base_s3) => BaseLocation::S3(
                find_region(base_s3, name)
                    .ok_or_else(|| {
                        PitrError::Config(format!(
                            "no replication region named '{name}' is configured in \
                             [online_backup.s3], where the base backups are"
                        ))
                    })?
                    .to_s3_config(),
            ),
            BaseLocation::Local(dir) => BaseLocation::Local(dir.clone()),
        };
        Ok(Self {
            location: PitrLocation::S3(wal_region.to_s3_config()),
            bases,
            ..self.clone()
        })
    }

    /// The WAL configuration the backend archives with: the configured one with the
    /// segment directory resolved, so that the backend and this module agree on it.
    pub fn backend_wal_config(&self) -> WalArchiveConfig {
        WalArchiveConfig {
            local_path: Some(self.local_dir.clone()),
            ..self.wal.clone()
        }
    }
}

/// The replication region `name` of `config`, whether or not replication is enabled.
fn find_region<'a>(config: &'a S3Config, name: &str) -> Option<&'a ReplicationRegionConfig> {
    config
        .replication
        .as_ref()
        .and_then(|replication| replication.regions.iter().find(|r| r.region == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubidm_proto::backup::WalArchiveConfig;

    #[test]
    fn test_pitr_settings_from_config() {
        use crate::config::OnlineBackup;
        let mut config = Configuration::new_for_test();
        assert!(PitrSettings::from_config(&config).unwrap().is_none());

        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        config.online_backup = Some(OnlineBackup {
            path: Some(PathBuf::from("/var/lib/kubidm/backups")),
            wal_archive: Some(WalArchiveConfig {
                enabled: true,
                ..WalArchiveConfig::default()
            }),
            ..OnlineBackup::default()
        });
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.local_dir, PathBuf::from("/var/lib/kubidm/wal"));
        assert_eq!(
            settings.location,
            PitrLocation::Local(PathBuf::from("/var/lib/kubidm/wal"))
        );
        assert_eq!(
            settings.bases,
            BaseLocation::Local(PathBuf::from("/var/lib/kubidm/backups"))
        );
        assert_eq!(
            settings.backend_wal_config().local_path,
            Some(PathBuf::from("/var/lib/kubidm/wal"))
        );

        // The backup S3 section is the default archive location and holds the bases;
        // wal_archive.s3 only moves the archive.
        let backup_s3 = S3Config::with_bucket("backups".to_string());
        let wal_s3 = S3Config::with_bucket("wal".to_string());
        let online_backup = config.online_backup.as_mut().unwrap();
        online_backup.s3 = Some(backup_s3.clone());
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.location, PitrLocation::S3(backup_s3.clone()));
        assert_eq!(settings.bases, BaseLocation::S3(backup_s3.clone()));
        config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap()
            .s3 = Some(wal_s3.clone());
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.location, PitrLocation::S3(wal_s3));
        assert_eq!(settings.bases, BaseLocation::S3(backup_s3));

        // An explicit local path wins over the database directory.
        config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap()
            .local_path = Some(PathBuf::from("/srv/wal"));
        let settings = PitrSettings::from_config(&config).unwrap().unwrap();
        assert_eq!(settings.local_dir, PathBuf::from("/srv/wal"));

        // Disabled: none. In memory without a local path: an error. No base location: an
        // error.
        let wal = config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap();
        wal.enabled = false;
        assert!(PitrSettings::from_config(&config).unwrap().is_none());
        let wal = config
            .online_backup
            .as_mut()
            .unwrap()
            .wal_archive
            .as_mut()
            .unwrap();
        wal.enabled = true;
        wal.local_path = None;
        config.db_path = None;
        assert!(matches!(
            PitrSettings::from_config(&config),
            Err(PitrError::Config(_))
        ));
        config.db_path = Some(PathBuf::from("/var/lib/kubidm/kubidm.db"));
        let online_backup = config.online_backup.as_mut().unwrap();
        online_backup.s3 = None;
        online_backup.path = None;
        assert!(matches!(
            PitrSettings::from_config(&config),
            Err(PitrError::Config(_))
        ));
    }

    #[test]
    fn test_location_display() {
        let mut s3 = S3Config::with_bucket("bucket".to_string());
        assert_eq!(PitrLocation::S3(s3.clone()).to_string(), "s3://bucket");
        s3.path_prefix = Some("/prod/".to_string());
        assert_eq!(BaseLocation::S3(s3).to_string(), "s3://bucket/prod");
        assert_eq!(
            PitrLocation::Local(PathBuf::from("/var/lib/kubidm/wal")).to_string(),
            "/var/lib/kubidm/wal"
        );
    }
}
