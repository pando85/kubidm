//! Fixtures shared by the PITR unit tests.

use std::path::Path;
use std::time::Duration;

use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, PitrBaseBackup, PitrManifest, WalSegment,
};
use kubidmd_lib::be::{BackupStructuralReport, SharedWalArchiver};
use kubidmd_lib::repl::cid::Cid;
use kubidmd_lib::repl::wal::WalPendingOp;
use uuid::Uuid;

pub(super) fn segment(id: &str, start: u64, end: u64) -> WalSegment {
    WalSegment {
        segment_id: id.to_string(),
        server_uuid: Uuid::nil(),
        start_ts: Duration::from_secs(start),
        end_ts: Duration::from_secs(end),
        first_cid: String::new(),
        last_cid: String::new(),
        entry_count: 1,
        checksum_sha256: String::new(),
        size_bytes: 1,
        compression: BackupCompression::Gzip,
        server_version: env!("KUBIDM_PKG_SERIES").to_string(),
        created_at: String::new(),
        encryption_key: None,
    }
}

pub(super) fn base(key: &str, watermark: u64) -> PitrBaseBackup {
    PitrBaseBackup {
        key: key.to_string(),
        timestamp: String::new(),
        watermark_ts: Duration::from_secs(watermark),
        server_version: env!("KUBIDM_PKG_SERIES").to_string(),
        server_uuid: Some(Uuid::nil()),
    }
}

pub(super) fn manifest() -> PitrManifest {
    let mut m = PitrManifest::new(Uuid::nil());
    m.add_base_backup(base("backup-1", 100));
    m.add_base_backup(base("backup-2", 400));
    m.add_segment(segment("s1", 110, 200));
    m.add_segment(segment("s2", 210, 450));
    m.add_segment(segment("s3", 460, 600));
    m
}

pub(super) const DAY: u64 = 86400;

pub(super) fn report(ts: u64, server: Uuid) -> BackupStructuralReport {
    BackupStructuralReport {
        entry_count: 1,
        version: Some(env!("KUBIDM_PKG_SERIES").to_string()),
        db_s_uuid: Some(server),
        db_ts_max: Some(Duration::from_secs(ts)),
        errors: Vec::new(),
    }
}

pub(super) fn fast_encryption(passphrase_file: &Path) -> BackupEncryptionConfig {
    BackupEncryptionConfig {
        enabled: true,
        key_source: kubidm_proto::backup::EncryptionKeySource::Passphrase,
        key_derivation: kubidm_proto::backup::KeyDerivationParams {
            m_cost: crate::backup::MIN_KDF_M_COST,
            t_cost: 1,
            p_cost: 1,
        },
        key_identifier: Some("unit-wal-key".to_string()),
        passphrase_file: Some(passphrase_file.to_path_buf()),
    }
}

pub(super) fn append_create(archiver: &SharedWalArchiver, server: Uuid, secs: u64, data: &[u8]) {
    archiver
        .lock()
        .unwrap()
        .append_transaction(
            &Cid {
                ts: Duration::from_secs(secs),
                s_uuid: server,
            },
            false,
            vec![(
                secs,
                WalPendingOp::Create {
                    entry_uuid: Uuid::new_v4(),
                    entry_data: data.to_vec(),
                },
            )],
        )
        .unwrap();
}
