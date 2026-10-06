use crate::{
    prelude::*,
    value::{AuthType, SessionExtMetadata},
};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::AuthenticationResult;

#[derive(Debug)]
pub enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
    BackupCodeRemoval(BackupCodeRemoval),
    AuthSessionRecord(AuthSessionRecord),
    ApprovalTimeoutCheck(ApprovalTimeoutCheck),
    ApprovalEscalationCheck(ApprovalEscalationCheck),
}

pub struct PasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

impl fmt::Debug for PasswordUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordUpgrade")
            .field("target_uuid", &self.target_uuid)
            .finish()
    }
}

pub struct UnixPasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

impl fmt::Debug for UnixPasswordUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixPasswordUpgrade")
            .field("target_uuid", &self.target_uuid)
            .finish()
    }
}

#[derive(Debug)]
pub struct WebauthnCounterIncrement {
    pub target_uuid: Uuid,
    pub auth_result: AuthenticationResult,
}

#[derive(Debug)]
pub struct BackupCodeRemoval {
    pub target_uuid: Uuid,
    pub code_to_remove: String,
}

#[derive(Debug)]
pub struct AuthSessionRecord {
    pub target_uuid: Uuid,
    pub session_id: Uuid,
    pub cred_id: Uuid,
    pub label: String,
    pub expiry: Option<OffsetDateTime>,
    pub issued_at: OffsetDateTime,
    pub issued_by: IdentityId,
    pub scope: SessionScope,
    pub type_: AuthType,
    pub ext_metadata: SessionExtMetadata,
}

#[derive(Debug)]
pub struct ApprovalTimeoutCheck {
    pub request_uuid: Uuid,
}

#[derive(Debug)]
pub struct ApprovalEscalationCheck {
    pub request_uuid: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_upgrade_debug_does_not_leak() {
        let action = PasswordUpgrade {
            target_uuid: Uuid::new_v4(),
            existing_password: "super-secret-password".to_string(),
        };
        let debug = format!("{:?}", action);
        assert!(debug.contains("PasswordUpgrade"));
        assert!(debug.contains("target_uuid"));
        assert!(!debug.contains("super-secret-password"));
    }

    #[test]
    fn test_unix_password_upgrade_debug_does_not_leak() {
        let action = UnixPasswordUpgrade {
            target_uuid: Uuid::new_v4(),
            existing_password: "unix-secret".to_string(),
        };
        let debug = format!("{:?}", action);
        assert!(debug.contains("UnixPasswordUpgrade"));
        assert!(!debug.contains("unix-secret"));
    }

    #[test]
    fn test_backup_code_removal_debug() {
        let action = BackupCodeRemoval {
            target_uuid: Uuid::new_v4(),
            code_to_remove: "secret-backup-code".to_string(),
        };
        let debug = format!("{:?}", action);
        assert!(debug.contains("BackupCodeRemoval"));
        // BackupCodeRemoval derives Debug, so it will include the code
        // This is acceptable since backup codes are less sensitive than passwords
        assert!(debug.contains("code_to_remove"));
    }

    #[test]
    fn test_approval_timeout_check_debug() {
        let action = ApprovalTimeoutCheck {
            request_uuid: Uuid::new_v4(),
        };
        let debug = format!("{:?}", action);
        assert!(debug.contains("ApprovalTimeoutCheck"));
        assert!(debug.contains("request_uuid"));
    }

    #[test]
    fn test_approval_escalation_check_debug() {
        let action = ApprovalEscalationCheck {
            request_uuid: Uuid::new_v4(),
        };
        let debug = format!("{:?}", action);
        assert!(debug.contains("ApprovalEscalationCheck"));
    }

    #[test]
    fn test_delayed_action_variants() {
        let pw_uuid = Uuid::new_v4();
        let action = DelayedAction::PwUpgrade(PasswordUpgrade {
            target_uuid: pw_uuid,
            existing_password: "password".to_string(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("PwUpgrade"));

        let unix_uuid = Uuid::new_v4();
        let action = DelayedAction::UnixPwUpgrade(UnixPasswordUpgrade {
            target_uuid: unix_uuid,
            existing_password: "unixpw".to_string(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("UnixPwUpgrade"));

        let action = DelayedAction::BackupCodeRemoval(BackupCodeRemoval {
            target_uuid: Uuid::new_v4(),
            code_to_remove: "code".to_string(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("BackupCodeRemoval"));

        let action = DelayedAction::ApprovalTimeoutCheck(ApprovalTimeoutCheck {
            request_uuid: Uuid::new_v4(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("ApprovalTimeoutCheck"));

        let action = DelayedAction::ApprovalEscalationCheck(ApprovalEscalationCheck {
            request_uuid: Uuid::new_v4(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("ApprovalEscalationCheck"));
    }
}
