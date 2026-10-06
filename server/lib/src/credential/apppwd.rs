use crate::{
    credential::{CryptoPolicy, Password},
    prelude::*,
};
use kubidm_proto::internal::OperationError;
use std::{cmp::Ordering, fmt};

#[derive(Clone)]
pub struct ApplicationPassword {
    pub uuid: Uuid,
    pub(crate) application: Uuid,
    pub(crate) label: String,
    pub(crate) password: Password,
}

impl fmt::Debug for ApplicationPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationPassword")
            .field("uuid", &self.uuid)
            .field("application", &self.application)
            .field("label", &self.label)
            .finish()
    }
}

impl ApplicationPassword {
    pub fn new(
        application: Uuid,
        label: &str,
        cleartext: &str,
        policy: &CryptoPolicy,
    ) -> Result<ApplicationPassword, OperationError> {
        let pw = Password::new(policy, cleartext).map_err(|e| {
            error!(crypto_err = ?e);
            OperationError::CryptographyError
        })?;
        let ap = ApplicationPassword {
            uuid: Uuid::new_v4(),
            application,
            label: label.to_string(),
            password: pw,
        };
        Ok(ap)
    }
}

impl PartialEq for ApplicationPassword {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
            || (self.application == other.application && self.label == other.label)
    }
}

impl Eq for ApplicationPassword {}

impl PartialOrd for ApplicationPassword {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApplicationPassword {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationPassword;
    use crate::credential::CryptoPolicy;
    use uuid::Uuid;

    fn test_policy() -> CryptoPolicy {
        CryptoPolicy::danger_test_minimum()
    }

    #[test]
    fn test_application_password_new() {
        let app_uuid = Uuid::new_v4();
        let ap = ApplicationPassword::new(app_uuid, "test-label", "test-password", &test_policy());
        assert!(ap.is_ok());
        let ap = ap.unwrap();
        assert_eq!(ap.application, app_uuid);
        assert_eq!(ap.label, "test-label");
    }

    #[test]
    fn test_application_password_debug_does_not_leak() {
        let ap = ApplicationPassword::new(
            Uuid::new_v4(),
            "secret-label",
            "super-secret-password",
            &test_policy(),
        )
        .unwrap();
        let debug_str = format!("{:?}", ap);
        assert!(debug_str.contains("ApplicationPassword"));
        // The debug output intentionally includes the label but NOT the password
        assert!(debug_str.contains("secret-label"));
        assert!(!debug_str.contains("super-secret-password"));
    }

    #[test]
    fn test_application_password_eq_same_uuid() {
        let app_uuid = Uuid::new_v4();
        let pw = "test-password";
        let ap1 = ApplicationPassword::new(app_uuid, "label", pw, &test_policy()).unwrap();
        // Create another with same UUID by cloning
        let ap2 = ap1.clone();
        assert_eq!(ap1, ap2);
    }

    #[test]
    fn test_application_password_eq_same_app_and_label() {
        let app_uuid = Uuid::new_v4();
        let ap1 = ApplicationPassword::new(app_uuid, "my-label", "pw1", &test_policy()).unwrap();
        let ap2 = ApplicationPassword::new(app_uuid, "my-label", "pw2", &test_policy()).unwrap();
        // Different UUIDs but same app+label should be equal
        assert_ne!(ap1.uuid, ap2.uuid);
        assert_eq!(ap1, ap2);
    }

    #[test]
    fn test_application_password_ne_different_app() {
        let ap1 =
            ApplicationPassword::new(Uuid::new_v4(), "same-label", "pw", &test_policy()).unwrap();
        let ap2 =
            ApplicationPassword::new(Uuid::new_v4(), "same-label", "pw", &test_policy()).unwrap();
        assert_ne!(ap1, ap2);
    }

    #[test]
    fn test_application_password_ne_different_label() {
        let app_uuid = Uuid::new_v4();
        let ap1 = ApplicationPassword::new(app_uuid, "label-1", "pw", &test_policy()).unwrap();
        let ap2 = ApplicationPassword::new(app_uuid, "label-2", "pw", &test_policy()).unwrap();
        assert_ne!(ap1, ap2);
    }

    #[test]
    fn test_application_password_ord_by_uuid() {
        let app_uuid = Uuid::new_v4();
        let ap1 = ApplicationPassword::new(app_uuid, "a", "pw", &test_policy()).unwrap();
        let ap2 = ApplicationPassword::new(app_uuid, "b", "pw", &test_policy()).unwrap();
        // Ordering is by UUID, which is random
        let _ = ap1.cmp(&ap2);
    }

    #[test]
    fn test_application_password_partial_ord() {
        let ap1 = ApplicationPassword::new(Uuid::new_v4(), "test", "pw", &test_policy()).unwrap();
        let ap2 = ap1.clone();
        assert_eq!(ap1.partial_cmp(&ap2), Some(std::cmp::Ordering::Equal));
    }
}
