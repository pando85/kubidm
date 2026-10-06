use std::time::Duration;

use kubidm_proto::internal::RadiusAuthToken;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    entry::{Entry, EntryCommitted, EntryReduced},
    idm::group::Group,
    prelude::*,
};

#[derive(Debug, Clone)]
pub(crate) struct RadiusAccount {
    pub name: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub groups: Vec<Group<()>>,
    pub radius_secret: String,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
}

impl RadiusAccount {
    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        let radius_secret = value
            .get_ava_single_secret(Attribute::RadiusSecret)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::RadiusSecret))?
            .to_string();

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

        let uuid = value.get_uuid();

        let displayname = value
            .get_ava_single_utf8(Attribute::DisplayName)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::DisplayName))?;

        let groups = Group::<()>::try_from_account_reduced(value, qs)?;

        let valid_from = value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = value.get_ava_single_datetime(Attribute::AccountExpire);

        Ok(RadiusAccount {
            name,
            displayname,
            uuid,
            groups,
            radius_secret,
            valid_from,
            expire,
        })
    }

    fn is_within_valid_time(&self, ct: Duration) -> bool {
        let cot = OffsetDateTime::UNIX_EPOCH + ct;

        let vmin = if let Some(vft) = &self.valid_from {
            // If current time greater than start time window
            vft < &cot
        } else {
            // We have no time, not expired.
            true
        };
        let vmax = if let Some(ext) = &self.expire {
            // If exp greater than ct then expired.
            &cot < ext
        } else {
            // If not present, we are not expired
            true
        };
        // Mix the results
        vmin && vmax
    }

    pub(crate) fn to_radiusauthtoken(
        &self,
        ct: Duration,
    ) -> Result<RadiusAuthToken, OperationError> {
        if !self.is_within_valid_time(ct) {
            return Err(OperationError::InvalidAccountState(
                "Account Expired".to_string(),
            ));
        }

        // If we don't have access/permission, then just error instead.
        // This includes if we don't have the secret.
        Ok(RadiusAuthToken {
            name: self.name.clone(),
            displayname: self.displayname.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
            secret: self.radius_secret.clone(),
            groups: self.groups.iter().map(|g| g.to_proto()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RadiusAccount;
    use crate::prelude::*;
    use time::Duration as TimeDuration;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn make_account() -> RadiusAccount {
        RadiusAccount {
            name: "radius_user".to_string(),
            displayname: "Radius User".to_string(),
            uuid: Uuid::new_v4(),
            groups: vec![],
            radius_secret: "secret123".to_string(),
            valid_from: None,
            expire: None,
        }
    }

    #[test]
    fn test_radius_account_no_time_constraints() {
        let account = make_account();
        // No valid_from or expire means always valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(0)));
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(999999)));
    }

    #[test]
    fn test_radius_account_valid_from_future() {
        // valid_from is 1 hour from epoch, current time is 30 min from epoch
        let mut account = make_account();
        account.valid_from = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        // Before valid_from - should be invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(1800)));
        // After valid_from - should be valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(7200)));
    }

    #[test]
    fn test_radius_account_expired() {
        // expire is 1 hour from epoch, current time is 2 hours from epoch
        let mut account = make_account();
        account.expire = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        // Before expiry - should be valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(1800)));
        // After expiry - should be invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(7200)));
    }

    #[test]
    fn test_radius_account_valid_window() {
        // valid_from at 1h, expire at 3h
        let mut account = make_account();
        account.valid_from = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));
        account.expire = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(3));

        // Before valid_from - invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(1800)));
        // Within window - valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(7200)));
        // After expiry - invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(14400)));
    }

    #[test]
    fn test_radius_account_exact_boundary_valid_from() {
        let mut account = make_account();
        account.valid_from = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        // Exactly at valid_from - the check is vft < cot, so equal means invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(3600)));
        // One second after - valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(3601)));
    }

    #[test]
    fn test_radius_account_exact_boundary_expire() {
        let mut account = make_account();
        account.expire = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        // Exactly at expire - the check is cot < ext, so equal means invalid
        assert!(!account.is_within_valid_time(std::time::Duration::from_secs(3600)));
        // One second before - valid
        assert!(account.is_within_valid_time(std::time::Duration::from_secs(3599)));
    }

    #[test]
    fn test_radius_account_to_radiusauthtoken_valid() {
        let account = make_account();
        let token = account.to_radiusauthtoken(std::time::Duration::from_secs(1000));
        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!(token.name, "radius_user");
        assert_eq!(token.displayname, "Radius User");
        assert_eq!(token.secret, "secret123");
    }

    #[test]
    fn test_radius_account_to_radiusauthtoken_expired() {
        let mut account = make_account();
        account.expire = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        let result = account.to_radiusauthtoken(std::time::Duration::from_secs(7200));
        assert!(result.is_err());
        if let Err(OperationError::InvalidAccountState(msg)) = result {
            assert_eq!(msg, "Account Expired");
        } else {
            panic!("Expected InvalidAccountState error");
        }
    }

    #[test]
    fn test_radius_account_to_radiusauthtoken_not_yet_valid() {
        let mut account = make_account();
        account.valid_from = Some(OffsetDateTime::UNIX_EPOCH + TimeDuration::hours(1));

        let result = account.to_radiusauthtoken(std::time::Duration::from_secs(1800));
        assert!(result.is_err());
        if let Err(OperationError::InvalidAccountState(msg)) = result {
            assert_eq!(msg, "Account Expired");
        } else {
            panic!("Expected InvalidAccountState error");
        }
    }
}
