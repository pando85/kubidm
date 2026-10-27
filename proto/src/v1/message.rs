use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema, Eq, PartialEq)]
pub enum OutboundMessage {
    TestMessageV1 {
        display_name: String,
    },
    CredentialResetV1 {
        display_name: String,
        intent_id: String,
        #[serde(with = "time::serde::timestamp")]
        expiry_time: OffsetDateTime,
    },
    AccountSignupRequestV1 {
        username: String,
        intent_id: String,
        #[serde(with = "time::serde::timestamp")]
        expiry_time: OffsetDateTime,
    },
}

impl OutboundMessage {
    pub fn display_type(&self) -> &'static str {
        match self {
            Self::TestMessageV1 { .. } => "test_message_v1",
            Self::CredentialResetV1 { .. } => "credential_reset_v1",
            Self::AccountSignupRequestV1 { .. } => "account_signup_request_v1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_message_v1_serde_roundtrip() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test display".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let recovered: OutboundMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_test_message_v1_fields() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "hello world".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inner = value.get("TestMessageV1").unwrap();
        assert_eq!(inner["display_name"], "hello world");
    }

    #[test]
    fn test_credential_reset_v1_serde_roundtrip() {
        let expiry = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let msg = OutboundMessage::CredentialResetV1 {
            display_name: "user one".to_string(),
            intent_id: "intent_abc123".to_string(),
            expiry_time: expiry,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let recovered: OutboundMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_credential_reset_v1_fields() {
        let expiry = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        let msg = OutboundMessage::CredentialResetV1 {
            display_name: "user two".to_string(),
            intent_id: "intent_xyz789".to_string(),
            expiry_time: expiry,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inner = value.get("CredentialResetV1").unwrap();
        assert_eq!(inner["display_name"], "user two");
        assert_eq!(inner["intent_id"], "intent_xyz789");
        assert!(inner.get("expiry_time").unwrap().is_number());
    }

    #[test]
    fn test_display_type() {
        let test_msg = OutboundMessage::TestMessageV1 {
            display_name: "test".to_string(),
        };
        assert_eq!(test_msg.display_type(), "test_message_v1");

        let cred_msg = OutboundMessage::CredentialResetV1 {
            display_name: "user".to_string(),
            intent_id: "id".to_string(),
            expiry_time: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(cred_msg.display_type(), "credential_reset_v1");
    }

    #[test]
    fn test_credential_reset_v1_expiry_time_serializes_as_timestamp() {
        let msg = OutboundMessage::CredentialResetV1 {
            display_name: "user".to_string(),
            intent_id: "id".to_string(),
            expiry_time: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inner = value.get("CredentialResetV1").unwrap();
        assert_eq!(inner["expiry_time"], 0);
    }
}
