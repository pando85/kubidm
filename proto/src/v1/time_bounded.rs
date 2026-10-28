//! Kubidm: time-bounded group membership.
//!
//! A group with the `time_bounded_grant` class can hold grants that make an entry a
//! member of the group only between `valid_from` (or immediately) and `valid_until`.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// Grant `member` a time-bounded membership of a group. Replaces any existing grant for
/// the same member.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct TimeBoundedMemberGrantRequest {
    /// The name, spn or uuid of the person, group or service account to grant.
    pub member: String,
    /// When the membership starts (RFC 3339). Starts immediately when absent.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub valid_from: Option<OffsetDateTime>,
    /// When the membership ends (RFC 3339, exclusive).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub valid_until: OffsetDateTime,
}

/// A time-bounded membership grant of a group.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct TimeBoundedMemberGrant {
    pub member: Uuid,
    /// The spn of the member, when it can be resolved.
    pub member_spn: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub valid_until: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_bounded_grant_request_round_trip() {
        let json = r#"{"member":"alice","valid_until":"2030-01-02T03:04:05Z"}"#;
        let req: TimeBoundedMemberGrantRequest =
            serde_json::from_str(json).expect("Failed to deserialise");
        assert_eq!(req.member, "alice");
        assert!(req.valid_from.is_none());
        assert_eq!(req.valid_until.unix_timestamp(), 1_893_553_445);

        let json = serde_json::to_string(&req).expect("Failed to serialise");
        let again: TimeBoundedMemberGrantRequest =
            serde_json::from_str(&json).expect("Failed to deserialise");
        assert_eq!(req, again);

        let json = r#"{"member":"alice","valid_from":"2030-01-01T00:00:00+01:00","valid_until":"2030-01-02T03:04:05Z"}"#;
        let req: TimeBoundedMemberGrantRequest =
            serde_json::from_str(json).expect("Failed to deserialise");
        assert_eq!(
            req.valid_from.map(|vf| vf.unix_timestamp()),
            Some(1_893_452_400)
        );
    }
}
