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

/// Whether a time-bounded grant makes its member a member of the group, at the time the
/// grants were listed.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeBoundedMemberGrantState {
    /// The grant is within its window: its member is a member of the group.
    Active,
    /// The grant starts later (`valid_from` is in the future).
    Pending,
    /// The grant ended (`valid_until` is past). It grants nothing, and is removed when the
    /// member is granted again, or revoked.
    Expired,
    /// The grant has not ended, but grants nothing because the group is high privilege
    /// (`idm_high_privilege`, or nested in it). It applies again, within its window, once
    /// the group is no longer high privilege. It can still be revoked.
    Suppressed,
}

impl std::fmt::Display for TimeBoundedMemberGrantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Pending => write!(f, "pending"),
            Self::Expired => write!(f, "expired"),
            Self::Suppressed => write!(f, "suppressed"),
        }
    }
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
    /// Whether the grant currently makes its member a member of the group.
    pub state: TimeBoundedMemberGrantState,
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

    #[test]
    fn test_time_bounded_grant_state_round_trip() {
        let json = r#"{"member":"00000000-0000-0000-0000-000000000001","member_spn":null,"valid_until":"2030-01-02T03:04:05Z","state":"suppressed"}"#;
        let grant: TimeBoundedMemberGrant =
            serde_json::from_str(json).expect("Failed to deserialise");
        assert_eq!(grant.state, TimeBoundedMemberGrantState::Suppressed);
        assert_eq!(grant.state.to_string(), "suppressed");

        for state in [
            TimeBoundedMemberGrantState::Active,
            TimeBoundedMemberGrantState::Pending,
            TimeBoundedMemberGrantState::Expired,
            TimeBoundedMemberGrantState::Suppressed,
        ] {
            let json = serde_json::to_string(&state).expect("Failed to serialise");
            assert_eq!(json, format!("\"{state}\""));
        }
    }
}
