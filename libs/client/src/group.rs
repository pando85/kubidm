use crate::{ClientError, KubidmClient};
use kubidm_proto::constants::{
    ATTR_CLASS, ATTR_MAX_GRANT_DURATION, ATTR_UUID, ENTRYCLASS_GROUP, ENTRYCLASS_TIME_BOUNDED_GRANT,
};
use kubidm_proto::internal::{Filter, Modify, ModifyList};
use kubidm_proto::v1::{Entry, TimeBoundedMemberGrant, TimeBoundedMemberGrantRequest};
use time::OffsetDateTime;

impl KubidmClient {
    pub async fn idm_group_search(&self, id: &str) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/group/_search/{id}"))
            .await
    }

    pub async fn idm_group_purge_attr(&self, id: &str, attr: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/group/{id}/_attr/{attr}").as_str())
            .await
    }

    pub async fn group_account_policy_enable(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            &format!("/v1/group/{id}/_attr/class"),
            vec!["account_policy".to_string()],
        )
        .await
    }

    pub async fn group_rename(&self, name: &str, new_name: &str) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{name}/_attr/name"), vec![new_name])
            .await
    }

    pub async fn group_account_policy_authsession_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/authsession_expiry"),
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_authsession_expiry_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/authsession_expiry"))
            .await
    }

    pub async fn group_account_policy_credential_type_minimum_set(
        &self,
        id: &str,
        value: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/credential_type_minimum"),
            vec![value.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_password_minimum_length_set(
        &self,
        id: &str,
        length: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/auth_password_minimum_length"),
            vec![length.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_password_minimum_length_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/auth_password_minimum_length"
        ))
        .await
    }

    pub async fn group_account_policy_privilege_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/privilege_expiry"),
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_privilege_expiry_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/privilege_expiry"))
            .await
    }

    pub async fn group_account_policy_webauthn_attestation_set(
        &self,
        id: &str,
        att_ca_list: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/webauthn_attestation_ca_list"),
            vec![att_ca_list.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_webauthn_attestation_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/webauthn_attestation_ca_list"
        ))
        .await
    }

    pub async fn group_account_policy_limit_search_max_results(
        &self,
        id: &str,
        maximum: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/limit_search_max_results"),
            vec![maximum.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_limit_search_max_results_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/limit_search_max_results"))
            .await
    }

    pub async fn group_account_policy_limit_search_max_filter_test(
        &self,
        id: &str,
        maximum: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/limit_search_max_filter_test"),
            vec![maximum.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_limit_search_max_filter_test_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/limit_search_max_filter_test"
        ))
        .await
    }

    pub async fn group_account_policy_allow_primary_cred_fallback(
        &self,
        id: &str,
        allow: bool,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/allow_primary_cred_fallback"),
            vec![allow.to_string()],
        )
        .await
    }

    pub async fn idm_group_purge_mail(&self, id: &str) -> Result<(), ClientError> {
        self.idm_group_purge_attr(id, "mail").await
    }

    pub async fn idm_group_set_mail<T: serde::Serialize>(
        &self,
        id: &str,
        values: &[T],
    ) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{id}/_attr/mail"), values)
            .await
    }

    pub async fn idm_group_get_mail(&self, id: &str) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(&format!("/v1/group/{id}/_attr/mail"))
            .await
    }

    pub async fn idm_group_purge_description(&self, id: &str) -> Result<(), ClientError> {
        self.idm_group_purge_attr(id, "description").await
    }

    pub async fn idm_group_set_description(
        &self,
        id: &str,
        description: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{id}/_attr/description"), &[description])
            .await
    }

    /// Kubidm: allow time-bounded membership grants on a group, optionally setting the
    /// longest window (in seconds) that a grant may cover. The class and the cap are written
    /// in a single modify, so the group is never enabled without the requested cap.
    pub async fn idm_group_time_bounded_enable(
        &self,
        id: &str,
        max_grant_duration: Option<u32>,
    ) -> Result<(), ClientError> {
        // Resolve the group to its uuid, so that the modify targets exactly this group.
        let group_uuid = self
            .idm_group_get(id)
            .await?
            .and_then(|entry| entry.attrs.get(ATTR_UUID).and_then(|v| v.first().cloned()))
            .ok_or(ClientError::EmptyResponse)?;

        let mut mods = vec![Modify::Present(
            ATTR_CLASS.to_string(),
            ENTRYCLASS_TIME_BOUNDED_GRANT.to_string(),
        )];
        if let Some(max_grant_duration) = max_grant_duration {
            mods.push(Modify::Purged(ATTR_MAX_GRANT_DURATION.to_string()));
            mods.push(Modify::Present(
                ATTR_MAX_GRANT_DURATION.to_string(),
                max_grant_duration.to_string(),
            ));
        }

        let filter = Filter::And(vec![
            Filter::Eq(ATTR_CLASS.to_string(), ENTRYCLASS_GROUP.to_string()),
            Filter::Eq(ATTR_UUID.to_string(), group_uuid),
        ]);
        self.modify(filter, ModifyList::new_list(mods)).await
    }

    /// Kubidm: grant `member` a membership of a group from `valid_from` (or now) until
    /// `valid_until`, replacing any existing grant of `member`.
    pub async fn idm_group_time_bounded_member_grant(
        &self,
        id: &str,
        member: &str,
        valid_from: Option<OffsetDateTime>,
        valid_until: OffsetDateTime,
    ) -> Result<(), ClientError> {
        let request = TimeBoundedMemberGrantRequest {
            member: member.to_string(),
            valid_from,
            valid_until,
        };
        self.perform_post_request(&format!("/v1/group/{id}/_time_bounded_member"), request)
            .await
    }

    /// Kubidm: revoke the time-bounded membership grant of `member` on a group.
    pub async fn idm_group_time_bounded_member_revoke(
        &self,
        id: &str,
        member: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_time_bounded_member/{member}"))
            .await
    }

    /// Kubidm: list the time-bounded membership grants of a group.
    pub async fn idm_group_time_bounded_member_list(
        &self,
        id: &str,
    ) -> Result<Vec<TimeBoundedMemberGrant>, ClientError> {
        self.perform_get_request(&format!("/v1/group/{id}/_time_bounded_member"))
            .await
    }
}
