//! Kubidm: template driven delegated administration.

use crate::{ClientError, KubidmClient};
use kubidm_proto::internal::Filter as ProtoFilter;
use kubidm_proto::v1::{DelegationGrant, DelegationGrantRequest};

impl KubidmClient {
    /// List the delegations.
    pub async fn delegation_list(&self) -> Result<Vec<DelegationGrant>, ClientError> {
        self.perform_get_request("/v1/delegation").await
    }

    /// Get a delegation, by name or uuid.
    pub async fn delegation_get(&self, id: &str) -> Result<DelegationGrant, ClientError> {
        self.perform_get_request(format!("/v1/delegation/{id}").as_str())
            .await
    }

    /// Grant the members of `receiver` the rights of `template` over the members of
    /// `scope` (that match `filter`, if any). The groups are names, spns or uuids.
    pub async fn delegation_grant(
        &self,
        template: &str,
        receiver: &str,
        scope: &str,
        filter: Option<ProtoFilter>,
    ) -> Result<DelegationGrant, ClientError> {
        let request = DelegationGrantRequest {
            template: template.to_string(),
            receiver: receiver.to_string(),
            scope: scope.to_string(),
            filter,
        };
        self.perform_post_request("/v1/delegation", request).await
    }

    /// Revoke a delegation, by name or uuid.
    pub async fn delegation_revoke(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/delegation/{id}").as_str())
            .await
    }
}
