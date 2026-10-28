use crate::{ClientError, KubidmClient};
use kubidm_proto::v1::{
    ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalPolicy, ApprovalPolicyCreateRequest,
    ApprovalRequest, ApprovalRequestCreateRequest, ApprovalRequestState,
};
use uuid::Uuid;

impl KubidmClient {
    pub async fn approval_policy_list(&self) -> Result<Vec<ApprovalPolicy>, ClientError> {
        self.perform_get_request("/v1/approval/policy").await
    }

    pub async fn approval_policy_get(&self, name: &str) -> Result<ApprovalPolicy, ClientError> {
        self.perform_get_request(format!("/v1/approval/policy/{}", name).as_str())
            .await
    }

    pub async fn approval_policy_create(
        &self,
        request: &ApprovalPolicyCreateRequest,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/v1/approval/policy", request)
            .await
    }

    pub async fn approval_policy_delete(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/approval/policy/{}", name).as_str())
            .await
    }

    pub async fn approval_policy_enable(&self, name: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/approval/policy/{}/_enable", name).as_str(),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn approval_policy_disable(&self, name: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/approval/policy/{}/_disable", name).as_str(),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn approval_request_list(
        &self,
        state: Option<ApprovalRequestState>,
    ) -> Result<Vec<ApprovalRequest>, ClientError> {
        let url = match state {
            Some(s) => format!("/v1/approval/request?state={}", s),
            None => "/v1/approval/request".to_string(),
        };
        self.perform_get_request(url.as_str()).await
    }

    pub async fn approval_request_get(&self, uuid: &str) -> Result<ApprovalRequest, ClientError> {
        self.perform_get_request(format!("/v1/approval/request/{}", uuid).as_str())
            .await
    }

    /// Create an approval request as the calling identity. Returns the uuid of the request.
    pub async fn approval_request_create(
        &self,
        request: &ApprovalRequestCreateRequest,
    ) -> Result<Uuid, ClientError> {
        self.perform_post_request("/v1/approval/request", request)
            .await
    }

    pub async fn approval_request_approve(
        &self,
        uuid: &str,
        comment: Option<&str>,
    ) -> Result<(), ClientError> {
        let request = ApprovalDecisionRequest {
            action: ApprovalDecisionAction::Approve,
            comment: comment.map(String::from),
        };
        self.perform_post_request(
            format!("/v1/approval/request/{}/_decision", uuid).as_str(),
            &request,
        )
        .await
    }

    pub async fn approval_request_reject(
        &self,
        uuid: &str,
        comment: Option<&str>,
    ) -> Result<(), ClientError> {
        let request = ApprovalDecisionRequest {
            action: ApprovalDecisionAction::Reject,
            comment: comment.map(String::from),
        };
        self.perform_post_request(
            format!("/v1/approval/request/{}/_decision", uuid).as_str(),
            &request,
        )
        .await
    }

    pub async fn approval_request_cancel(&self, uuid: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/approval/request/{}", uuid).as_str())
            .await
    }

    /// Execute an approved request as its requester: carry out its operation and consume
    /// the approval. Only `group_membership_high_privilege` requests can be executed.
    pub async fn approval_request_execute(&self, uuid: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/approval/request/{}/_execute", uuid).as_str(),
            serde_json::json!({}),
        )
        .await
    }
}
