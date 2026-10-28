//! Kubidm: protect approval policies, approval requests and approval decision records.
//!
//! The outcome of an approval request is computed from the request (its quorum snapshot,
//! requester and creation time) and from its decision records, and whether an approval
//! can be used depends on its policy (enabled, operation types), see
//! `crate::server::approval`. Those entries are written only by the approval operations
//! (`approval_policy_create`, `approval_policy_enable`, `approval_policy_delete`, and the
//! request and decision operations), which run as the internal system identity after their
//! own authorisation checks (`idm_approval_admins` for policies), as does referential
//! integrity. Any other write - an access control profile granting more than intended, an
//! impersonated administrator, or another internal role - could forge, alter or remove a
//! decision, or change who approves under a policy, so this plugin refuses every create,
//! modify and delete of these entries that does not come from the system identity, with
//! `SystemProtectedObject`, whatever the access controls allow.
//!
//! This is a plugin rather than an entry in `server::access::protected`, as those rules are
//! only applied to non-internal identities, while this must also exclude the internal roles
//! other than the system.
//!
//! Replication does not run these hooks, so replicated records and requests are applied.

use std::sync::Arc;

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct ApprovalProtect {}

fn is_approval_entry<VALID, STATE>(entry: &Entry<VALID, STATE>) -> bool {
    entry.attribute_equality(Attribute::Class, &EntryClass::ApprovalPolicy.into())
        || entry.attribute_equality(Attribute::Class, &EntryClass::ApprovalRequest.into())
        || entry.attribute_equality(Attribute::Class, &EntryClass::ApprovalDecisionRecord.into())
}

fn is_system(ident: &Identity) -> bool {
    ident.is_internal() && ident.get_uuid() == UUID_SYSTEM
}

impl ApprovalProtect {
    fn check<'a, I, VALID: 'a, STATE: 'a>(
        ident: &Identity,
        op: &str,
        mut entries: I,
    ) -> Result<(), OperationError>
    where
        I: Iterator<Item = &'a Entry<VALID, STATE>>,
    {
        if is_system(ident) || !entries.any(is_approval_entry) {
            return Ok(());
        }
        security_access!(
            ident = %ident,
            op,
            "denied - approval policies, requests and decision records are only written by the approval operations"
        );
        Err(OperationError::SystemProtectedObject)
    }

    fn check_modify(
        ident: &Identity,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntryInvalidCommitted],
    ) -> Result<(), OperationError> {
        // Both before and after the change: neither turning an entry into one, nor
        // changing one, is allowed.
        Self::check(ident, "modify", pre_cand.iter().map(|e| e.as_ref()))?;
        Self::check(ident, "modify", cand.iter())
    }
}

impl Plugin for ApprovalProtect {
    fn id() -> &'static str {
        "plugin_approval_protect"
    }

    #[instrument(
        level = "debug",
        name = "approval_protect_pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::check(&ce.ident, "create", cand.iter())
    }

    #[instrument(level = "debug", name = "approval_protect_pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::check_modify(&me.ident, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "approval_protect_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::check_modify(&me.ident, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "approval_protect_pre_delete", skip_all)]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidCommitted>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Self::check(&de.ident, "delete", cand.iter())
    }
}
