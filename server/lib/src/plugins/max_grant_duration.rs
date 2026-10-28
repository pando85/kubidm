//! Kubidm: reject writing a `max_grant_duration` of 0.
//!
//! A cap of 0 seconds allows no time-bounded grant at all, which is never what an
//! administrator means, so a create or modify that writes it is rejected. This is not a
//! schema rule on purpose: released versions accepted 0, and schema rejects a value on
//! every path, so entries holding it could not be replicated or refreshed (they would
//! become conflict entries) and could not be modified locally either. Replication does not
//! run these hooks, and an entry that already holds 0 can still be modified as long as the
//! modify leaves the value as it is. A stored 0 is read as "no grants allowed", see
//! `server::time_bounded`.

use std::sync::Arc;

use crate::plugins::Plugin;
use crate::prelude::*;

pub struct MaxGrantDuration {}

impl Plugin for MaxGrantDuration {
    fn id() -> &'static str {
        "plugin_max_grant_duration"
    }

    #[instrument(
        level = "debug",
        name = "max_grant_duration_pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter()
            .try_for_each(|entry| Self::check(None, entry.get_ava_single_uint32(Self::ATTR)))
    }

    #[instrument(level = "debug", name = "max_grant_duration_pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(pre_cand, cand)
    }

    #[instrument(
        level = "debug",
        name = "max_grant_duration_pre_batch_modify",
        skip_all
    )]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(pre_cand, cand)
    }
}

impl MaxGrantDuration {
    const ATTR: Attribute = Attribute::MaxGrantDuration;

    fn modify(
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntryInvalidCommitted],
    ) -> Result<(), OperationError> {
        pre_cand
            .iter()
            .zip(cand.iter())
            .try_for_each(|(pre, post)| {
                Self::check(
                    pre.get_ava_single_uint32(Self::ATTR),
                    post.get_ava_single_uint32(Self::ATTR),
                )
            })
    }

    /// Reject `post` when it writes a cap of 0 that `pre` did not already hold.
    fn check(pre: Option<u32>, post: Option<u32>) -> Result<(), OperationError> {
        if post == Some(0) && pre != Some(0) {
            error!(
                "{} must be a positive number of seconds, 0 would allow no grant",
                Self::ATTR
            );
            Err(OperationError::SchemaViolation(
                SchemaError::InvalidAttributeSyntax(Self::ATTR.to_string()),
            ))
        } else {
            Ok(())
        }
    }
}
