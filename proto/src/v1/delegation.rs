//! Kubidm: template driven delegated administration.
//!
//! A delegation grants the members of a receiver group a fixed set of rights, defined by a
//! built-in template, over the members of a scope group. See the book chapter on delegated
//! administration.

use crate::internal::Filter as ProtoFilter;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Grant a delegation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct DelegationGrantRequest {
    /// The template to grant: `helpdesk`, `user_admin` or `group_admin` (the name of the
    /// template's `delegated_role` entry, such as `idm_delegated_helpdesk`, is accepted too).
    pub template: String,
    /// The name, spn or uuid of the group whose members receive the rights.
    pub receiver: String,
    /// The name, spn or uuid of the group whose members the rights apply to.
    pub scope: String,
    /// An optional filter that further narrows the scope. It can only narrow it: the
    /// targets always are members of the scope group, and never high privilege.
    #[serde(default)]
    pub filter: Option<ProtoFilter>,
}

/// A group a delegation refers to.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct DelegationGroup {
    pub uuid: Uuid,
    /// `None` if the group no longer resolves to a name.
    pub spn: Option<String>,
}

/// A delegation, as granted from a template.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct DelegationGrant {
    /// The uuid of the access control profile that implements the delegation.
    pub uuid: Uuid,
    /// The name of the access control profile,
    /// `delegation_<template>_<scope uuid>_<receiver uuid>` (the low 64 bits of each).
    pub name: String,
    /// The template the delegation was granted from, `None` if it is not a known template.
    pub template: Option<String>,
    /// The receiver groups. A delegation granted from a template has exactly one, more
    /// are reported as drift.
    pub receivers: Vec<DelegationGroup>,
    /// The scope group, `None` once it has been deleted (the delegation then grants
    /// nothing).
    pub scope: Option<DelegationGroup>,
    /// The filter that narrows the scope, as stored: references to entries are UUIDs.
    pub filter: Option<ProtoFilter>,
    /// Who granted the delegation, `None` once they have been deleted.
    pub delegated_by: Option<DelegationGroup>,
    /// Whether the access control profile is enabled.
    pub enabled: bool,
    /// How the access control profile differs from what its template grants, if at all.
    /// Empty when it matches the template.
    pub drift: Vec<String>,
}
