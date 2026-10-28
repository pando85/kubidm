//! This module contains the server's async tasks that are called from the various frontend
//! components to conduct operations. These are separated based on protocol versions and
//! if they are read or write transactions internally.

use kubidmd_lib::idm::{ldap::LdapServer, pip::prefetch::PipPrefetcher, server::IdmServer};
use std::sync::Arc;

pub struct QueryServerReadV1 {
    pub(crate) idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
    /// Kubidm: prefetches the PIP attributes that access control profiles reference,
    /// before each request's transaction. `None` when no PIP is configured.
    pip: Option<Arc<PipPrefetcher>>,
}

impl QueryServerReadV1 {
    pub fn new(
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
        pip: Option<Arc<PipPrefetcher>>,
    ) -> Self {
        debug!("Starting query server read worker ...");
        QueryServerReadV1 { idms, ldap, pip }
    }

    pub fn start_static(
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
        pip: Option<Arc<PipPrefetcher>>,
    ) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(idms, ldap, pip));

        let x_ref = Box::leak(x);
        &(*x_ref)
    }
}

pub struct QueryServerWriteV1 {
    pub(crate) idms: Arc<IdmServer>,
}

impl QueryServerWriteV1 {
    pub fn new(idms: Arc<IdmServer>) -> Self {
        debug!("Starting a query server write worker ...");
        QueryServerWriteV1 { idms }
    }

    pub fn start_static(idms: Arc<IdmServer>) -> &'static QueryServerWriteV1 {
        let x = Box::new(QueryServerWriteV1::new(idms));

        let x_ptr = Box::leak(x);
        &(*x_ptr)
    }
}

pub mod internal;
#[cfg(test)]
mod pip_tests;
pub mod v1_read;
pub mod v1_scim;
pub mod v1_write;
pub mod write_action;
