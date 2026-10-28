use crate::{
    maintenance::{QueryServerMaintenanceWriteFence, ReplicationFence},
    prelude::*,
    status::DatabaseCheck,
    valueset::{ValueSetDateTime, ValueSetEmailAddress, ValueSetIutf8N, ValueSetMessage},
};
use kubidm_proto::internal::ConsistencyError;
use kubidm_proto::v1::OutboundMessage;

impl<'a> QueryServerWriteTransaction<'a> {
    pub(crate) fn queue_message(
        &mut self,
        ident: &Identity,
        message: OutboundMessage,
        to_address: String,
    ) -> Result<Uuid, OperationError> {
        let curtime_odt = self.get_curtime_odt();
        let delete_after_odt = curtime_odt + DEFAULT_MESSAGE_RETENTION;

        let message_uuid = Uuid::new_v4();

        let e_msg = EntryInitNew::from_iter([
            (
                Attribute::Class,
                ValueSetIutf8N::new(EntryClass::OutboundMessage.into()) as ValueSet,
            ),
            (Attribute::Uuid, ValueSetUuid::new(message_uuid)),
            (Attribute::SendAfter, ValueSetDateTime::new(curtime_odt)),
            (
                Attribute::DeleteAfter,
                ValueSetDateTime::new(delete_after_odt),
            ),
            (Attribute::MessageTemplate, ValueSetMessage::new(message)),
            (
                Attribute::MailDestination,
                ValueSetEmailAddress::new(to_address),
            ),
        ]);

        self.impersonate_create(ident, vec![e_msg]).map(|()| {
            debug!(?message_uuid, "Queued");
            message_uuid
        })
    }

    /// Consume a normal QueryServer write transaction but retain only its single
    /// writer permit. Every other transaction/cache guard is dropped immediately.
    ///
    /// This is the node-drain primitive: reads remain possible (including
    /// replication supplier reads), while all new local/replication writes queue
    /// behind the returned RAII fence.
    pub fn into_maintenance_write_fence(self) -> QueryServerMaintenanceWriteFence<'a> {
        QueryServerMaintenanceWriteFence::new(self._write_ticket)
    }
}

impl QueryServerReadTransaction<'_> {
    /// Capture the current replication history as an opaque handoff fence.
    pub fn maintenance_replication_fence(&mut self) -> Result<ReplicationFence, OperationError> {
        self.consumer_get_state()
            .map(ReplicationFence::from_ruv_range)
    }

    /// Run the normal full QueryServer consistency verification without the
    /// process-exiting behaviour of the offline CLI helper.
    ///
    /// Kubidm: the result is recorded as the database health of the server: errors make
    /// it unhealthy (not ready) until a later verification is clean.
    pub fn maintenance_verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        let results = self.verify();
        if results.iter().all(Result::is_ok) {
            self.health.mark_database_healthy(DatabaseCheck::Verify);
        } else {
            self.health.mark_database_failure(DatabaseCheck::Verify);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::status::{DatabaseCheck, DatabaseHealth};

    /// Replace the memberof attributes of `uuid` behind the back of the plugins.
    fn set_memberof_unchecked(
        server_txn: &mut QueryServerWriteTransaction,
        uuid: Uuid,
        memberof: Option<&(ValueSet, ValueSet)>,
    ) -> Option<(ValueSet, ValueSet)> {
        let mut work_set = server_txn
            .internal_search_writeable(&filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))))
            .expect("Unable to search the entry");
        let mut previous = None;
        for (pre, entry) in work_set.iter_mut() {
            previous = pre
                .get_ava_set(Attribute::MemberOf)
                .cloned()
                .zip(pre.get_ava_set(Attribute::DirectMemberOf).cloned());
            entry.purge_ava(Attribute::MemberOf);
            entry.purge_ava(Attribute::DirectMemberOf);
            if let Some((mo, dmo)) = memberof {
                entry.set_ava_set(&Attribute::MemberOf, mo.clone());
                entry.set_ava_set(&Attribute::DirectMemberOf, dmo.clone());
            }
        }
        server_txn
            .internal_apply_writable(work_set)
            .expect("Unable to apply the entry");
        previous
    }

    #[qs_test]
    async fn test_maintenance_verify_records_database_health(server: &QueryServer) {
        let person_uuid = Uuid::new_v4();
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        server_txn
            .internal_create(vec![
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Account.to_value()),
                    (Attribute::Class, EntryClass::Person.to_value()),
                    (Attribute::Name, Value::new_iname("testperson1")),
                    (Attribute::Uuid, Value::Uuid(person_uuid)),
                    (Attribute::DisplayName, Value::new_utf8s("testperson1"))
                ),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Group.to_value()),
                    (Attribute::Name, Value::new_iname("testgroup1")),
                    (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
                    (Attribute::Member, Value::ReferN(person_uuid))
                ),
            ])
            .unwrap();
        server_txn.commit().unwrap();

        let mut server_read = server.read().await.unwrap();
        assert!(server_read.maintenance_verify().iter().all(Result::is_ok));
        drop(server_read);
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Healthy
        );

        // Corrupt the derived memberof of the person: the verification finds it and the
        // database is unhealthy.
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let original = set_memberof_unchecked(&mut server_txn, person_uuid, None);
        assert!(original.is_some());
        server_txn.commit().unwrap();

        let mut server_read = server.read().await.unwrap();
        assert!(server_read.maintenance_verify().iter().any(Result::is_err));
        drop(server_read);
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Unhealthy
        );

        // A successful write does not prove the corruption is gone.
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        set_memberof_unchecked(&mut server_txn, person_uuid, original.as_ref());
        server_txn.commit().unwrap();
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Unhealthy
        );

        // The next clean verification does.
        let mut server_read = server.read().await.unwrap();
        assert!(server_read.maintenance_verify().iter().all(Result::is_ok));
        drop(server_read);
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Healthy
        );
    }

    #[qs_test]
    async fn test_commit_success_recovers_database_health(server: &QueryServer) {
        server.health().mark_database_failure(DatabaseCheck::Commit);
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Unhealthy
        );

        // An aborted write transaction is not a recovery.
        let server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        drop(server_txn);
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Unhealthy
        );

        let server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        server_txn.commit().unwrap();
        assert_eq!(
            server.health().get_database_health(),
            DatabaseHealth::Healthy
        );
    }
}
