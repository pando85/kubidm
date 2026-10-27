use crate::{
    maintenance::{QueryServerMaintenanceWriteFence, ReplicationFence},
    prelude::*,
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
    pub fn maintenance_verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        self.verify()
    }
}
