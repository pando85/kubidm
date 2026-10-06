use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};
use kubidm_proto::v1::OutboundMessage;

#[derive(Debug, Clone)]
pub struct ValueSetMessage {
    message: OutboundMessage,
}

impl ValueSetMessage {
    pub fn new(message: OutboundMessage) -> Box<Self> {
        Box::new(ValueSetMessage { message })
    }
}

impl ValueSetT for ValueSetMessage {
    fn insert_checked(&mut self, _value: Value) -> Result<bool, OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn clear(&mut self) {
        debug_assert!(false);
    }

    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool {
        debug_assert!(false);
        false
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        1
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Message
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::empty())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKubidm::from(
            self.message.clone(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Message(self.message.clone())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::empty())
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::empty())
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_message() {
            &self.message == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, _other: &ValueSet) -> Result<(), OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn as_message(&self) -> Option<&OutboundMessage> {
        Some(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetMessage;
    use crate::prelude::ValueSet;
    use crate::valueset::from_db_valueset_v2;
    use kubidm_proto::v1::OutboundMessage;
    use time::OffsetDateTime;

    #[test]
    fn test_valueset_message_new() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test_user".to_string(),
        };
        let vs: ValueSet = ValueSetMessage::new(msg);
        assert_eq!(vs.len(), 1);
    }

    #[test]
    fn test_valueset_message_as_message() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test_user".to_string(),
        };
        let vs: ValueSet = ValueSetMessage::new(msg.clone());
        let retrieved = vs.as_message().expect("Expected message");
        assert_eq!(*retrieved, msg);
    }

    #[test]
    fn test_valueset_message_equal() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test_user".to_string(),
        };
        let vs1: ValueSet = ValueSetMessage::new(msg.clone());
        let vs2: ValueSet = ValueSetMessage::new(msg);
        assert!(vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_message_not_equal() {
        let msg1 = OutboundMessage::TestMessageV1 {
            display_name: "user_a".to_string(),
        };
        let msg2 = OutboundMessage::TestMessageV1 {
            display_name: "user_b".to_string(),
        };
        let vs1: ValueSet = ValueSetMessage::new(msg1);
        let vs2: ValueSet = ValueSetMessage::new(msg2);
        assert!(!vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_message_dbv2_roundtrip() {
        let msg = OutboundMessage::CredentialResetV1 {
            display_name: "test_user".to_string(),
            intent_id: "intent_123".to_string(),
            expiry_time: OffsetDateTime::UNIX_EPOCH,
        };
        let vs: ValueSet = ValueSetMessage::new(msg);
        let dbvs = vs.to_db_valueset_v2();
        let vs2 = from_db_valueset_v2(dbvs).expect("Failed to restore from db");
        assert!(vs.equal(&vs2));
    }

    #[test]
    fn test_valueset_message_syntax() {
        use crate::prelude::SyntaxType;
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test_user".to_string(),
        };
        let vs: ValueSet = ValueSetMessage::new(msg);
        assert_eq!(vs.syntax(), SyntaxType::Message);
    }

    #[test]
    fn test_valueset_message_contains_always_false() {
        let msg = OutboundMessage::TestMessageV1 {
            display_name: "test_user".to_string(),
        };
        let vs: ValueSet = ValueSetMessage::new(msg);
        assert!(!vs.contains(&crate::prelude::PartialValue::new_utf8s("anything")));
    }
}
