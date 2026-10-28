//! Kubidm: tests of `acp_receiver_pip_condition`, the PIP condition on the receiver of
//! an access control profile.

use std::sync::Arc;

use kubidm_proto::internal::{AuthorizationAction, AuthorizationDecision, AuthorizationRequest};

use super::profiles::{AccessControlProfile, AcpPipCondition};
use super::AccessControlsTransaction;
use crate::idm::pip::prefetch::PipPrefetchedAttributes;
use crate::prelude::*;

#[test]
fn test_pip_condition_parse() {
    let condition = AcpPipCondition::parse([
        "pip:hr:department=eng",
        "pip:hr:level=5",
        "pip:hr:department=platform",
        "pip:risk-v2.signals:score=low risk",
    ])
    .expect("valid condition");
    let names: Vec<&String> = condition.attribute_names().collect();
    assert_eq!(
        names,
        vec![
            "pip:hr:department",
            "pip:hr:level",
            "pip:risk-v2.signals:score"
        ]
    );

    // The value may contain '=' and ':' after the first '='.
    assert!(AcpPipCondition::parse(["pip:hr:token=a=b:c"]).is_ok());

    // Conditions are case-insensitive, like the attribute that stores them.
    assert_eq!(
        AcpPipCondition::parse(["PIP:HR:Department=Eng"]),
        AcpPipCondition::parse(["pip:hr:department=eng"])
    );
}

#[test]
fn test_pip_condition_parse_rejects_malformed() {
    for term in [
        // Not a pip attribute, or missing parts.
        "department=eng",
        "pip:hr=eng",
        "pip::department=eng",
        "pip:hr:=eng",
        "pip:hr:department",
        "pip:hr:department=",
        "=eng",
        "",
        // Invalid characters in the source or attribute.
        "pip:h r:department=eng",
        "pip:hr:dep artment=eng",
        "pip:hr:a:b=eng",
        // Control characters in the value.
        "pip:hr:department=eng\n",
    ] {
        assert!(
            AcpPipCondition::parse([term]).is_err(),
            "{term:?} must be rejected"
        );
    }

    // An empty condition is an error, not "always true".
    assert!(AcpPipCondition::parse(std::iter::empty()).is_err());
}

fn person(name: &str, uuid: Uuid) -> EntryInitNew {
    entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname(name)),
        (Attribute::DisplayName, Value::new_utf8s(name)),
        (Attribute::Uuid, Value::Uuid(uuid))
    )
}

fn search_acp(name: &str, uuid: Uuid, receiver: Uuid, target: &str) -> EntryInitNew {
    entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (
            Attribute::Class,
            EntryClass::AccessControlProfile.to_value()
        ),
        (
            Attribute::Class,
            EntryClass::AccessControlReceiverGroup.to_value()
        ),
        (
            Attribute::Class,
            EntryClass::AccessControlTargetScope.to_value()
        ),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname(name)),
        (Attribute::Uuid, Value::Uuid(uuid)),
        (Attribute::AcpReceiverGroup, Value::ReferN(receiver)),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(&format!("{{\"eq\":[\"name\",\"{target}\"]}}"))
                .expect("filter")
        ),
        (
            Attribute::AcpSearchAttr,
            Value::new_iutf8n(Attribute::Name.as_str())
        ),
        (
            Attribute::AcpSearchAttr,
            Value::new_iutf8n(Attribute::Class.as_str())
        ),
        (
            Attribute::AcpSearchAttr,
            Value::new_iutf8n(Attribute::Uuid.as_str())
        ),
        (
            Attribute::AcpModifyPresentAttr,
            Value::new_iutf8n(Attribute::DisplayName.as_str())
        ),
        (
            Attribute::AcpModifyRemovedAttr,
            Value::new_iutf8n(Attribute::DisplayName.as_str())
        )
    )
}

struct Fixture {
    reader: Uuid,
    target: Uuid,
}

const PIP_TARGET: &str = "pip_target";
const OTHER_TARGET: &str = "pip_other_target";

/// A reader, a target only reachable through a PIP-conditioned profile, and another
/// target reachable through a plain profile.
async fn setup(qs: &QueryServer) -> Fixture {
    let reader = Uuid::new_v4();
    let target = Uuid::new_v4();
    let other = Uuid::new_v4();
    let group = Uuid::new_v4();
    let pip_acp = Uuid::new_v4();
    let plain_acp = Uuid::new_v4();

    let mut qs_write = qs.write(duration_from_epoch_now()).await.expect("txn");

    let mut conditioned = search_acp("acp_pip_conditioned", pip_acp, group, PIP_TARGET);
    conditioned.add_ava(
        Attribute::AcpReceiverPipCondition,
        Value::new_iutf8n("pip:hr:department=eng"),
    );
    conditioned.add_ava(
        Attribute::AcpReceiverPipCondition,
        Value::new_iutf8n("pip:hr:level=5"),
    );

    qs_write
        .internal_create(vec![
            person("pip_reader", reader),
            person(PIP_TARGET, target),
            person(OTHER_TARGET, other),
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("pip_readers")),
                (Attribute::Uuid, Value::Uuid(group)),
                (Attribute::Member, Value::ReferN(reader))
            ),
            conditioned,
            search_acp("acp_pip_plain", plain_acp, group, OTHER_TARGET),
        ])
        .expect("failed to create entries");

    // The condition is parsed onto the profile ...
    let acp_entry = qs_write.internal_search_uuid(pip_acp).expect("acp");
    let acp = AccessControlProfile::try_from(&mut qs_write, &acp_entry).expect("acp parse");
    assert_eq!(
        acp.pip_condition,
        Some(AcpPipCondition::parse(["pip:hr:department=eng", "pip:hr:level=5"]).expect("parse"))
    );
    let plain_entry = qs_write.internal_search_uuid(plain_acp).expect("acp");
    let plain = AccessControlProfile::try_from(&mut qs_write, &plain_entry).expect("acp parse");
    assert_eq!(plain.pip_condition, None);

    qs_write.commit().expect("commit");

    Fixture { reader, target }
}

/// How many of the PIP target and the other target `pip` lets the reader find.
fn search_counts(
    qs_read: &mut QueryServerReadTransaction<'_>,
    fx: &Fixture,
    pip: Option<PipPrefetchedAttributes>,
) -> (usize, usize) {
    let reader = qs_read.internal_search_uuid(fx.reader).expect("reader");
    let ident =
        Identity::from_impersonate_entry_readonly(reader).with_pip_attributes(pip.map(Arc::new));
    let mut count = |name: &str| {
        let filter = filter!(f_eq(Attribute::Name, PartialValue::new_iname(name)));
        qs_read
            .impersonate_search(filter.clone(), filter, &ident)
            .expect("search failed")
            .len()
    };
    (count(PIP_TARGET), count(OTHER_TARGET))
}

#[qs_test]
async fn test_pip_condition_enforced(qs: &QueryServer) {
    let fx = setup(qs).await;
    let mut qs_read = qs.read().await.expect("txn");

    // The referenced attributes are collected when the profiles are loaded.
    assert_eq!(
        qs_read.get_accesscontrols().get_pip_referenced_attributes(),
        &btreeset!["pip:hr:department".to_string(), "pip:hr:level".to_string()]
    );

    let matching = PipPrefetchedAttributes::new(fx.reader)
        .with_value("pip:hr:department", "eng")
        .with_value("pip:hr:department", "platform")
        .with_value("pip:hr:level", "5")
        .with_value("pip:crm:tier", "gold");

    // All values match: granted. The plain profile is unaffected.
    assert_eq!(
        search_counts(&mut qs_read, &fx, Some(matching.clone())),
        (1, 1)
    );

    // Nothing prefetched (no PIP configured): not granted.
    assert_eq!(search_counts(&mut qs_read, &fx, None), (0, 1));

    // The prefetch failed (an errored, denied or timed out source contributes no
    // attributes): not granted.
    assert_eq!(
        search_counts(
            &mut qs_read,
            &fx,
            Some(PipPrefetchedAttributes::new(fx.reader))
        ),
        (0, 1)
    );

    // One attribute missing: not granted.
    let missing = PipPrefetchedAttributes::new(fx.reader).with_value("pip:hr:department", "eng");
    assert_eq!(search_counts(&mut qs_read, &fx, Some(missing)), (0, 1));

    // A different value: not granted.
    let different = PipPrefetchedAttributes::new(fx.reader)
        .with_value("pip:hr:department", "sales")
        .with_value("pip:hr:level", "5");
    assert_eq!(search_counts(&mut qs_read, &fx, Some(different)), (0, 1));

    // Names and values match case-insensitively.
    let other_case = PipPrefetchedAttributes::new(fx.reader)
        .with_value("pip:HR:Department", "ENG")
        .with_value("pip:hr:level", "5");
    assert_eq!(search_counts(&mut qs_read, &fx, Some(other_case)), (1, 1));

    // The same attribute from another source does not count.
    let other_source = PipPrefetchedAttributes::new(fx.reader)
        .with_value("pip:crm:department", "eng")
        .with_value("pip:hr:level", "5");
    assert_eq!(search_counts(&mut qs_read, &fx, Some(other_source)), (0, 1));

    // Attributes prefetched for another subject are never used.
    let mut wrong_subject = PipPrefetchedAttributes::new(fx.target);
    wrong_subject = wrong_subject
        .with_value("pip:hr:department", "eng")
        .with_value("pip:hr:level", "5");
    assert_eq!(
        search_counts(&mut qs_read, &fx, Some(wrong_subject)),
        (0, 1)
    );
}

/// The policy decision point evaluates with the same prefetched attributes, so that its
/// answers agree with the real operations.
#[qs_test]
async fn test_pip_condition_pdp_and_modify(qs: &QueryServer) {
    let fx = setup(qs).await;

    let matching = PipPrefetchedAttributes::new(fx.reader)
        .with_value("pip:hr:department", "eng")
        .with_value("pip:hr:level", "5");

    let request = |action| AuthorizationRequest {
        subject: None,
        resource: fx.target,
        action,
        attributes: Some(btreeset![Attribute::DisplayName.to_string()]),
        include_explanation: false,
    };

    let mut qs_read = qs.read().await.expect("txn");
    let reader = qs_read.internal_search_uuid(fx.reader).expect("reader");
    for (pip, allowed) in [(Some(matching.clone()), true), (None, false)] {
        let ident = Identity::from_impersonate_entry_readwrite(reader.clone())
            .with_pip_attributes(pip.map(Arc::new));
        let decision = crate::server::authorization::make_authorization_decision(
            &mut qs_read,
            &ident,
            &request(AuthorizationAction::Modify),
        )
        .map(|response| response.decision);
        if allowed {
            assert_eq!(decision, Ok(AuthorizationDecision::Allow));
        } else {
            // Without the condition the target is not even visible.
            assert_eq!(decision, Err(OperationError::NoMatchingEntries));
        }
    }
    drop(qs_read);

    // The real modify agrees.
    for (pip, allowed) in [(None, false), (Some(matching), true)] {
        let mut qs_write = qs.write(duration_from_epoch_now()).await.expect("txn");
        let reader = qs_write.internal_search_uuid(fx.reader).expect("reader");
        let ident = Identity::from_impersonate_entry_readwrite(reader)
            .with_pip_attributes(pip.map(Arc::new));
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(fx.target)));
        let result = qs_write.impersonate_modify(
            &filter,
            &filter,
            &ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("renamed")),
            &ident,
        );
        assert_eq!(result.is_ok(), allowed, "{result:?}");
    }
}

#[qs_test]
async fn test_pip_condition_malformed_rejected(qs: &QueryServer) {
    let group = Uuid::new_v4();
    let mut qs_write = qs.write(duration_from_epoch_now()).await.expect("txn");
    qs_write
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("pip_readers")),
            (Attribute::Uuid, Value::Uuid(group))
        )])
        .expect("create group");

    let mut acp = search_acp("acp_pip_malformed", Uuid::new_v4(), group, PIP_TARGET);
    acp.add_ava(
        Attribute::AcpReceiverPipCondition,
        Value::new_iutf8n("department=eng"),
    );
    // The profiles are reloaded, and the invalid one rejected, at commit.
    qs_write.internal_create(vec![acp]).expect("create");
    assert!(matches!(
        qs_write.commit(),
        Err(OperationError::InvalidAcpState(err)) if err.contains("acp_receiver_pip_condition")
    ));
}

/// Without PIP conditions nothing is referenced, so no request prefetches anything.
#[qs_test]
async fn test_pip_no_conditions_nothing_referenced(qs: &QueryServer) {
    let qs_read = qs.read().await.expect("txn");
    assert!(qs_read
        .get_accesscontrols()
        .get_pip_referenced_attributes()
        .is_empty());
}
