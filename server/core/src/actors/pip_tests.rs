//! Kubidm: the PIP prefetch of the request path, against a local HTTP PIP source.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use kubidm_proto::internal::{
    AuthorizationAction, AuthorizationDecision, AuthorizationRequest, Filter as ProtoFilter,
    SearchRequest,
};
use kubidmd_lib::entry::{Entry, EntryInit, EntryNew};
use kubidmd_lib::entry_init;
use kubidmd_lib::idm::ldap::{LdapResponseState, LdapServer};
use kubidmd_lib::idm::pip::config::{
    HttpMethod, HttpPipConfig, PipConfig, PipFallbackBehavior, PipHealthCheckConfig,
    PipSourceConfig, PipTlsConfig,
};
use kubidmd_lib::idm::pip::prefetch::PipPrefetcher;
use kubidmd_lib::idm::server::IdmServerTransaction;
use kubidmd_lib::idm::serviceaccount::GenerateApiTokenEvent;
use kubidmd_lib::prelude::*;
use kubidmd_lib::testkit::{setup_idm_test, TestConfiguration};
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapFilter, LdapMsg, LdapOp,
    LdapSearchRequest, LdapSearchScope,
};

use super::QueryServerReadV1;
use compact_jwt::JwsCompact;

const PIP_TARGET: &str = "pip_target";
const OTHER_TARGET: &str = "pip_other_target";
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A local HTTP PIP source that answers every request with `body`, and records the
/// request lines it saw.
fn serve(body: &'static str) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_thread = seen.clone();
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            if let Some(line) = head.lines().next() {
                if let Ok(mut seen) = seen_thread.lock() {
                    seen.push(line.to_string());
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
        }
    });
    (Url::parse(&format!("http://{addr}")).expect("url"), seen)
}

/// An address on which nothing listens.
fn refused_url() -> Url {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    Url::parse(&format!("http://{addr}")).expect("url")
}

fn prefetcher(base_url: Url) -> Option<Arc<PipPrefetcher>> {
    let config = PipConfig {
        sources: vec![PipSourceConfig::Http(HttpPipConfig {
            id: "hr".to_string(),
            base_url,
            endpoint_path: "/users/{username}".to_string(),
            method: HttpMethod::Get,
            auth: None,
            tls: PipTlsConfig {
                allow_insecure: true,
                ..PipTlsConfig::default()
            },
            timeout_secs: 5,
            cache_ttl_secs: 60,
            headers: BTreeMap::new(),
            fallback_behavior: PipFallbackBehavior::Deny,
            fallback_values: BTreeMap::new(),
            health_check: PipHealthCheckConfig::default(),
            health_check_path: None,
            provided_attributes: vec!["department".to_string()],
        })],
        enabled: true,
        prefetch_timeout_ms: 2000,
    };
    PipPrefetcher::from_config(&config)
        .expect("valid pip config")
        .map(Arc::new)
}

fn person(name: &str, uuid: Uuid) -> Entry<EntryInit, EntryNew> {
    entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname(name)),
        (Attribute::DisplayName, Value::new_utf8s(name)),
        (Attribute::Uuid, Value::Uuid(uuid))
    )
}

fn acp(name: &str, receiver: Uuid, target: &str) -> Entry<EntryInit, EntryNew> {
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
    idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
    token: JwsCompact,
    pip_target: Uuid,
    other_target: Uuid,
}

/// A service account (with an api token) in a group that receives a profile conditioned
/// on `pip:hr:department=eng` for one target, and a plain profile for another target.
async fn setup() -> Fixture {
    let (idms, _idms_delayed, _idms_audit) = setup_idm_test(TestConfiguration::default()).await;
    let idms = Arc::new(idms);
    let ldap = Arc::new(LdapServer::new(&idms).await.expect("ldap server"));

    let svc = Uuid::new_v4();
    let group = Uuid::new_v4();
    let pip_target = Uuid::new_v4();
    let other_target = Uuid::new_v4();

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await.expect("write txn");

    let mut conditioned = acp("acp_pip_conditioned", group, PIP_TARGET);
    conditioned.add_ava(
        Attribute::AcpReceiverPipCondition,
        Value::new_iutf8n("pip:HR:Department=Eng"),
    );

    idms_prox_write
        .qs_write
        .internal_create(vec![
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Name, Value::new_iname("pip_svc")),
                (Attribute::DisplayName, Value::new_utf8s("pip_svc")),
                (Attribute::EntryManagedBy, Value::Refer(svc)),
                (Attribute::Uuid, Value::Uuid(svc))
            ),
            person(PIP_TARGET, pip_target),
            person(OTHER_TARGET, other_target),
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("pip_readers")),
                (Attribute::Uuid, Value::Uuid(group)),
                (Attribute::Member, Value::ReferN(svc))
            ),
            conditioned,
            acp("acp_pip_plain", group, OTHER_TARGET),
        ])
        .expect("create entries");

    let svc_entry = idms_prox_write
        .qs_write
        .internal_search_uuid(svc)
        .expect("service account");
    let token = idms_prox_write
        .service_account_generate_api_token(
            &GenerateApiTokenEvent {
                ident: Identity::from_impersonate_entry_readwrite(svc_entry),
                target: svc,
                label: "pip".to_string(),
                expiry: None,
                read_write: true,
                compact: false,
            },
            ct,
        )
        .expect("api token");
    idms_prox_write.commit().expect("commit");

    Fixture {
        idms,
        ldap,
        token,
        pip_target,
        other_target,
    }
}

impl Fixture {
    fn actor(&self, pip: Option<Arc<PipPrefetcher>>) -> QueryServerReadV1 {
        QueryServerReadV1::new(self.idms.clone(), self.ldap.clone(), pip)
    }

    /// The request path of the HTTP extractor: pre-validation (and PIP prefetch).
    async fn client_auth_info(&self, actor: &QueryServerReadV1) -> ClientAuthInfo {
        let mut client_auth_info = ClientAuthInfo::new(
            Source::Https(LOCALHOST),
            None,
            Some(self.token.clone()),
            None,
        );
        actor
            .pre_validate_client_auth_info(&mut client_auth_info)
            .await
            .expect("pre-validate");
        client_auth_info
    }

    /// Whether the PIP target and the other target are found by a v1 search.
    async fn search(&self, actor: &QueryServerReadV1) -> (bool, bool) {
        let mut found = Vec::new();
        for name in [PIP_TARGET, OTHER_TARGET] {
            let client_auth_info = self.client_auth_info(actor).await;
            let response = actor
                .handle_search(
                    client_auth_info,
                    SearchRequest {
                        filter: ProtoFilter::Eq(Attribute::Name.to_string(), name.to_string()),
                    },
                    Uuid::new_v4(),
                )
                .await
                .expect("search");
            found.push(response.entries.len() == 1);
        }
        (found[0], found[1])
    }

    /// Whether `/v1/authorize` allows modifying the display name of `resource`.
    async fn authorize(&self, actor: &QueryServerReadV1, resource: Uuid) -> bool {
        let client_auth_info = self.client_auth_info(actor).await;
        let response = actor
            .handle_authorization_request(
                client_auth_info,
                AuthorizationRequest {
                    subject: None,
                    resource,
                    action: AuthorizationAction::Modify,
                    attributes: Some([Attribute::DisplayName.to_string()].into()),
                    include_explanation: false,
                },
                Uuid::new_v4(),
            )
            .await;
        matches!(response, Ok(r) if r.decision == AuthorizationDecision::Allow)
    }

    /// Whether the PIP target and the other target are found by an LDAP search of a
    /// session bound with the api token.
    async fn ldap_search(&self, actor: &QueryServerReadV1) -> (bool, bool) {
        let bind = LdapMsg {
            msgid: 1,
            op: LdapOp::BindRequest(LdapBindRequest {
                version: 3,
                dn: "dn=token".to_string(),
                cred: LdapBindCred::Simple(self.token.to_string()),
            }),
            ctrl: Vec::new(),
        };
        let uat = match actor
            .handle_ldaprequest(Uuid::new_v4(), bind, None, LOCALHOST)
            .await
        {
            Some(LdapResponseState::Bind(uat, _)) => uat,
            _ => panic!("ldap bind failed"),
        };
        // A bind never carries PIP attributes: they are per operation.
        assert!(uat.pip_attributes.is_none());

        let mut found = Vec::new();
        for name in [PIP_TARGET, OTHER_TARGET] {
            let search = LdapMsg {
                msgid: 2,
                op: LdapOp::SearchRequest(LdapSearchRequest {
                    base: "dc=example,dc=com".to_string(),
                    scope: LdapSearchScope::Subtree,
                    aliases: LdapDerefAliases::Never,
                    sizelimit: 0,
                    timelimit: 0,
                    typesonly: false,
                    filter: LdapFilter::Equality(Attribute::Name.to_string(), name.to_string()),
                    attrs: vec![Attribute::Name.to_string()],
                }),
                ctrl: Vec::new(),
            };
            let entries = match actor
                .handle_ldaprequest(Uuid::new_v4(), search, Some(uat.clone()), LOCALHOST)
                .await
            {
                Some(LdapResponseState::MultiPartResponse(msgs)) => msgs
                    .iter()
                    .filter(|msg| matches!(msg.op, LdapOp::SearchResultEntry(_)))
                    .count(),
                _ => panic!("ldap search failed"),
            };
            found.push(entries == 1);
        }
        (found[0], found[1])
    }
}

#[tokio::test]
async fn test_pip_prefetch_matching_grants_access() {
    let fx = setup().await;
    let (url, seen) = serve(r#"{"department": "eng"}"#);
    let actor = fx.actor(prefetcher(url));

    // v1 search: the conditioned profile and the plain one both apply.
    assert_eq!(fx.search(&actor).await, (true, true));
    // The PDP evaluates with the same prefetched attributes.
    assert!(fx.authorize(&actor, fx.pip_target).await);
    assert!(fx.authorize(&actor, fx.other_target).await);
    // LDAP search, prefetched per operation.
    assert_eq!(fx.ldap_search(&actor).await, (true, true));

    // The source was queried for the authenticated subject.
    let seen = seen.lock().expect("lock").clone();
    assert!(!seen.is_empty());
    assert!(seen
        .iter()
        .all(|line| line.starts_with("GET /users/pip_svc ")));
}

#[tokio::test]
async fn test_pip_prefetch_other_value_denies() {
    let fx = setup().await;
    let (url, _seen) = serve(r#"{"department": "sales"}"#);
    let actor = fx.actor(prefetcher(url));

    assert_eq!(fx.search(&actor).await, (false, true));
    assert!(!fx.authorize(&actor, fx.pip_target).await);
    assert!(fx.authorize(&actor, fx.other_target).await);
    assert_eq!(fx.ldap_search(&actor).await, (false, true));
}

#[tokio::test]
async fn test_pip_prefetch_source_down_fails_closed() {
    let fx = setup().await;
    // The source is down and configured with `fallback_behavior = "deny"`.
    let actor = fx.actor(prefetcher(refused_url()));

    // No access through the conditioned profile, every other profile still applies.
    assert_eq!(fx.search(&actor).await, (false, true));
    assert!(!fx.authorize(&actor, fx.pip_target).await);
    assert!(fx.authorize(&actor, fx.other_target).await);
    assert_eq!(fx.ldap_search(&actor).await, (false, true));
}

#[tokio::test]
async fn test_pip_not_configured() {
    let fx = setup().await;
    let actor = fx.actor(None);

    // Nothing is prefetched ...
    let client_auth_info = fx.client_auth_info(&actor).await;
    let mut idms_prox_read = fx.idms.proxy_read().await.expect("read txn");
    let ident = idms_prox_read
        .validate_client_auth_info_to_ident(client_auth_info, duration_from_epoch_now())
        .expect("ident");
    assert!(ident.pip_attributes().is_none());
    drop(idms_prox_read);

    // ... so the conditioned profile never matches, and the rest is unchanged.
    assert_eq!(fx.search(&actor).await, (false, true));
    assert!(!fx.authorize(&actor, fx.pip_target).await);
    assert!(fx.authorize(&actor, fx.other_target).await);
    assert_eq!(fx.ldap_search(&actor).await, (false, true));
}
