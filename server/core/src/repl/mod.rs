use self::codec::{ConsumerRequest, SupplierResponse};
use crate::CoreAction;
use config::{RepNodeConfig, ReplicationConfiguration};
use crypto_glue::{traits::EncodeDer, x509::Certificate};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use kubidmd_lib::maintenance::{
    maintenance_state, with_maintenance_write_bypass, MaintenanceState,
};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::prelude::IdmServer;
use kubidmd_lib::repl::proto::{ConsumerState, ReplIncrementalContext};
use kubidmd_lib::server::QueryServerTransaction;
use kubidmd_lib::status::{tracker_now, ReplicationStartup, ReplicationStateTracker};
use rustls::{
    client::ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::{ServerConfig, WebPkiClientVerifier},
    RootCertStore,
};
use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, oneshot, Mutex, MutexGuard},
    task::JoinHandle,
    time::{interval, sleep, timeout, Instant},
};
use tokio_rustls::{client::TlsStream, TlsAcceptor, TlsConnector};
use tokio_util::codec::{Framed, FramedRead, FramedWrite};
use tracing::{error, Instrument};
use url::Url;
use uuid::Uuid;

mod codec;
pub(crate) mod config;

pub(crate) enum ReplCtrl {
    GetCertificate {
        respond: oneshot::Sender<Certificate>,
    },
    RenewCertificate {
        respond: oneshot::Sender<bool>,
    },
    /// Refresh this node from a supplier: from the supplier `from` (its origin, matched as
    /// [`peer_label`] names it) when given, otherwise from the first supplier task that
    /// takes the refresh. `Err` when `from` names no configured supplier. A refresh that
    /// has not started by `start_deadline`, or whose receiver was dropped (the requester
    /// gave up), is not run. The receiver gets [`RefreshProgress::Started`] as soon as a
    /// task has started the refresh, then [`RefreshProgress::Done`] once it was applied.
    RefreshConsumer {
        from: Option<String>,
        start_deadline: Instant,
        respond: oneshot::Sender<Result<mpsc::Receiver<RefreshProgress>, String>>,
    },
}

/// What the supplier task that runs a refresh reports to the requester of the refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefreshProgress {
    /// A task claimed the refresh and runs it now, from the supplier `supplier` (named as
    /// [`peer_label`] names it). From here on the requester waits for the outcome, however
    /// long it takes. If that task fails, another one may claim the refresh again before
    /// its start deadline, and report this again.
    Started { supplier: String },
    /// The refresh was applied.
    Done,
}

/// Whether a refresh is done, and the channel to its requester. Every supplier task that
/// may run the refresh shares it, and the one that holds the lock runs it.
pub(crate) type RefreshCoord = Mutex<(bool, mpsc::Sender<RefreshProgress>)>;

#[derive(Debug, Clone)]
enum ReplConsumerCtrl {
    Stop,
    /// Refresh this node. Every supplier task receives it, and the first one that takes the
    /// lock runs it, unless `from` restricts it to the task of one supplier (named as
    /// [`peer_label`] names it).
    ///
    /// A manual refresh carries a `start_deadline`: unless a task has reported that it
    /// started the refresh by then, the requester stops waiting for it, so a task that only
    /// gets to it later (its supplier unreachable, the task busy) must not run it then. It
    /// is also dropped once its receiver is gone. An automatic refresh has no deadline, and
    /// its receiver lives until the refresh is done.
    Refresh {
        refresh_coord: Arc<RefreshCoord>,
        from: Option<String>,
        start_deadline: Option<Instant>,
    },
}

/// Take the refresh lock of `refresh_coord`, and keep it only when the refresh must run
/// now: not done yet by another task, still awaited by its requester (its receiver is not
/// dropped), and not past its `start_deadline`. The requester is then told that the task of
/// `supplier` started it, so that it waits for the outcome rather than give up at the
/// deadline while the refresh still runs.
pub(crate) async fn claim_refresh<'a>(
    refresh_coord: &'a RefreshCoord,
    start_deadline: Option<Instant>,
    supplier: &str,
) -> Option<MutexGuard<'a, (bool, mpsc::Sender<RefreshProgress>)>> {
    // Every replication consumer *should* end up here behind this lock, but only one can
    // proceed. This is what we want!
    let refresh_coord_guard = refresh_coord.lock().await;

    // Simple case - task is already done.
    if refresh_coord_guard.0 {
        trace!("Refresh already completed by another task, return.");
        return None;
    }

    // The requester gave up: running it now would refresh this node long after the
    // operator was told it failed, from a supplier that may since have changed.
    if refresh_coord_guard.1.is_closed() {
        warn!("Refresh was abandoned by its requester before it could start, not refreshing.");
        return None;
    }
    if start_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        warn!("Refresh could not start before its deadline, not refreshing.");
        return None;
    }

    // The channel only waits on the requester when an earlier task reported its start and
    // failed before the requester read that report. A requester that gives up meanwhile
    // closes the channel, which ends the wait.
    let started = RefreshProgress::Started {
        supplier: supplier.to_string(),
    };
    if refresh_coord_guard.1.send(started).await.is_err() {
        warn!("Refresh was abandoned by its requester before it could start, not refreshing.");
        return None;
    }

    Some(refresh_coord_guard)
}

/// The address a supplier task tries first after a refresh `outcome`: the one the refresh
/// used, none after a failure, and the previous one when the task did not run the refresh.
fn address_after_refresh(
    previous: Option<SocketAddr>,
    outcome: Result<Option<SocketAddr>, ()>,
) -> Option<SocketAddr> {
    match outcome {
        Ok(Some(addr)) => Some(addr),
        Ok(None) => previous,
        Err(()) => None,
    }
}

/// Whether the replication task of the supplier `peer_url` may run a refresh restricted to
/// the supplier `from` (any supplier when `None`).
fn refresh_is_for_peer(from: Option<&str>, peer_url: &str) -> bool {
    from.is_none_or(|from| from == peer_url)
}

/// The supplier a manual refresh asked for with `--from`, named as [`peer_label`] names it.
/// `Err` is a message for the operator: the origin is not a URL, is not a configured
/// supplier (`pull` or `mutual-pull`) of this node, or matches more than one of them.
fn refresh_source(repl_config: &ReplicationConfiguration, from: &str) -> Result<String, String> {
    // Origins that differ only in their path name the same supplier.
    let suppliers: BTreeSet<String> = repl_config
        .manual
        .iter()
        .filter(|(_, node)| !matches!(node, RepNodeConfig::AllowPull { .. }))
        .map(|(origin, _)| peer_label(origin))
        .collect();

    // Host names are not case sensitive, but the url crate keeps the case of the host of a
    // `repl://` url: compare without it, and name the supplier as its task does.
    let found: Vec<&String> = match Url::parse(from.trim()) {
        Ok(origin) => {
            let wanted = peer_label(&origin);
            suppliers
                .iter()
                .filter(|supplier| supplier.eq_ignore_ascii_case(&wanted))
                .collect()
        }
        Err(_) => Vec::new(),
    };
    match found.as_slice() {
        [supplier] => Ok((*supplier).clone()),
        [] => Err(format!(
            "'{from}' is not a replication supplier of this node, refusing to refresh. The \
             configured suppliers (pull or mutual-pull) are: [{}]",
            suppliers.iter().cloned().collect::<Vec<_>>().join(", ")
        )),
        // Configured more than once, with the host in another case: each is its own
        // replication task, and which one the operator means can not be told.
        matches => Err(format!(
            "'{from}' matches more than one replication supplier of this node, refusing to \
             refresh. Matching suppliers: [{}]. Configure each supplier once.",
            matches
                .iter()
                .map(|supplier| supplier.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(crate) struct ReplicationServerHandles {
    pub repl_handle: tokio::task::JoinHandle<()>,
    pub ctrl_tx: mpsc::Sender<ReplCtrl>,
}

/// The name of a replication peer in the health tracker: its origin without any path.
fn peer_label(origin: &Url) -> String {
    format!(
        "{}://{}{}",
        origin.scheme(),
        origin.host_str().unwrap_or("unknown"),
        origin.port().map(|p| format!(":{}", p)).unwrap_or_default()
    )
}

/// The clock of the health tracker.
fn now_secs() -> u64 {
    tracker_now()
}

/// The peers this node pulls from, as named in the health tracker, and whether any of them
/// is configured with `automatic_refresh`.
fn supplier_peers(repl_config: &ReplicationConfiguration) -> (Vec<String>, bool) {
    let mut automatic = false;
    let peers = repl_config
        .manual
        .iter()
        .filter_map(|(origin, node)| match node {
            RepNodeConfig::Pull {
                automatic_refresh, ..
            }
            | RepNodeConfig::MutualPull {
                automatic_refresh, ..
            } => {
                if origin.domain().is_none() {
                    warn!(
                        "Replication supplier {origin} is not configured by DNS name. Replication \
                         requires a DNS name for the TLS certificate check, so this peer will \
                         never replicate and is reported as stale."
                    );
                }
                automatic |= *automatic_refresh;
                Some(peer_label(origin))
            }
            RepNodeConfig::AllowPull { .. } => None,
        })
        .collect();
    (peers, automatic)
}

/// What the health tracker needs to know about replication at startup. The supplier
/// peers are the `pull` and `mutual-pull` nodes: `allow-pull` nodes only pull from us.
/// Whether this node has synced before only matters when a supplier is configured with
/// `automatic_refresh`. It comes from the database; when that can not be read the node is
/// treated as never synced for readiness, so it stays not ready until its first successful
/// sync rather than serving content it can not vouch for. It is however treated as holding
/// replicated content by the domain mismatch guard, see [`startup_sync_state`].
pub(crate) async fn replication_startup(
    repl_config: &ReplicationConfiguration,
    idms: &IdmServer,
) -> ReplicationStartup {
    let (supplier_peers, automatic_refresh) = supplier_peers(repl_config);

    let (has_synced, sync_evidence) = if automatic_refresh {
        startup_sync_state(idms.replication_has_synced().await)
    } else {
        (false, false)
    };

    ReplicationStartup {
        supplier_peers,
        automatic_refresh,
        poll_interval: repl_config.get_task_poll_interval(),
        has_synced,
        sync_evidence,
    }
}

/// Whether this node has synced before, for readiness and for the domain mismatch guard,
/// from the result of reading it from the database. An error is no proof of a sync, so the
/// node is not ready until its first sync, but no proof of an empty node either: the guard
/// must never let a peer in another domain replace content this node may hold.
fn startup_sync_state<E: std::fmt::Debug>(has_synced: Result<bool, E>) -> (bool, bool) {
    match has_synced {
        Ok(has_synced) => (has_synced, has_synced),
        Err(err) => {
            error!(
                ?err,
                "Unable to read the replication state of the database. This node is treated \
                 as never synced, so it is not ready until its first successful sync, and \
                 as holding replicated content, so it is never refreshed automatically from \
                 a peer in another domain."
            );
            (false, true)
        }
    }
}

pub(crate) async fn create_repl_server(
    idms: Arc<IdmServer>,
    repl_config: &ReplicationConfiguration,
    rx: broadcast::Receiver<CoreAction>,
    tracker: ReplicationStateTracker,
) -> Result<ReplicationServerHandles, ()> {
    // We need to start the tcp listener. This will persist over ssl reloads!
    let listener = TcpListener::bind(&repl_config.bindaddress)
        .await
        .map_err(|e| {
            error!(
                "Could not bind to replication address {} -> {:?}",
                repl_config.bindaddress, e
            );
        })?;

    // Create the control channel. Use a low msg count, there won't be that much going on.
    let (ctrl_tx, ctrl_rx) = mpsc::channel(4);

    // We need to start the tcp listener. This will persist over ssl reloads!
    info!(
        "Starting replication interface https://{} ...",
        repl_config.bindaddress
    );

    let repl_handle: JoinHandle<()> = tokio::spawn(repl_acceptor(
        listener,
        idms,
        repl_config.clone(),
        rx,
        ctrl_rx,
        tracker,
    ));

    info!("Created replication interface");
    Ok(ReplicationServerHandles {
        repl_handle,
        ctrl_tx,
    })
}

#[instrument(level = "debug", skip_all)]
/// This returns the remote address that worked, so you can try that first next time
async fn repl_consumer_connect_supplier(
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    consumer_conn_settings: &ConsumerConnSettings,
) -> Option<(
    SocketAddr,
    Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
)> {
    // This is pretty gnarly, but we need to loop to try out each socket addr.
    for sock_addr in sock_addrs {
        debug!(
            "Attempting to connect to {} replica via {}",
            server_name.to_str(),
            sock_addr
        );

        let tcpstream = match timeout(
            consumer_conn_settings.replica_connect_timeout,
            TcpStream::connect(sock_addr),
        )
        .await
        {
            Ok(Ok(tc)) => {
                trace!("Connection established to peer on {:?}", sock_addr);
                tc
            }
            Ok(Err(err)) => {
                debug!(?err, "Failed to connect to {}", sock_addr);
                continue;
            }
            Err(_) => {
                debug!("Timeout connecting to {}", sock_addr);
                continue;
            }
        };

        let tlsstream = match timeout(
            consumer_conn_settings.replica_connect_timeout,
            tls_connector.connect(server_name.to_owned(), tcpstream),
        )
        .await
        {
            Ok(Ok(ta)) => ta,
            Ok(Err(e)) => {
                error!("Replication client TLS setup error, continuing -> {:?}", e);
                continue;
            }
            Err(_) => {
                debug!("Timeout establishing TLS to {}", sock_addr);
                continue;
            }
        };

        let supplier_conn = Framed::new(
            tlsstream,
            codec::ConsumerCodec::new(consumer_conn_settings.max_frame_bytes),
        );
        // "hey this one worked, try it first next time!"
        return Some((sock_addr.to_owned(), supplier_conn));
    }

    error!(
        "Unable to connect to supplier, tried to connect to {:?}",
        sock_addrs
    );
    None
}

async fn repl_consumer_disconnect_supplier(
    supplier_conn: Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    consumer_conn_settings: &ConsumerConnSettings,
) {
    let mut tls_stream = supplier_conn.into_inner();

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        tls_stream.shutdown(),
    )
    .await
    {
        Ok(Ok(_)) => debug!("Connection closed successfully"),
        Ok(Err(tls_err)) => warn!(?tls_err, "Unable to cleanly shutdown TLS client connection"),
        Err(_) => error!("Timeout attempting to close connection"),
    }
}

/// This returns the socket address that worked, so you can try that first next time
#[allow(clippy::too_many_arguments)]
#[instrument(
    level="info",
    skip(refresh_coord, tls_connector, idms, consumer_conn_settings, tracker),
    fields(eventid = Uuid::new_v4().to_string(), server_name = %server_name.to_str())
)]
async fn repl_run_consumer_refresh(
    refresh_coord: Arc<RefreshCoord>,
    start_deadline: Option<Instant>,
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
    tracker: &ReplicationStateTracker,
    peer_url: &str,
) -> Result<Option<SocketAddr>, ()> {
    // Take the refresh lock, unless it must not run (anymore).
    let Some(refresh_coord_guard) = claim_refresh(&refresh_coord, start_deadline, peer_url).await
    else {
        return Ok(None);
    };

    // Okay, we need to proceed. Open the connection.
    let (addr, mut supplier_conn) = repl_consumer_connect_supplier(
        server_name,
        sock_addrs,
        tls_connector,
        consumer_conn_settings,
    )
    .await
    .ok_or_else(|| {
        tracker.notify_replication_connect_failure(peer_url, now_secs());
    })?;

    tracker.notify_replication_connected(peer_url);
    tracker.notify_replication_refresh_started();

    let result = repl_run_consumer_refresh_inner(
        addr,
        &mut supplier_conn,
        refresh_coord_guard,
        idms,
        consumer_conn_settings,
        tracker,
    )
    .await;

    // disconnect the connection if possible.
    repl_consumer_disconnect_supplier(supplier_conn, consumer_conn_settings).await;

    match &result {
        Ok(_) => tracker.notify_replication_refresh_success(peer_url, now_secs()),
        Err(_) => tracker.notify_replication_refresh_failed(now_secs()),
    }

    result
}

async fn repl_run_consumer_refresh_inner(
    addr: SocketAddr,
    supplier_conn: &mut Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    mut refresh_coord_guard: MutexGuard<'_, (bool, mpsc::Sender<RefreshProgress>)>,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
    tracker: &ReplicationStateTracker,
) -> Result<Option<SocketAddr>, ()> {
    // If we fail at any point, just RETURN because this leaves the next task to attempt, or
    // the channel drops and that tells the caller this failed.
    let exchange_failed = || tracker.notify_replication_exchange_failure(now_secs());

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.send(ConsumerRequest::Refresh),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!(?err, "consumer encode error, unable to continue.");
            exchange_failed();
            return Err(());
        }
        Err(_) => {
            error!("consumer request timeout error, unable to continue.");
            exchange_failed();
            return Err(());
        }
    };

    let refresh = match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.next(),
    )
    .await
    {
        Ok(Some(Ok(SupplierResponse::Refresh(changes)))) => {
            // Success - return to bypass the error message.
            changes
        }
        Ok(Some(Ok(SupplierResponse::Pong))) | Ok(Some(Ok(SupplierResponse::Incremental(_)))) => {
            error!("Supplier Response contains invalid State");
            exchange_failed();
            return Err(());
        }
        Ok(Some(Err(codec_err))) => {
            error!(?codec_err, "Consumer decode error, unable to continue.");
            exchange_failed();
            return Err(());
        }
        Ok(None) => {
            error!("Connection closed");
            exchange_failed();
            return Err(());
        }
        Err(_) => {
            error!("consumer response timeout error, unable to continue.");
            exchange_failed();
            return Err(());
        }
    };

    // The requester may have given up between the claim and reading the report that the
    // refresh started (it reached its start deadline first). It then closed its receiver
    // and told the operator that the refresh did not start, so do not replace the content
    // of this node behind its back. A requester that read the report keeps its receiver
    // until the refresh is done, as does the requester of an automatic refresh.
    if refresh_coord_guard.1.is_closed() {
        warn!("Refresh was abandoned by its requester before it could be applied, not refreshing.");
        return Err(());
    }

    // Now apply the refresh if possible
    {
        // Scope the transaction.
        let ct = duration_from_epoch_now();
        let write_txn = if maintenance_state() == MaintenanceState::Recovering {
            with_maintenance_write_bypass(idms.proxy_write(ct)).await
        } else {
            idms.proxy_write(ct).await
        };

        write_txn
            .and_then(|mut write_txn| {
                write_txn
                    .qs_write
                    .consumer_apply_refresh(refresh)
                    .and_then(|cs| write_txn.commit().map(|()| cs))
            })
            .map_err(|err| {
                error!(?err, "Consumer was not able to apply refresh.");
                tracker.notify_replication_apply_failure(now_secs());
            })?;
    }

    // Now mark the refresh as complete AND indicate it to the channel.
    refresh_coord_guard.0 = true;
    if refresh_coord_guard
        .1
        .send(RefreshProgress::Done)
        .await
        .is_err()
    {
        warn!("Unable to signal to caller that refresh has completed.");
    }

    // Here the coord guard will drop and every other task proceeds.

    info!("Replication refresh was successful.");
    Ok(Some(addr))
}

#[allow(clippy::too_many_arguments)]
#[instrument(
    level="info",
    skip(tls_connector, idms, consumer_conn_settings, server_name, tracker),
    fields(eventid = Uuid::new_v4().to_string(), server_name = %server_name.to_str())
)]
async fn repl_run_consumer(
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    automatic_refresh: bool,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
    task_tx: &mut broadcast::Sender<ReplConsumerCtrl>,
    tracker: &ReplicationStateTracker,
    peer_url: &str,
) -> Option<SocketAddr> {
    let connect_result = repl_consumer_connect_supplier(
        server_name,
        sock_addrs,
        tls_connector,
        consumer_conn_settings,
    )
    .await;

    let (socket_addr, mut supplier_conn) = match connect_result {
        Some(r) => {
            tracker.notify_replication_connected(peer_url);
            r
        }
        None => {
            tracker.notify_replication_connect_failure(peer_url, now_secs());
            return None;
        }
    };

    let result = repl_run_consumer_inner(
        socket_addr,
        &mut supplier_conn,
        idms,
        automatic_refresh,
        consumer_conn_settings,
        task_tx,
        tracker,
        peer_url,
    )
    .await;

    repl_consumer_disconnect_supplier(supplier_conn, consumer_conn_settings).await;

    result
}

#[allow(clippy::too_many_arguments)]
async fn repl_run_consumer_inner(
    socket_addr: SocketAddr,
    supplier_conn: &mut Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    idms: &IdmServer,
    automatic_refresh: bool,
    consumer_conn_settings: &ConsumerConnSettings,
    task_tx: &mut broadcast::Sender<ReplConsumerCtrl>,
    tracker: &ReplicationStateTracker,
    peer_url: &str,
) -> Option<SocketAddr> {
    let exchange_failed = || tracker.notify_replication_exchange_failure(now_secs());

    // Perform incremental.
    let consumer_ruv_range = {
        let consumer_state = idms
            .proxy_read()
            .await
            .and_then(|mut read_txn| read_txn.qs_read.consumer_get_state());
        match consumer_state {
            Ok(ruv_range) => ruv_range,
            Err(err) => {
                error!(
                    ?err,
                    "consumer ruv range could not be accessed, unable to continue."
                );
                tracker.notify_replication_apply_failure(now_secs());
                return None;
            }
        }
    };

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.send(ConsumerRequest::Incremental(consumer_ruv_range)),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!(?err, "consumer encode error, unable to continue.");
            exchange_failed();
            return None;
        }
        Err(_) => {
            error!("consumer request timeout, unable to continue");
            exchange_failed();
            return None;
        }
    };

    let changes = match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.next(),
    )
    .await
    {
        Ok(Some(Ok(SupplierResponse::Incremental(changes)))) => changes,
        Ok(Some(Ok(SupplierResponse::Pong))) | Ok(Some(Ok(SupplierResponse::Refresh(_)))) => {
            error!("Supplier Response contains invalid state");
            exchange_failed();
            return None;
        }
        Ok(Some(Err(err))) => {
            error!(?err, "Consumer decode error, unable to continue.");
            exchange_failed();
            return None;
        }
        Ok(None) => {
            error!("Consumer connection closed, unable to continue.");
            exchange_failed();
            return None;
        }

        Err(_) => {
            error!("consumer response timeout, unable to continue");
            exchange_failed();
            return None;
        }
    };

    // A supplier in another domain while this node holds replicated content (or is in sync
    // with other suppliers) is the one that must be refreshed, for example a new replica or
    // an empty re-created one: never refresh from it, that would wipe this node. The manual
    // `kubidmd refresh-replication-consumer` does not go through this check.
    if matches!(changes, ReplIncrementalContext::DomainMismatch)
        && !tracker.notify_replication_domain_mismatch(peer_url, now_secs())
    {
        error!(
            "Supplier {peer_url} is in a different domain from this node, which holds \
             replicated content. This node will not be refreshed from it automatically, as \
             that would replace its content with the supplier's: the supplier is reported \
             stale and this node degraded. Compare the domains with `kubidmd domain show`. \
             If the supplier is the one out of the domain (for example an empty or re-created \
             node), refresh the supplier from a node that holds the content: on the \
             supplier, run `kubidmd refresh-replication-consumer \
             --i-want-to-refresh-this-servers-database --from <origin of a node in this \
             domain>`. If the supplier's domain is the intended one (the cluster was \
             intentionally rebuilt in a new domain), an operator must run \
             `kubidmd refresh-replication-consumer --i-want-to-refresh-this-servers-database \
             --from {peer_url}` on this node."
        );
        return None;
    }

    // Now apply the changes if possible
    let consumer_state = {
        let ct = duration_from_epoch_now();
        let write_txn = if maintenance_state() == MaintenanceState::Recovering {
            with_maintenance_write_bypass(idms.proxy_write(ct)).await
        } else {
            idms.proxy_write(ct).await
        };

        match write_txn.and_then(|mut write_txn| {
            write_txn
                .qs_write
                .consumer_apply_changes(changes)
                .and_then(|cs| write_txn.commit().map(|()| cs))
        }) {
            Ok(state) => state,
            Err(err) => {
                error!(?err, "Consumer was not able to apply changes.");
                tracker.notify_replication_apply_failure(now_secs());
                return None;
            }
        }
    };

    match consumer_state {
        ConsumerState::Ok => {
            info!("Incremental Replication Success");
            tracker.notify_replication_incremental_success(peer_url, now_secs());
            // return to bypass the failure message.
            Some(socket_addr)
        }
        ConsumerState::RefreshRequired => {
            tracker.notify_replication_refresh_required(peer_url);
            if automatic_refresh {
                warn!("Consumer is out of date and must be refreshed. This will happen *now*.");

                let (tx, mut rx) = mpsc::channel(1);

                let refresh_coord = Arc::new(Mutex::new((false, tx)));

                if task_tx
                    .send(ReplConsumerCtrl::Refresh {
                        refresh_coord,
                        from: None,
                        // The receiver below waits for it, however long it takes.
                        start_deadline: None,
                    })
                    .is_err()
                {
                    error!("Unable to begin replication consumer refresh, tasks are unable to be notified.");
                } else {
                    tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Some(RefreshProgress::Started { supplier }) => {
                                    info!("replication consumer refresh started from {supplier}")
                                }
                                Some(RefreshProgress::Done) => {
                                    info!("replication consumer refresh complete!");
                                    break;
                                }
                                None => {
                                    warn!("refresh task was lost with no response!");
                                    break;
                                }
                            }
                        }
                    });
                }

                None
            } else {
                error!("Consumer is out of date and must be refreshed. You must manually resolve this situation.");
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ConsumerConnSettings {
    max_frame_bytes: usize,
    task_poll_interval: Duration,
    replica_connect_timeout: Duration,
}

#[allow(clippy::too_many_arguments)]
async fn repl_task(
    origin: Url,

    client_key: PrivateKeyDer<'static>,
    client_cert: CertificateDer<'static>,
    supplier_cert: CertificateDer<'static>,

    consumer_conn_settings: ConsumerConnSettings,
    mut task_rx: broadcast::Receiver<ReplConsumerCtrl>,
    mut task_tx: broadcast::Sender<ReplConsumerCtrl>,
    automatic_refresh: bool,
    idms: Arc<IdmServer>,
    tracker: ReplicationStateTracker,
) {
    if origin.scheme() != "repl" {
        error!("Replica origin is not repl:// - refusing to proceed.");
        return;
    }

    let domain = match origin.domain() {
        Some(d) => d,
        None => {
            error!("Replica origin does not have a valid domain name, unable to proceed. Perhaps you tried to use an ip address?");
            return;
        }
    };

    let Ok(server_name) = ServerName::try_from(domain.to_owned()) else {
        error!("Replica origin does not have a valid domain name, unable to proceed.");
        return;
    };

    // Add the supplier cert.
    // ⚠️  note that here we need to build a new cert store. This is because
    // we want to pin a single certificate!
    let mut root_cert_store = RootCertStore::empty();
    if let Err(err) = root_cert_store.add(supplier_cert) {
        error!(?err, "Replica supplier cert invalid.");
        return;
    };

    let provider = rustls::crypto::aws_lc_rs::default_provider().into();

    let tls_client_config = match ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder
                .with_root_certificates(root_cert_store)
                .with_client_auth_cert(vec![client_cert], client_key)
        }) {
        Ok(ccb) => ccb,
        Err(err) => {
            error!(?err, "Unable to build TLS client configuration");
            return;
        }
    };

    let tls_connector = TlsConnector::from(Arc::new(tls_client_config));

    let mut repl_interval = interval(consumer_conn_settings.task_poll_interval);

    let peer_url = peer_label(&origin);

    info!("Replica task for {} has started.", origin);

    // we keep track of the "last known good" socketaddr so we can try that first next time.
    let mut last_working_address: Option<SocketAddr> = None;

    // Okay, all the parameters are set up. Now we replicate on our interval.
    loop {
        // we resolve the DNS entry to the ip:port each time we attempt a connection to avoid stale
        // DNS issues, ref #3188. If we are unable to resolve the address, we backoff and try again
        // as in something like docker the address may change frequently.
        //
        // Note, if DNS isn't available, we can proceed with the last used working address too. This
        // prevents DNS (or lack thereof) from causing a replication outage.
        let mut sorted_socket_addrs = vec![];

        // If the target address worked last time, then let's use it this time!
        if let Some(addr) = last_working_address {
            debug!(?last_working_address);
            sorted_socket_addrs.push(addr);
        };

        // Default to port 443 if not set in the origin
        match origin.socket_addrs(|| Some(443)) {
            Ok(mut socket_addrs) => {
                // Make every address unique.
                socket_addrs.sort_unstable();
                socket_addrs.dedup();

                // The only possible conflict is with the last working address,
                // so lets just check that.
                socket_addrs.into_iter().for_each(|addr| {
                    if Some(&addr) != last_working_address.as_ref() {
                        // Not already present, append
                        sorted_socket_addrs.push(addr);
                    }
                });
            }
            Err(err) => {
                if let Some(addr) = last_working_address {
                    warn!(
                        ?err,
                        "Unable to resolve '{origin}' to ip:port, using last known working address '{addr}'"
                    );
                } else {
                    warn!(?err, "Unable to resolve '{origin}' to ip:port.");
                }
            }
        };

        if sorted_socket_addrs.is_empty() {
            warn!(
                "No replication addresses available, delaying replication operation for '{origin}'"
            );
            tracker.notify_replication_connect_failure(&peer_url, now_secs());
            repl_interval.tick().await;
            continue;
        }

        tokio::select! {
            Ok(task) = task_rx.recv() => {
                match task {
                    ReplConsumerCtrl::Stop => break,
                    ReplConsumerCtrl::Refresh { refresh_coord, from, start_deadline } => {
                        // A refresh restricted to another supplier is not ours to run.
                        if !refresh_is_for_peer(from.as_deref(), &peer_url) {
                            trace!("Refresh requested from another supplier, skipping.");
                            continue;
                        }
                        let outcome = repl_run_consumer_refresh(
                            refresh_coord,
                            start_deadline,
                            &server_name,
                            &sorted_socket_addrs,
                            &tls_connector,
                            &idms,
                            &consumer_conn_settings,
                            &tracker,
                            &peer_url,
                        )
                        .await;
                        last_working_address = address_after_refresh(last_working_address, outcome);
                    }
                }
            }
            _ = repl_interval.tick() => {
                // A drained/fenced node remains a replication supplier, but its
                // consumer must not start new apply work. Recovering is the sole
                // non-serving state where replication writes receive the scoped
                // maintenance bypass.
                if !matches!(
                    maintenance_state(),
                    MaintenanceState::Serving | MaintenanceState::Recovering
                ) {
                    debug!("Skipping replication consumer while node is maintenance-fenced");
                    continue;
                }

                // Interval passed, attempt a replication run.
                repl_run_consumer(
                    &server_name,
                    &sorted_socket_addrs,
                    &tls_connector,
                    automatic_refresh,
                    &idms,
                    &consumer_conn_settings,
                    &mut task_tx,
                    &tracker,
                    &peer_url,
                )
                .await;
            }
        }
    }

    info!("Replica task for {} has stopped.", origin);
}

#[instrument(level = "debug", skip_all)]
async fn handle_repl_conn(
    max_frame_bytes: usize,
    tcpstream: TcpStream,
    client_address: SocketAddr,
    tls_acceptor: TlsAcceptor,
    idms: Arc<IdmServer>,
) {
    debug!(?client_address, "replication client connected 🛫");

    let tlsstream = match tls_acceptor.accept(tcpstream).await {
        Ok(ta) => ta,
        Err(err) => {
            error!(?err, "Replication TLS setup error, disconnecting client");
            return;
        }
    };

    let (r, w) = tokio::io::split(tlsstream);
    let mut r = FramedRead::new(r, codec::SupplierCodec::new(max_frame_bytes));
    let mut w = FramedWrite::new(w, codec::SupplierCodec::new(max_frame_bytes));

    while let Some(codec_msg) = r.next().await {
        match codec_msg {
            Ok(ConsumerRequest::Ping) => {
                debug!("consumer requested ping");
                if let Err(err) = w.send(SupplierResponse::Pong).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Incremental(consumer_ruv_range)) => {
                let changes = match idms.proxy_read().await.and_then(|mut read_txn| {
                    read_txn
                        .qs_read
                        .supplier_provide_changes(consumer_ruv_range)
                }) {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide changes failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Incremental(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Refresh) => {
                let changes = match idms
                    .proxy_read()
                    .await
                    .and_then(|mut read_txn| read_txn.qs_read.supplier_provide_refresh())
                {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide refresh failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Refresh(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Err(err) => {
                error!(?err, "supplier decode error, unable to continue.");
                break;
            }
        }
    }

    debug!(?client_address, "replication client disconnected 🛬");
}

/// This is the main acceptor for the replication server.
async fn repl_acceptor(
    listener: TcpListener,
    idms: Arc<IdmServer>,
    repl_config: ReplicationConfiguration,
    mut rx: broadcast::Receiver<CoreAction>,
    mut ctrl_rx: mpsc::Receiver<ReplCtrl>,
    tracker: ReplicationStateTracker,
) {
    info!("Starting Replication Acceptor ...");
    // Persistent parts
    // These all probably need changes later ...
    let replica_connect_timeout = Duration::from_secs(5);
    let mut retry_timeout = Duration::from_secs(1);
    let max_frame_bytes = 268435456;

    let consumer_conn_settings = ConsumerConnSettings {
        max_frame_bytes,
        task_poll_interval: repl_config.get_task_poll_interval(),
        replica_connect_timeout,
    };

    // Setup a broadcast to control our tasks.
    let (task_tx, task_rx1) = broadcast::channel(1);
    // Note, we drop this task here since each task will re-subscribe. That way the
    // broadcast doesn't jam up because we aren't draining this task.
    drop(task_rx1);
    let mut task_handles = VecDeque::new();

    // Create another broadcast to control the replication tasks and their need to reload.

    // Spawn a KRC communication task?

    // In future we need to update this from the KRC if configured, and we default this
    // to "empty". But if this map exists in the config, we have to always use that.
    let replication_node_map = repl_config.manual.clone();
    let domain_name = match repl_config.origin.domain() {
        Some(n) => n.to_string(),
        None => {
            error!("Unable to start replication, replication origin does not contain a valid domain name.");
            return;
        }
    };

    // This needs to have an event loop that can respond to changes.
    // For now we just design it to reload ssl if the map changes internally.
    'event: loop {
        // Don't block shutdowns while we are waiting here.
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => break 'event,
                    CoreAction::Reload => {}
                }
            }
            _ = sleep(retry_timeout) => {}
        }

        // The timeout is initially small, we increase it here to prevent spinning too much.
        retry_timeout = Duration::from_secs(60);

        info!("Starting replication reload ...");
        // Tell existing tasks to shutdown.
        // Note: We ignore the result here since an err can occur *if* there are
        // no tasks currently listening on the channel.
        info!("Stopping {} Replication Tasks ...", task_handles.len());
        debug_assert!(task_handles.len() >= task_tx.receiver_count());
        let _ = task_tx.send(ReplConsumerCtrl::Stop);
        for task_handle in task_handles.drain(..) {
            // Let each task join.
            let res: Result<(), _> = task_handle.await;
            if res.is_err() {
                warn!("Failed to join replication task, continuing ...");
            }
        }

        // Now we can start to re-load configurations and setup our client tasks
        // as well.

        // Get our private key / cert.
        let res = {
            let ct = duration_from_epoch_now();
            idms.proxy_write(ct).await.and_then(|mut idms_prox_write| {
                idms_prox_write
                    .qs_write
                    .supplier_get_key_cert(&domain_name)
                    .and_then(|res| idms_prox_write.commit().map(|()| res))
            })
        };

        let (server_key, server_cert) = match res {
            Ok(r) => r,
            Err(err) => {
                error!(?err, "CRITICAL: Unable to access supplier certificate/key.");
                continue 'event;
            }
        };

        info!(
            replication_cert_not_before = ?server_cert.tbs_certificate().validity().not_before,
            replication_cert_not_after = ?server_cert.tbs_certificate().validity().not_after,
        );

        // rustls expects these to be der
        let Ok(server_key_der) = PrivateKeyDer::try_from(server_key.as_bytes().to_vec()) else {
            error!("CRITICAL: Unable to convert server key from DER.");
            continue 'event;
        };

        let Ok(server_cert_der) = server_cert.to_der().map(CertificateDer::from) else {
            error!("CRITICAL: Unable to convert server cert to DER.");
            continue 'event;
        };

        let mut client_certs = Vec::new();

        // For each node in the map, either spawn a task to pull from that node,
        // or setup the node as allowed to pull from us.
        for (origin, node) in replication_node_map.iter() {
            // Setup client certs
            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: consumer_cert,
                    automatic_refresh: _,
                }
                | RepNodeConfig::AllowPull { consumer_cert } => {
                    let Ok(consumer_cert_der) = consumer_cert.to_der().map(CertificateDer::from)
                    else {
                        warn!("WARNING: Unable to convert client cert to DER.");
                        continue 'event;
                    };

                    client_certs.push(consumer_cert_der)
                }
                RepNodeConfig::Pull {
                    supplier_cert: _,
                    automatic_refresh: _,
                } => {}
            };

            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: supplier_cert,
                    automatic_refresh,
                }
                | RepNodeConfig::Pull {
                    supplier_cert,
                    automatic_refresh,
                } => {
                    let Ok(supplier_cert_der) = supplier_cert.to_der().map(CertificateDer::from)
                    else {
                        warn!("WARNING: Unable to convert client cert to DER.");
                        continue 'event;
                    };

                    let task_rx = task_tx.subscribe();
                    let task_tx_c = task_tx.clone();

                    let handle: JoinHandle<()> = tokio::spawn(repl_task(
                        origin.clone(),
                        server_key_der.clone_key(),
                        server_cert_der.clone(),
                        supplier_cert_der.clone(),
                        consumer_conn_settings.clone(),
                        task_rx,
                        task_tx_c,
                        *automatic_refresh,
                        idms.clone(),
                        tracker.clone(),
                    ));

                    task_handles.push_back(handle);
                    debug_assert_eq!(task_handles.len(), task_tx.receiver_count());
                }
                RepNodeConfig::AllowPull { consumer_cert: _ } => {}
            };
        }

        // ⚠️  This section is critical to the security of replication
        //    Since replication relies on mTLS we MUST ensure these options
        //    are absolutely correct!
        //
        // Setup the TLS builder.

        // ⚠️  CRITICAL - ensure that the cert store only has client certs from
        // the repl map added.

        let tls_acceptor = if client_certs.is_empty() {
            warn!("No replication client certs are available, replication connections will be ignored.");
            None
        } else {
            let mut client_cert_roots = RootCertStore::empty();

            for client_cert in client_certs.into_iter() {
                if let Err(err) = client_cert_roots.add(client_cert) {
                    error!(?err, "CRITICAL, unable to add client certificate.");
                    continue 'event;
                }
            }

            let provider: Arc<_> = rustls::crypto::aws_lc_rs::default_provider().into();

            let client_cert_verifier_result = WebPkiClientVerifier::builder_with_provider(
                client_cert_roots.into(),
                provider.clone(),
            )
            // We don't allow clients that lack a certificate to correct.
            // allow_unauthenticated()
            .build();

            let client_cert_verifier = match client_cert_verifier_result {
                Ok(ccv) => ccv,
                Err(err) => {
                    error!(
                        ?err,
                        "CRITICAL, unable to configure client certificate verifier."
                    );
                    continue 'event;
                }
            };

            let tls_server_config = match ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .and_then(|builder| {
                    builder
                        .with_client_cert_verifier(client_cert_verifier)
                        .with_single_cert(vec![server_cert_der], server_key_der)
                }) {
                Ok(tls_server_config) => tls_server_config,
                Err(err) => {
                    error!(
                        ?err,
                        "CRITICAL, unable to create TLS Server Config. Will retry ..."
                    );
                    continue 'event;
                }
            };

            Some(TlsAcceptor::from(Arc::new(tls_server_config)))
        };

        // IMPORTANT: We have to drop the retry timeout else the renew
        // cert times out. This is a HACK until I swap in the new actors
        // framework.
        retry_timeout = Duration::from_secs(1);

        'event_inner: loop {
            // This is great to diagnose when spans are entered or present and they capture
            // things incorrectly.
            // eprintln!("🔥 C ---> {:?}", tracing::Span::current());
            let eventid = Uuid::new_v4();

            tokio::select! {
                Ok(action) = rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break 'event,
                        CoreAction::Reload => continue 'event,
                    }
                }
                Some(ctrl_msg) = ctrl_rx.recv() => {
                    match ctrl_msg {
                        ReplCtrl::GetCertificate {
                            respond
                        } => {
                            let _span = debug_span!("supplier_accept_loop", uuid = ?eventid).entered();
                            if respond.send(server_cert.clone()).is_err() {
                                warn!("Server certificate was requested, but requsetor disconnected");
                            } else {
                                trace!("Sent server certificate via control channel");
                            }
                            continue 'event_inner
                        }
                        ReplCtrl::RenewCertificate {
                            respond
                        } => {
                            let span = debug_span!("supplier_accept_loop", uuid = ?eventid);
                            async {
                                debug!("renewing replication certificate ...");
                                // Renew the cert.
                                let res = {
                                    let ct = duration_from_epoch_now();
                                    idms.proxy_write(ct).await
                                        .and_then(|mut idms_prox_write|
                                    idms_prox_write
                                        .qs_write
                                        .supplier_renew_key_cert(&domain_name)
                                        .and_then(|res| idms_prox_write.commit().map(|()| res))
                                        )
                                };

                                let success = res.is_ok();

                                if let Err(err) = res {
                                    error!(?err, "failed to renew server certificate");
                                }

                                if respond.send(success).is_err() {
                                    warn!("Server certificate renewal was requested, but requester disconnected!");
                                } else {
                                    trace!("Sent server certificate renewal status via control channel");
                                }
                            }
                            .instrument(span)
                            .await;

                            // Start a reload.
                            continue 'event;
                        }
                        ReplCtrl::RefreshConsumer {
                            from,
                            start_deadline,
                            respond
                        } => {
                            // Only the task of the requested supplier may run the refresh.
                            let from = match from
                                .as_deref()
                                .map(|from| refresh_source(&repl_config, from))
                                .transpose()
                            {
                                Ok(from) => from,
                                Err(message) => {
                                    error!("{message}");
                                    if respond.send(Err(message)).is_err() {
                                        warn!("Replication consumer refresh was requested, but requester disconnected");
                                    }
                                    continue 'event_inner
                                }
                            };
                            if let Some(from) = &from {
                                info!("Refreshing this node from the replication supplier {from}");
                            }

                            // Indicate to consumer tasks that they should do a refresh.
                            let (tx, rx) = mpsc::channel(1);

                            let refresh_coord = Arc::new(
                                Mutex::new(
                                (
                                    false, tx
                                )
                                )
                            );

                            if task_tx.send(ReplConsumerCtrl::Refresh {
                                refresh_coord,
                                from,
                                start_deadline: Some(start_deadline),
                            }).is_err() {
                                error!("Unable to begin replication consumer refresh, tasks are unable to be notified.");
                            }

                            if respond.send(Ok(rx)).is_err() {
                                warn!("Replication consumer refresh was requested, but requester disconnected");
                            } else {
                                trace!("Sent refresh comms channel to requester");
                            }
                            continue 'event_inner
                        }
                    }
                }
                // Handle accepts.
                // Handle *reloads*
                /*
                _ = reload.recv() => {
                    info!("Initiating TLS reload");
                    continue
                }
                */
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcpstream, client_socket_addr)) => {
                            if let Some(clone_tls_acceptor) = tls_acceptor.clone() {
                                let clone_idms = idms.clone();
                                // We don't care about the join handle here - once a client connects
                                // it sticks to whatever ssl settings it had at launch.
                                tokio::spawn(
                                    handle_repl_conn(max_frame_bytes, tcpstream, client_socket_addr, clone_tls_acceptor, clone_idms)
                                );
                            } else {
                                // TLS is not setup, generally due to no accepted/trusted client
                                // certs being present. Drop the connection.
                                warn!("Ignoring connection from {client_socket_addr} as replication is not configured correctly.");
                                warn!("This is because you have not configured this server with trusted partner certificates.");
                            }
                        }
                        Err(e) => {
                            error!("replication acceptor error, continuing -> {:?}", e);
                        }
                    }
                    continue 'event_inner
                }
            } // end select
              // Continue to poll/loop
        }
    }
    // Shutdown child tasks.
    info!("Stopping {} Replication Tasks ...", task_handles.len());
    debug_assert!(task_handles.len() >= task_tx.receiver_count());
    let _ = task_tx.send(ReplConsumerCtrl::Stop);
    for task_handle in task_handles.drain(..) {
        // Let each task join.
        let res: Result<(), _> = task_handle.await.map(|_| ());
        if res.is_err() {
            warn!("Failed to join replication task, continuing ...");
        }
    }

    info!("Stopped {}", super::TaskName::ReplicationSupervisor);
}

#[cfg(test)]
mod tests {
    use super::{
        address_after_refresh, claim_refresh, peer_label, refresh_is_for_peer, refresh_source,
        startup_sync_state, supplier_peers, RefreshProgress,
    };
    use crate::repl::config::{RepNodeConfig, ReplicationConfiguration};
    use crypto_glue::{traits::DecodePem, x509::Certificate};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, Mutex};
    use tokio::time::Instant;
    use url::Url;

    // Test only certificate, a self-signed server cert. Only its presence matters here.
    const TEST_X509_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICeDCCAh6gAwIBAgIBAjAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCQVUxDDAK
BgNVBAgMA1FMRDEPMA0GA1UECgwGS2FuaWRtMRwwGgYDVQQDDBNLYW5pZG0gR2Vu
ZXJhdGVkIENBMTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQgRXZhbHVhdGlvbiAt
IE5PVCBGT1IgUFJPRFVDVElPTjAeFw0yNTA3MjkwMzMxMDNaFw0yNTA4MDMwMzMx
MDNaMHoxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANRTEQxDzANBgNVBAoMBkthbmlk
bTESMBAGA1UEAwwJbG9jYWxob3N0MTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQg
RXZhbHVhdGlvbiAtIE5PVCBGT1IgUFJPRFVDVElPTjBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABPFkpVzFH+feItm9JFFm/noge+BlZLpdGWOuSUvfoivAzCgPr7Kr
nGd8kUzIyJermePzu2SVQLaEt/7GY8Ha+2ujgYkwgYYwCQYDVR0TBAIwADAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFOjucEtX
mj/wQ7npVaMOyDtLU6dUMB8GA1UdIwQYMBaAFNo5o+5ea0sNMlW/75VgGJCv2AcJ
MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiEA1TACf4eS
g07LRiKhlMgA+6xxztxiZCuV6LakRp7FZdECIFp0rFSiFJdkLEO9IyqYc+zPW770
ta41VMU3u9UQfHxF
-----END CERTIFICATE-----
"#;

    fn cert() -> Certificate {
        Certificate::from_pem(TEST_X509_CERT_DATA).expect("Unable to parse test X509 cert data")
    }

    fn url(s: &str) -> Url {
        Url::from_str(s).expect("Invalid url")
    }

    #[test]
    fn peer_label_drops_the_path() {
        assert_eq!(
            peer_label(&url("repl://node1.example.com:8444/some/path")),
            "repl://node1.example.com:8444"
        );
        assert_eq!(
            peer_label(&url("repl://node1.example.com")),
            "repl://node1.example.com"
        );
        // Peers configured by address stay distinct.
        assert_eq!(
            peer_label(&url("repl://192.0.2.1:8444")),
            "repl://192.0.2.1:8444"
        );
        assert_ne!(
            peer_label(&url("repl://192.0.2.1:8444")),
            peer_label(&url("repl://192.0.2.2:8444"))
        );
    }

    #[test]
    fn supplier_peers_are_the_nodes_this_node_pulls_from() {
        let mut repl_config = ReplicationConfiguration::default();
        // Replication configured without peers: nothing to sync from.
        assert_eq!(supplier_peers(&repl_config), (vec![], false));

        // A node that only supplies others has nothing to sync from either.
        repl_config.manual.insert(
            url("repl://consumer.example.com:8444"),
            RepNodeConfig::AllowPull {
                consumer_cert: cert(),
            },
        );
        assert_eq!(supplier_peers(&repl_config), (vec![], false));

        // The node that created the domain: it pulls from its partners, but never takes
        // its content from them.
        repl_config.manual.insert(
            url("repl://partner.example.com:8444"),
            RepNodeConfig::MutualPull {
                partner_cert: cert(),
                automatic_refresh: false,
            },
        );
        assert_eq!(
            supplier_peers(&repl_config),
            (vec!["repl://partner.example.com:8444".to_string()], false)
        );

        // A replica that is refreshed from its supplier when needed.
        repl_config.manual.insert(
            url("repl://supplier.example.com:8444"),
            RepNodeConfig::Pull {
                supplier_cert: cert(),
                automatic_refresh: true,
            },
        );
        assert_eq!(
            supplier_peers(&repl_config),
            (
                vec![
                    "repl://partner.example.com:8444".to_string(),
                    "repl://supplier.example.com:8444".to_string(),
                ],
                true
            )
        );
    }

    fn refresh_config() -> ReplicationConfiguration {
        let mut repl_config = ReplicationConfiguration::default();
        repl_config.manual.insert(
            url("repl://pod-0.example.com:8444"),
            RepNodeConfig::MutualPull {
                partner_cert: cert(),
                automatic_refresh: false,
            },
        );
        repl_config.manual.insert(
            url("repl://pod-1.example.com:8444"),
            RepNodeConfig::Pull {
                supplier_cert: cert(),
                automatic_refresh: true,
            },
        );
        repl_config.manual.insert(
            url("repl://consumer.example.com:8444"),
            RepNodeConfig::AllowPull {
                consumer_cert: cert(),
            },
        );
        repl_config
    }

    #[test]
    fn refresh_source_matches_a_configured_supplier() {
        let repl_config = refresh_config();
        assert_eq!(
            refresh_source(&repl_config, "repl://pod-0.example.com:8444"),
            Ok("repl://pod-0.example.com:8444".to_string())
        );
        // Matched as the peer is named: any path is ignored, the host is not case
        // sensitive.
        assert_eq!(
            refresh_source(&repl_config, " repl://POD-1.example.com:8444/ "),
            Ok("repl://pod-1.example.com:8444".to_string())
        );
    }

    #[test]
    fn refresh_source_rejects_anything_else() {
        let repl_config = refresh_config();
        for from in [
            // Not configured.
            "repl://pod-2.example.com:8444",
            // Another port.
            "repl://pod-0.example.com:9444",
            // Only a consumer of this node.
            "repl://consumer.example.com:8444",
            // Not a URL.
            "pod-0",
            "",
        ] {
            let err = refresh_source(&repl_config, from).expect_err(from);
            assert!(
                err.contains("is not a replication supplier of this node"),
                "{err}"
            );
            // The message lists what can be used instead, but no consumer.
            assert!(err.contains("repl://pod-0.example.com:8444"), "{err}");
            assert!(err.contains("repl://pod-1.example.com:8444"), "{err}");
            assert!(!err.contains("[repl://consumer"), "{err}");
        }
        assert!(
            refresh_source(&ReplicationConfiguration::default(), "repl://a.example.com")
                .is_err_and(|err| err.ends_with("[]"))
        );
    }

    #[test]
    fn refresh_source_rejects_an_ambiguous_origin() {
        // The same host configured twice, in another case: two replication tasks.
        let mut repl_config = refresh_config();
        repl_config.manual.insert(
            url("repl://POD-1.example.com:8444"),
            RepNodeConfig::Pull {
                supplier_cert: cert(),
                automatic_refresh: false,
            },
        );
        for from in [
            "repl://pod-1.example.com:8444",
            "repl://POD-1.example.com:8444",
            "repl://Pod-1.Example.com:8444/",
        ] {
            let err = refresh_source(&repl_config, from).expect_err(from);
            assert!(
                err.contains("matches more than one replication supplier"),
                "{err}"
            );
            // Both matches are listed, nothing else.
            assert!(err.contains("repl://pod-1.example.com:8444"), "{err}");
            assert!(err.contains("repl://POD-1.example.com:8444"), "{err}");
            assert!(!err.contains("pod-0"), "{err}");
        }
        // Other suppliers are still unambiguous.
        assert_eq!(
            refresh_source(&repl_config, "repl://pod-0.example.com:8444"),
            Ok("repl://pod-0.example.com:8444".to_string())
        );

        // Origins that differ only in their path are one supplier, not ambiguous.
        let mut repl_config = refresh_config();
        repl_config.manual.insert(
            url("repl://pod-1.example.com:8444/other"),
            RepNodeConfig::Pull {
                supplier_cert: cert(),
                automatic_refresh: false,
            },
        );
        assert_eq!(
            refresh_source(&repl_config, "repl://pod-1.example.com:8444"),
            Ok("repl://pod-1.example.com:8444".to_string())
        );
    }

    const SUPPLIER: &str = "repl://pod-1.example.com:8444";

    #[tokio::test]
    async fn abandoned_or_late_refresh_is_not_run() {
        let later = Instant::now() + Duration::from_secs(60);

        // A manual refresh still awaited before its deadline runs, and its requester learns
        // at once which supplier it runs from.
        let (tx, mut rx) = mpsc::channel(1);
        let coord = Mutex::new((false, tx));
        assert!(claim_refresh(&coord, Some(later), SUPPLIER).await.is_some());
        assert_eq!(
            rx.recv().await,
            Some(RefreshProgress::Started {
                supplier: SUPPLIER.to_string()
            })
        );

        // The requester gave up (it timed out and dropped its receiver): not run, even
        // before the deadline.
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let coord = Mutex::new((false, tx));
        assert!(claim_refresh(&coord, Some(later), SUPPLIER).await.is_none());
        assert!(claim_refresh(&coord, None, SUPPLIER).await.is_none());

        // Past its deadline: not run, even while its receiver is still there, and its
        // requester hears nothing.
        let (tx, mut rx) = mpsc::channel(1);
        let coord = Mutex::new((false, tx));
        let past = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(claim_refresh(&coord, Some(past), SUPPLIER).await.is_none());
        assert!(rx.try_recv().is_err());

        // Already done by another task: not run again.
        let (tx, _rx) = mpsc::channel(1);
        let coord = Mutex::new((true, tx));
        assert!(claim_refresh(&coord, Some(later), SUPPLIER).await.is_none());

        // An automatic refresh has no deadline and keeps its receiver: it runs, however
        // late a task gets to it.
        let (tx, mut rx) = mpsc::channel(1);
        let coord = Mutex::new((false, tx));
        let mut guard = claim_refresh(&coord, None, SUPPLIER)
            .await
            .expect("refresh runs");
        // The task that runs it reports completion to the receiver.
        guard.0 = true;
        assert!(matches!(
            rx.recv().await,
            Some(RefreshProgress::Started { .. })
        ));
        assert!(guard.1.send(RefreshProgress::Done).await.is_ok());
        drop(guard);
        assert_eq!(rx.recv().await, Some(RefreshProgress::Done));
    }

    #[tokio::test]
    async fn retried_claim_waits_for_the_requester_to_read_the_first_start() {
        // A first task reported its start and failed before the requester read the
        // report: a second task reports its own start once the requester reads the first.
        let later = Instant::now() + Duration::from_secs(60);
        let (tx, mut rx) = mpsc::channel(1);
        let coord = Arc::new(Mutex::new((false, tx)));
        drop(claim_refresh(&coord, Some(later), "repl://a:8444").await);

        let second = {
            let coord = coord.clone();
            tokio::spawn(async move {
                claim_refresh(&coord, Some(later), "repl://b:8444")
                    .await
                    .is_some()
            })
        };
        assert_eq!(
            rx.recv().await,
            Some(RefreshProgress::Started {
                supplier: "repl://a:8444".to_string()
            })
        );
        assert_eq!(
            rx.recv().await,
            Some(RefreshProgress::Started {
                supplier: "repl://b:8444".to_string()
            })
        );
        assert!(second.await.is_ok_and(|claimed| claimed));

        // Had the requester given up instead, the second claim would not wait for it.
        let (tx, rx) = mpsc::channel(1);
        let coord = Mutex::new((false, tx));
        drop(claim_refresh(&coord, Some(later), "repl://a:8444").await);
        drop(rx);
        assert!(claim_refresh(&coord, Some(later), "repl://b:8444")
            .await
            .is_none());
    }

    #[test]
    fn refused_refresh_keeps_the_last_working_address() {
        let previous: SocketAddr = "192.0.2.1:8444".parse().expect("valid address");
        let used: SocketAddr = "192.0.2.2:8444".parse().expect("valid address");

        // A task that did not run the refresh (not its supplier's turn, abandoned, late)
        // keeps the address that worked last.
        assert_eq!(
            address_after_refresh(Some(previous), Ok(None)),
            Some(previous)
        );
        assert_eq!(address_after_refresh(None, Ok(None)), None);
        // One that ran it remembers the address it used, one that failed none.
        assert_eq!(
            address_after_refresh(Some(previous), Ok(Some(used))),
            Some(used)
        );
        assert_eq!(address_after_refresh(Some(previous), Err(())), None);
    }

    #[test]
    fn refresh_runs_only_on_the_requested_task() {
        // Without --from every supplier task may take the refresh.
        assert!(refresh_is_for_peer(None, "repl://pod-0.example.com:8444"));
        assert!(refresh_is_for_peer(None, "repl://pod-1.example.com:8444"));

        // With --from only the task of that supplier runs it.
        let from = refresh_source(&refresh_config(), "repl://pod-1.example.com:8444").ok();
        let from = from.as_deref();
        assert!(refresh_is_for_peer(from, "repl://pod-1.example.com:8444"));
        assert!(!refresh_is_for_peer(from, "repl://pod-0.example.com:8444"));
    }

    #[test]
    fn startup_sync_state_guards_when_unreadable() {
        // (has_synced for readiness, sync_evidence for the domain mismatch guard)
        assert_eq!(startup_sync_state::<()>(Ok(true)), (true, true));
        assert_eq!(startup_sync_state::<()>(Ok(false)), (false, false));
        // An error is never a reason to become ready, nor to be refreshed from a peer in
        // another domain.
        assert_eq!(startup_sync_state(Err("db error")), (false, true));
    }
}
