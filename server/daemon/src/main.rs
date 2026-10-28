#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_family = "unix")]
use kubidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

#[cfg(target_family = "windows")] // for windows builds
use whoami;

use std::fs::{metadata, File};
// This works on both unix and windows.
use clap::{Args, Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use kubidm_proto::internal::OperationError;
use kubidmd_core::{
    admin::{
        AdminTaskRequest, AdminTaskResponse, ClientCodec, MaintenanceErrorCode,
        MaintenanceOperation, ProtoDomainInfo, ProtoDomainUpgradeCheckReport,
        ProtoDomainUpgradeCheckStatus, ReplicationFence, ReplicationSyncResult,
    },
    backup::pitr::{pitr_list_server_core, pitr_recover_server_core, RecoveryTargetSpec},
    backup_server_core, cert_generate_core,
    config::{Configuration, ServerConfigUntagged},
    create_server_core, dbscan_get_id2entry_core, dbscan_list_id2entry_core,
    dbscan_list_index_analysis_core, dbscan_list_index_core, dbscan_list_indexes_core,
    dbscan_list_quarantined_core, dbscan_quarantine_id2entry_core, dbscan_restore_quarantined_core,
    domain_rename_core, list_backups_server_core, reindex_server_core,
    replicate_status_server_core, restore_s3_database, restore_server_core, s3_config_for_cli,
    vacuum_server_core, verify_backup_server_core, verify_s3_backup_server_core,
    verify_server_core, BackupVerifyLevel, CoreAction, RestoreStatus,
};
use serde::Serialize;
use sketching::{pipeline::TracingPipelineGuard, tracing_forest::util::*};
use std::{fmt, io::Read, path::PathBuf, process::ExitCode};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use uuid::Uuid;

include!("./opt.rs");

/// Get information on the windows username
#[cfg(target_family = "windows")]
fn get_user_details_windows() {
    eprintln!(
        "Running on windows, current username is: {:?}",
        whoami::username()
    );
}

fn display_json_success() {
    let json_output = serde_json::json!({
        "status": "ok",
    });
    println!("{json_output}");
}

fn display_json_success_output<T: Serialize>(data: T) {
    let json_output = serde_json::json!({
        "status": "ok",
        "output": data,
    });
    println!("{json_output}");
}

fn display_json_error<E, M>(error: E, message: M)
where
    E: fmt::Display,
    M: fmt::Display,
{
    let json_output = serde_json::json!({
        "status": "error",
        "reason": format!("{error}"),
        "message": format!("{message}")
    });
    println!("{json_output}");
}

fn display_json_error_context<E, M, C>(error: E, message: M, context: C)
where
    E: fmt::Display,
    M: fmt::Display,
    C: fmt::Display,
{
    let json_output = serde_json::json!({
        "status": "error",
        "reason": format!("{error}"),
        "message": format!("{message}"),
        "context": format!("{context}"),
    });
    println!("{json_output}");
}

async fn submit_admin_req_json(path: &str, req: AdminTaskRequest) -> ExitCode {
    // Connect to the socket.
    let stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        Err(err) => {
            display_json_error(err, "Unable to connect to socket path.");

            return ExitCode::FAILURE;
        }
    };

    let mut reqs = Framed::new(stream, ClientCodec);

    if let Err(err) = reqs.send(req).await {
        display_json_error(err, "Unable to connect to send request.");

        return ExitCode::FAILURE;
    };

    if let Err(err) = reqs.flush().await {
        display_json_error(err, "Unable to connect to flush request.");

        return ExitCode::FAILURE;
    }

    match reqs.next().await {
        Some(Ok(AdminTaskResponse::RecoverAccount { password })) => {
            display_json_success_output(password)
        }
        Some(Ok(AdminTaskResponse::Success)) => {
            display_json_success();
        }
        Some(Ok(AdminTaskResponse::Error)) => {
            display_json_error(
                "ResponseError",
                "Error processing request - you should inspect the server logs.",
            );
            return ExitCode::FAILURE;
        }
        Some(Ok(AdminTaskResponse::ErrorMessage { message })) => {
            display_json_error("ResponseError", message);
            return ExitCode::FAILURE;
        }
        Some(Err(err)) => {
            display_json_error(err, "Error during admin task operation.");
            return ExitCode::FAILURE;
        }
        None => {
            display_json_error("SocketClosed", "Error makeing request to admin socket.");
            return ExitCode::FAILURE;
        }

        _ => {}
    }

    ExitCode::SUCCESS
}

async fn submit_admin_req_human(path: &str, req: AdminTaskRequest) -> ExitCode {
    // Connect to the socket.
    let stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        Err(e) => {
            error!(err = ?e, %path, "Unable to connect to socket path");
            let diag = kubidm_lib_file_permissions::diagnose_path(path.as_ref());
            info!(%diag);
            return ExitCode::FAILURE;
        }
    };

    let mut reqs = Framed::new(stream, ClientCodec);

    if let Err(e) = reqs.send(req).await {
        error!(err = ?e, "Unable to send request");
        return ExitCode::FAILURE;
    };

    if let Err(e) = reqs.flush().await {
        error!(err = ?e, "Unable to flush request");
        return ExitCode::FAILURE;
    }

    trace!("flushed, waiting ...");

    match reqs.next().await {
        Some(Ok(AdminTaskResponse::RecoverAccount { password })) => info!(new_password = ?password),
        Some(Ok(AdminTaskResponse::ShowReplicationCertificate { cert })) => {
            info!(certificate = ?cert)
        }
        Some(Ok(AdminTaskResponse::ShowReplicationCertificateMetadata {
            not_before,
            not_after,
            subject,
            expired,
        })) => {
            info!("not_before : {}", not_before);
            info!("not_after  : {}", not_after);
            info!("subject    : {}", subject);
            info!("expired    : {}", expired);
        }
        Some(Ok(AdminTaskResponse::DomainUpgradeCheck { report })) => {
            let ProtoDomainUpgradeCheckReport {
                name,
                uuid,
                current_level,
                upgrade_level,
                report_items,
            } = report;

            info!("domain_name            : {}", name);
            info!("domain_uuid            : {}", uuid);
            info!("domain_current_level   : {}", current_level);
            info!("domain_upgrade_level   : {}", upgrade_level);

            if report_items.is_empty() {
                // Nothing to report, so this implies a pass.
                info!("------------------------");
                info!("status                 : PASS");
                return ExitCode::SUCCESS;
            }

            for item in report_items {
                info!("------------------------");
                match item.status {
                    ProtoDomainUpgradeCheckStatus::Pass6To7Gidnumber => {
                        info!("upgrade_item           : gidnumber range validity");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : PASS");
                    }
                    ProtoDomainUpgradeCheckStatus::Fail6To7Gidnumber => {
                        info!("upgrade_item           : gidnumber range validity");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : FAIL");
                        info!("description            : The automatically allocated gidnumbers for posix accounts was found to allocate numbers into systemd-reserved ranges. These can no longer be used.");
                        info!("action                 : Modify the gidnumber of affected entries so that they are in the range 65536 to 524287 OR reset the gidnumber to cause it to automatically regenerate.");
                        for entry_id in item.affected_entries {
                            info!("affected_entry         : {}", entry_id);
                        }
                    }
                    // ===========
                    ProtoDomainUpgradeCheckStatus::Pass7To8SecurityKeys => {
                        info!("upgrade_item           : security key usage");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : PASS");
                    }
                    ProtoDomainUpgradeCheckStatus::Fail7To8SecurityKeys => {
                        info!("upgrade_item           : security key usage");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : FAIL");
                        info!("description            : Security keys no longer function as a second factor due to the introduction of CTAP2 and greater forcing PIN interactions.");
                        info!("action                 : Modify the accounts in question to remove their security key and add it as a passkey or enable TOTP");
                        for entry_id in item.affected_entries {
                            info!("affected_entry         : {}", entry_id);
                        }
                    }
                    // ===========
                    ProtoDomainUpgradeCheckStatus::Pass7To8Oauth2StrictRedirectUri => {
                        info!("upgrade_item           : oauth2 strict redirect uri enforcement");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : PASS");
                    }
                    ProtoDomainUpgradeCheckStatus::Fail7To8Oauth2StrictRedirectUri => {
                        info!("upgrade_item           : oauth2 strict redirect uri enforcement");
                        debug!("from_level             : {}", item.from_level);
                        debug!("to_level               : {}", item.to_level);
                        info!("status                 : FAIL");
                        info!("description            : To harden against possible public client open redirection vulnerabilities, redirect uris must now be registered ahead of time and are validated rather than the former origin verification process.");
                        info!("action                 : Verify the redirect uri's for OAuth2 clients and then enable strict-redirect-uri on each client.");
                        for entry_id in item.affected_entries {
                            info!("affected_entry         : {}", entry_id);
                        }
                    }
                }
            } // end for report items
        }
        Some(Ok(AdminTaskResponse::DomainRaise { level })) => {
            info!("success - raised domain level to {}", level)
        }
        Some(Ok(AdminTaskResponse::DomainShow { domain_info })) => {
            let ProtoDomainInfo {
                name,
                displayname,
                uuid,
                level,
            } = domain_info;

            info!("domain_name   : {}", name);
            info!("domain_display: {}", displayname);
            info!("domain_uuid   : {}", uuid);
            info!("domain_level  : {}", level);
        }
        Some(Ok(
            AdminTaskResponse::MaintenanceCapabilities { .. }
            | AdminTaskResponse::MaintenanceStatus { .. }
            | AdminTaskResponse::MaintenanceDrain { .. }
            | AdminTaskResponse::MaintenanceRun { .. }
            | AdminTaskResponse::ReplicationFence { .. }
            | AdminTaskResponse::ReplicationSyncUntil { .. }
            | AdminTaskResponse::MaintenanceResume { .. }
            | AdminTaskResponse::MaintenanceError { .. },
        )) => {
            // Only `kubidmd maintenance` sends maintenance requests, and it prints its own
            // responses, so seeing one here means the server answered the wrong request.
            error!("Unexpected maintenance response to a non maintenance request");
            return ExitCode::FAILURE;
        }
        Some(Ok(AdminTaskResponse::Success)) => info!("success"),
        Some(Ok(AdminTaskResponse::Error)) => {
            info!("Error - you should inspect the logs.");
            return ExitCode::FAILURE;
        }
        Some(Ok(AdminTaskResponse::ErrorMessage { message })) => {
            error!("Error - {message}");
            return ExitCode::FAILURE;
        }
        Some(Err(err)) => {
            error!(?err, "Error during admin task operation");
            return ExitCode::FAILURE;
        }
        None => {
            error!("Error making request to admin socket");
            return ExitCode::FAILURE;
        }
    };

    ExitCode::SUCCESS
}

/// The request `kubidmd refresh-replication-consumer` sends. `Err` is a usage error that
/// must be reported before anything is sent to the server.
fn refresh_replication_consumer_request(
    proceed: bool,
    from: Option<&str>,
) -> Result<AdminTaskRequest, String> {
    if !proceed {
        return Err("Unwilling to proceed. Check --help.".to_string());
    }
    Ok(AdminTaskRequest::RefreshReplicationConsumer {
        from: from.map(str::to_owned),
    })
}

/// The `kubidmd maintenance` request a subcommand stands for. `Err` is a usage error that
/// must be reported before anything is sent to the server.
fn maintenance_request(cmd: &MaintenanceCmds) -> Result<AdminTaskRequest, String> {
    Ok(match cmd {
        MaintenanceCmds::Capabilities => AdminTaskRequest::MaintenanceCapabilities,
        MaintenanceCmds::Status => AdminTaskRequest::MaintenanceStatus,
        MaintenanceCmds::Drain(opt) => AdminTaskRequest::MaintenanceDrain {
            operation_id: opt.operation_id,
        },
        MaintenanceCmds::Run(opt) => AdminTaskRequest::MaintenanceRun {
            operation_id: opt.operation_id.operation_id,
            operation: match opt.operation {
                MaintenanceRunOperation::Reindex => MaintenanceOperation::Reindex,
                MaintenanceRunOperation::Verify => MaintenanceOperation::Verify,
            },
        },
        MaintenanceCmds::Fence => AdminTaskRequest::ReplicationFence,
        MaintenanceCmds::SyncUntil(opt) => AdminTaskRequest::ReplicationSyncUntil {
            operation_id: opt.operation_id.operation_id,
            fence: maintenance_fence(&opt.fence)?,
            timeout_seconds: opt.timeout_seconds,
        },
        MaintenanceCmds::Resume(opt) => AdminTaskRequest::MaintenanceResume {
            operation_id: opt.operation_id,
        },
    })
}

/// Parse the fence given to `sync-until`, inline or from a file.
fn maintenance_fence(source: &MaintenanceFenceSource) -> Result<ReplicationFence, String> {
    let json = match (&source.fence, &source.fence_file) {
        (Some(json), _) => json.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|err| format!("Unable to read the fence file '{}': {err}", path.display()))?,
        (None, None) => return Err("A replication fence is required".to_string()),
    };
    serde_json::from_str(&json).map_err(|err| format!("Invalid replication fence JSON: {err}"))
}

/// The snake_case name serde gives a plain enum value, as used on the wire and in JSON output.
fn serde_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn json_text<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|err| format!("<unserializable value: {err}>"))
}

fn or_none<T: fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}

/// What `kubidmd maintenance` prints for a response, and whether the step succeeded.
#[derive(Debug, PartialEq, Eq)]
struct MaintenanceOutcome {
    text: String,
    success: bool,
}

impl MaintenanceOutcome {
    fn ok(human: String, output: serde_json::Value, format: MaintenanceOutput) -> Self {
        let text = match format {
            MaintenanceOutput::Human => human,
            MaintenanceOutput::Json => {
                let mut object = serde_json::json!({ "status": "ok" });
                object["output"] = output;
                object.to_string()
            }
        };
        MaintenanceOutcome {
            text,
            success: true,
        }
    }

    /// `output` carries the structured detail of a failure that is more than an error
    /// message, such as the result of a run that did not succeed.
    fn failed(
        reason: &str,
        message: &str,
        retryable: bool,
        output: serde_json::Value,
        format: MaintenanceOutput,
    ) -> Self {
        let text = match format {
            MaintenanceOutput::Human => {
                let retry = if retryable {
                    " (retryable: repeat the same request)"
                } else {
                    ""
                };
                format!("error: {reason}{retry}\n{message}")
            }
            MaintenanceOutput::Json => {
                let mut object = serde_json::json!({
                    "status": "error",
                    "reason": reason,
                    "message": message,
                    "retryable": retryable,
                });
                object["output"] = output;
                object.to_string()
            }
        };
        MaintenanceOutcome {
            text,
            success: false,
        }
    }
}

fn maintenance_outcome(
    response: &AdminTaskResponse,
    format: MaintenanceOutput,
) -> MaintenanceOutcome {
    match response {
        AdminTaskResponse::MaintenanceCapabilities { capabilities } => {
            let human = format!(
                "api_version        : {}\n\
                 drain              : {}\n\
                 replication_fence  : {}\n\
                 sync_until         : {}\n\
                 reindex            : {}\n\
                 verify             : {}\n\
                 vacuum             : {}\n\
                 restore            : {}",
                capabilities.api_version,
                capabilities.drain,
                capabilities.replication_fence,
                capabilities.sync_until,
                capabilities.reindex,
                capabilities.verify,
                capabilities.vacuum,
                capabilities.restore,
            );
            MaintenanceOutcome::ok(
                human,
                serde_json::json!({ "capabilities": capabilities }),
                format,
            )
        }
        AdminTaskResponse::MaintenanceStatus { status, fence } => {
            let mut human = format!(
                "state               : {}\n\
                 active_operation_id : {}\n\
                 last_error          : {}",
                serde_label(&status.state),
                or_none(status.active_operation_id),
                or_none(status.last_error.as_deref()),
            );
            if let Some(fence) = fence {
                human.push_str(&format!("\nfence               : {}", json_text(fence)));
            }
            MaintenanceOutcome::ok(
                human,
                serde_json::json!({ "status": status, "fence": fence }),
                format,
            )
        }
        AdminTaskResponse::MaintenanceDrain {
            operation_id,
            fence,
        } => MaintenanceOutcome::ok(
            format!(
                "drained\noperation_id : {operation_id}\nfence        : {}",
                json_text(fence)
            ),
            serde_json::json!({ "operation_id": operation_id, "fence": fence }),
            format,
        ),
        AdminTaskResponse::MaintenanceRun { result } => {
            let operation = serde_label(&result.operation);
            if result.success {
                let mut human = format!(
                    "{operation} succeeded\noperation_id : {}",
                    result.operation_id
                );
                if let Some(fence) = &result.fence {
                    human.push_str(&format!("\nfence        : {}", json_text(fence)));
                }
                MaintenanceOutcome::ok(human, serde_json::json!({ "result": result }), format)
            } else {
                let mut message =
                    format!("{operation} failed for operation {}", result.operation_id);
                if let Some(error) = &result.error {
                    message.push_str(&format!(": {error}"));
                }
                for verification_error in &result.verification_errors {
                    message.push_str(&format!("\nverification error: {verification_error}"));
                }
                MaintenanceOutcome::failed(
                    "run_failed",
                    &message,
                    false,
                    serde_json::json!({ "result": result }),
                    format,
                )
            }
        }
        AdminTaskResponse::ReplicationFence { fence } => MaintenanceOutcome::ok(
            format!("fence : {}", json_text(fence)),
            serde_json::json!({ "fence": fence }),
            format,
        ),
        AdminTaskResponse::ReplicationSyncUntil {
            result,
            current_fence,
        } => {
            let label = serde_label(result);
            let detail = serde_json::json!({ "result": result, "current_fence": current_fence });
            match result {
                ReplicationSyncResult::Satisfied => MaintenanceOutcome::ok(
                    format!(
                        "fence satisfied\ncurrent_fence : {}",
                        json_text(current_fence)
                    ),
                    detail,
                    format,
                ),
                // The wait simply ran out: nothing changed, so asking again is safe.
                ReplicationSyncResult::TimedOut => MaintenanceOutcome::failed(
                    &label,
                    &format!(
                        "the fence was not satisfied in time\ncurrent_fence : {}",
                        json_text(current_fence)
                    ),
                    true,
                    detail,
                    format,
                ),
                ReplicationSyncResult::DomainMismatch
                | ReplicationSyncResult::GenerationMismatch => MaintenanceOutcome::failed(
                    &label,
                    &format!(
                        "the fence can never be satisfied by this node\ncurrent_fence : {}",
                        json_text(current_fence)
                    ),
                    false,
                    detail,
                    format,
                ),
            }
        }
        AdminTaskResponse::MaintenanceResume { operation_id } => MaintenanceOutcome::ok(
            format!("resumed\noperation_id : {operation_id}"),
            serde_json::json!({ "operation_id": operation_id }),
            format,
        ),
        AdminTaskResponse::MaintenanceError { code, message } => MaintenanceOutcome::failed(
            &serde_label(code),
            message,
            // A busy step never changed any state.
            *code == MaintenanceErrorCode::Busy,
            serde_json::Value::Null,
            format,
        ),
        AdminTaskResponse::Error => MaintenanceOutcome::failed(
            "response_error",
            "Error processing request - you should inspect the server logs.",
            false,
            serde_json::Value::Null,
            format,
        ),
        _ => MaintenanceOutcome::failed(
            "unexpected_response",
            "The server answered a maintenance request with an unrelated response.",
            false,
            serde_json::Value::Null,
            format,
        ),
    }
}

/// Send one request to the admin socket and wait for its response. The server answers a
/// request only once its step has finished, which can take long, so there is no client
/// side deadline. `Err` is the failure reason and a message.
async fn maintenance_exchange(
    path: &str,
    req: AdminTaskRequest,
) -> Result<AdminTaskResponse, (&'static str, String)> {
    let stream = UnixStream::connect(path).await.map_err(|err| {
        let diag = kubidm_lib_file_permissions::diagnose_path(path.as_ref());
        (
            "socket_connect",
            format!("Unable to connect to the admin socket '{path}': {err}\n{diag}"),
        )
    })?;

    let mut reqs = Framed::new(stream, ClientCodec);

    reqs.send(req)
        .await
        .map_err(|err| ("socket_send", format!("Unable to send the request: {err}")))?;
    reqs.flush()
        .await
        .map_err(|err| ("socket_send", format!("Unable to flush the request: {err}")))?;

    match reqs.next().await {
        Some(Ok(response)) => Ok(response),
        Some(Err(err)) => Err((
            "socket_receive",
            format!("Error during the admin task operation: {err}"),
        )),
        None => Err((
            "socket_closed",
            "The admin socket closed before it answered.".to_string(),
        )),
    }
}

/// Print `outcome` and return its exit code. Errors go to stderr, except as JSON, where
/// stdout always carries the one JSON object.
fn print_maintenance_outcome(outcome: &MaintenanceOutcome, format: MaintenanceOutput) -> ExitCode {
    if outcome.success || format == MaintenanceOutput::Json {
        println!("{}", outcome.text);
    } else {
        eprintln!("{}", outcome.text);
    }
    if outcome.success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn maintenance_command(
    opt: &MaintenanceOpt,
    config: &Configuration,
    rt: &tokio::runtime::Runtime,
) -> ExitCode {
    let format = opt.output;
    let failure = |reason: &str, message: &str| {
        print_maintenance_outcome(
            &MaintenanceOutcome::failed(reason, message, false, serde_json::Value::Null, format),
            format,
        )
    };

    // Building the request can read a fence file, which must not happen on the runtime.
    let req = match maintenance_request(&opt.commands) {
        Ok(req) => req,
        Err(message) => return failure("invalid_request", &message),
    };

    match rt.block_on(maintenance_exchange(config.adminbindpath.as_str(), req)) {
        Ok(response) => print_maintenance_outcome(&maintenance_outcome(&response, format), format),
        Err((reason, message)) => failure(reason, &message),
    }
}

/// Check what we're running as and various filesystem permissions.
fn check_file_ownership(opt: &KubidmdParser) -> Result<(), ExitCode> {
    // Get info about who we are.
    #[cfg(target_family = "unix")]
    let (cuid, ceuid) = {
        let cuid = get_current_uid();
        let ceuid = get_effective_uid();
        let cgid = get_current_gid();
        let cegid = get_effective_gid();

        if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
            warn!("This is running as uid == 0 (root) which may be a security risk.");
            // eprintln!("ERROR: Refusing to run - this process must not operate as root.");
            // std::process::exit(1);
        }

        if cuid != ceuid || cgid != cegid {
            error!("{} != {} || {} != {}", cuid, ceuid, cgid, cegid);
            error!("Refusing to run - uid and euid OR gid and egid must be consistent.");
            return Err(ExitCode::FAILURE);
        }
        (cuid, ceuid)
    };

    if let Some(cfg_path) = &opt.config_path {
        #[cfg(target_family = "unix")]
        {
            if let Some(cfg_meta) = match metadata(cfg_path) {
                Ok(m) => Some(m),
                Err(e) => {
                    error!(
                        "Unable to read metadata for configuration file '{}' - {:?}",
                        cfg_path.display(),
                        e
                    );
                    // return ExitCxode::FAILURE;
                    None
                }
            } {
                if !kubidm_lib_file_permissions::readonly(&cfg_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                        cfg_path.to_str().unwrap_or("invalid file path"));
                }

                if cfg_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...",
                        cfg_path.to_str().unwrap_or("invalid file path")
                        );
                }

                if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                        cfg_path.to_str().unwrap_or("invalid file path")
                        );
                }
            }
        }
    }
    Ok(())
}

/// What the operator must do after a restore or recovery that ended with `status`.
fn not_recorded_hint(status: RestoreStatus) -> &'static str {
    match status {
        RestoreStatus::AbandonedHistoryNotRecorded => {
            "; take a new online backup right after starting the server"
        }
        RestoreStatus::Complete | RestoreStatus::WalArchiveNotUpdated => "",
    }
}

/// The exit code of `database restore` and `restore-s3`: 1 when the restore failed, which
/// includes a database that was restored but could not be reindexed (its error says so),
/// otherwise [`RestoreStatus::exit_code`].
fn restore_exit_code(restored: Result<RestoreStatus, OperationError>) -> ExitCode {
    match restored.ok() {
        Some(RestoreStatus::Complete) => {
            info!("✅ Restore Success!");
            ExitCode::SUCCESS
        }
        Some(status) => {
            warn!(
                "Restore finished: the database was restored, but the WAL archive was not \
                 updated{}",
                not_recorded_hint(status)
            );
            ExitCode::from(status.exit_code())
        }
        None => ExitCode::FAILURE,
    }
}

async fn scripting_command(cmd: ScriptingCommand, config: Configuration) -> ExitCode {
    match cmd {
        ScriptingCommand::RecoverAccount { name } => {
            submit_admin_req_json(
                config.adminbindpath.as_str(),
                AdminTaskRequest::RecoverAccount {
                    name: name.to_owned(),
                },
            )
            .await;
        }

        ScriptingCommand::Backup { path, name } => {
            if !backup_server_core(&config, path.as_deref(), name.as_deref()).await {
                return ExitCode::FAILURE;
            }
        }

        ScriptingCommand::Reload => {
            submit_admin_req_json(config.adminbindpath.as_str(), AdminTaskRequest::Reload).await;
        }

        ScriptingCommand::HealthCheck {
            verify_tls,
            check_origin,
        } => {
            let healthcheck_url = match check_origin {
                true => format!("{}/healthz", config.origin),
                false => {
                    // the replace covers when you specify an ipv6-capable "all" address
                    format!(
                        "https://{}/healthz",
                        config.address[0].replace("[::]", "localhost")
                    )
                }
            };

            let mut client = reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(!verify_tls)
                .danger_accept_invalid_hostnames(!verify_tls)
                .https_only(true);

            client = match &config.tls_config {
                None => client,
                Some(tls_config) => {
                    // if the ca_cert file exists, then we'll use it
                    let ca_cert_path = tls_config.chain.clone();
                    match ca_cert_path.exists() {
                        true => {
                            let mut cert_buf = Vec::new();
                            if let Err(err) = std::fs::File::open(&ca_cert_path)
                                .and_then(|mut file| file.read_to_end(&mut cert_buf))
                            {
                                display_json_error_context(
                                    err,
                                    "Failed to read from filesystem.",
                                    ca_cert_path.display(),
                                );

                                return ExitCode::FAILURE;
                            }

                            let ca_chain_parsed =
                                match reqwest::Certificate::from_pem_bundle(&cert_buf) {
                                    Ok(val) => val,
                                    Err(err) => {
                                        display_json_error_context(
                                            err,
                                            "Failed to parse into ca_chain.",
                                            ca_cert_path.display(),
                                        );

                                        return ExitCode::FAILURE;
                                    }
                                };

                            // Need at least 2 certs for the leaf + chain. We skip the leaf.
                            for cert in ca_chain_parsed.into_iter().skip(1) {
                                client = client.add_root_certificate(cert)
                            }
                            client
                        }
                        false => {
                            display_json_error_context(
                                "NoSuchFile",
                                "Requested ca file does not exist.",
                                ca_cert_path.display(),
                            );

                            return ExitCode::FAILURE;
                        }
                    }
                }
            };
            #[allow(clippy::unwrap_used)]
            let client = client.build().unwrap();

            let _ = match client.get(&healthcheck_url).send().await {
                Ok(val) => val,
                Err(error) => {
                    let error_message = {
                        if error.is_timeout() {
                            format!("Timeout connecting to url={healthcheck_url}")
                        } else if error.is_connect() {
                            format!("Connection failed: {error}")
                        } else {
                            format!("Failed to complete healthcheck: {error:?}")
                        }
                    };

                    display_json_error("HealthcheckFailed", error_message);

                    return ExitCode::FAILURE;
                }
            };
            display_json_success();
        }
    }

    ExitCode::SUCCESS
}

// We have to do this because we can't use tracing until we've started the logging pipeline, and we can't start the logging pipeline until the tokio runtime's doing its thing.
async fn start_daemon(opt: KubidmdParser, config: Configuration) -> ExitCode {
    // if we have a server config and it has an OTEL URL, then we'll start the logging pipeline now.

    // TODO: only send to stderr when we're not in a TTY
    let (provider, logging_subscriber) = match sketching::pipeline::start_logging_pipeline(
        &config.otel_grpc_endpoint,
        config.log_level,
    ) {
        Err(err) => {
            eprintln!("Error starting logger - {err:} - Bailing on startup!");
            return ExitCode::FAILURE;
        }
        Ok(val) => val,
    };

    if let Err(err) = tracing::subscriber::set_global_default(logging_subscriber).map_err(|err| {
        eprintln!("Error starting logger - {err:} - Bailing on startup!");
        ExitCode::FAILURE
    }) {
        return err;
    };

    // ************************************************
    // HERE'S WHERE YOU CAN START USING THE LOGGER
    // ************************************************
    info!(version = %env!("KUBIDM_PKG_VERSION"), "Starting Kubidmd");

    // guard which shuts down the logging/tracing providers when we close out
    let _otelguard = TracingPipelineGuard(provider);

    // ===========================================================================
    // Start pre-run checks

    // Check the permissions of the files from the configuration.
    if let Err(err) = check_file_ownership(&opt) {
        return err;
    };

    if let Some(db_path) = config.db_path.as_ref() {
        let db_pathbuf = db_path.to_path_buf();
        // We can't check the db_path permissions because it may not exist yet!
        if let Some(db_parent_path) = db_pathbuf.parent() {
            if !db_parent_path.exists() {
                warn!(
                    "DB folder {} may not exist, server startup may FAIL!",
                    db_parent_path.to_str().unwrap_or("invalid file path")
                );
                let diag = kubidm_lib_file_permissions::diagnose_path(&db_pathbuf);
                info!(%diag);
            }

            let db_par_path_buf = db_parent_path.to_path_buf();
            let i_meta = match metadata(&db_par_path_buf) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "Unable to read metadata for database folder '{}' - {:?}",
                        &db_par_path_buf.to_str().unwrap_or("invalid file path"),
                        e
                    );
                    return ExitCode::FAILURE;
                }
            };
            if !i_meta.is_dir() {
                error!(
                    "ERROR: Refusing to run - DB folder {} may not be a directory",
                    db_par_path_buf.to_str().unwrap_or("invalid file path")
                );
                return ExitCode::FAILURE;
            }

            if kubidm_lib_file_permissions::readonly(&i_meta) {
                warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
            #[cfg(not(target_os = "windows"))]
            if i_meta.mode() & 0o007 != 0 {
                warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
        }
    } else {
        error!("No db_path set in configuration, server startup will FAIL!");
        return ExitCode::FAILURE;
    }

    let lock_was_setup = match &opt.commands {
        // we aren't going to touch the DB so we can carry on
        KubidmdOpt::ShowReplicationCertificate
        | KubidmdOpt::RenewReplicationCertificate
        | KubidmdOpt::RefreshReplicationConsumer { .. }
        | KubidmdOpt::RecoverAccount { .. }
        | KubidmdOpt::DisableAccount { .. }
        | KubidmdOpt::Database {
            commands:
                DbCommands::ListBackups { .. }
                | DbCommands::PitrList(_)
                | DbCommands::ReplicateStatus { .. },
        } => None,
        _ => {
            // Okay - Lets now create our lock and go.
            #[allow(clippy::expect_used)]
            let klock_path = match config.db_path.clone() {
                Some(val) => val.with_extension("klock"),
                None => std::env::temp_dir().join("kubidmd.klock"),
            };

            let flock = match File::create(&klock_path) {
                Ok(flock) => flock,
                Err(err) => {
                    error!(
                        "ERROR: Refusing to start - unable to create kubidmd exclusive lock at {}",
                        klock_path.display()
                    );
                    error!(?err);
                    return ExitCode::FAILURE;
                }
            };

            match flock.try_lock() {
                Ok(_) => debug!("Acquired kubidm exclusive lock"),
                Err(err) => {
                    error!(
                        "ERROR: Refusing to start - unable to lock kubidmd exclusive lock at {}",
                        klock_path.display()
                    );
                    error!(?err);
                    return ExitCode::FAILURE;
                }
            };

            Some(klock_path)
        }
    };

    let result_code = kubidm_main(config, opt).await;

    if let Some(klock_path) = lock_was_setup {
        if let Err(reason) = std::fs::remove_file(&klock_path) {
            warn!(
                ?reason,
                "WARNING: Unable to clean up kubidmd exclusive lock at {}",
                klock_path.display()
            );
        }
    }

    result_code
}

fn main() -> ExitCode {
    // On linux when debug assertions are disabled, prevent ptrace
    // from attaching to us.
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    if let Err(code) = prctl::set_dumpable(false) {
        println!(
            "CRITICAL: Unable to set prctl flags, which breaches our security model, quitting! {:?}", code
        );
        return ExitCode::FAILURE;
    }

    // We need enough backtrace depth to find leak sources if they exist.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::builder().trim_backtraces(Some(40)).build();

    // Read CLI args, determine what the user has asked us to do.
    let opt = KubidmdParser::parse();

    // print the app version and bail
    if let KubidmdOpt::Version = &opt.commands {
        println!("kubidmd {}", env!("KUBIDM_PKG_VERSION"));
        return ExitCode::SUCCESS;
    };

    if env!("KUBIDM_SERVER_CONFIG_PATH").is_empty() {
        eprintln!("CRITICAL: Kubidmd was not built correctly and is missing a valid KUBIDM_SERVER_CONFIG_PATH value");
        return ExitCode::FAILURE;
    }

    let default_config_path = PathBuf::from(env!("KUBIDM_SERVER_CONFIG_PATH"));

    let maybe_config_path = if let Some(p) = &opt.config_path {
        Some(p.clone())
    } else {
        // The user didn't ask for a file, lets check if the default path exists?
        if default_config_path.exists() {
            // It does, lets use it.
            Some(default_config_path)
        } else {
            // No default config, and no config specified, lets assume the user
            // has selected environment variables.
            None
        }
    };

    let maybe_sconfig = if let Some(config_path) = maybe_config_path {
        match ServerConfigUntagged::new(config_path) {
            Ok(c) => Some(c),
            Err(err) => {
                eprintln!("ERROR: Configuration Parse Failure: {err:?}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("WARNING: No configuration path was provided, relying on environment variables.");
        None
    };

    let is_server = matches!(&opt.commands, KubidmdOpt::Server);

    let config = Configuration::build()
        .add_opt_toml_config(maybe_sconfig)
        .add_cli_config(&opt.kubidmd_options)
        // set threads to 1 unless it's the main server.
        .is_server_mode(is_server)
        .finish();

    let Some(config) = config else {
        eprintln!(
            "ERROR: Unable to build server configuration from provided configuration inputs."
        );
        return ExitCode::FAILURE;
    };

    // ===========================================================================
    // Config ready

    // Get information on the windows username
    #[cfg(target_family = "windows")]
    get_user_details_windows();

    // Start the runtime
    let maybe_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.threads)
        .enable_all()
        .thread_name("kubidmd-thread-pool")
        // .thread_stack_size(8 * 1024 * 1024)
        // If we want a hook for thread start.
        // .on_thread_start()
        // In future, we can stop the whole process if a panic occurs.
        // .unhandled_panic(tokio::runtime::UnhandledPanic::ShutdownRuntime)
        .build();

    let rt = match maybe_rt {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("CRITICAL: Unable to start runtime! {err:?}");
            return ExitCode::FAILURE;
        }
    };

    // Choose where we go.

    let exit_code = if let KubidmdOpt::Scripting { command } = opt.commands {
        rt.block_on(scripting_command(command, config))
    } else if let KubidmdOpt::Maintenance(maintenance_opt) = opt.commands {
        maintenance_command(&maintenance_opt, &config, &rt)
    } else {
        rt.block_on(start_daemon(opt, config))
    };

    // Dropping the runtime would wait for every blocking task, however long it runs. The
    // server has stopped its tasks by now, but a scheduled backup verification abandoned
    // by the shutdown only stops at its next step, which can be minutes away on a large
    // database: never hold the exit for it. Its scratch directories are removed at the
    // next start. Every other command waits for its blocking work, so that a write it
    // left running is never cut short.
    if is_server {
        rt.shutdown_timeout(BLOCKING_TASKS_SHUTDOWN_TIMEOUT);
    } else {
        drop(rt);
    }
    exit_code
}

/// How long the exit of the server waits for blocking tasks still running once it stopped.
const BLOCKING_TASKS_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Build and execute the main server. The ServerConfig are the configuration options
/// that we are processing into the config for the main server.
async fn kubidm_main(config: Configuration, opt: KubidmdParser) -> ExitCode {
    match &opt.commands {
        KubidmdOpt::Server | KubidmdOpt::ConfigTest => {
            let config_test = matches!(&opt.commands, KubidmdOpt::ConfigTest);
            if config_test {
                info!("Running in server configuration test mode ...");
            } else {
                info!("Running in server mode ...");
            };

            // Verify the TLS configs.
            if let Some(tls_config) = config.tls_config.as_ref() {
                {
                    let i_meta = match metadata(&tls_config.chain) {
                        Ok(m) => m,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for TLS chain file '{}' - {:?}",
                                tls_config.chain.display(),
                                e
                            );
                            let diag =
                                kubidm_lib_file_permissions::diagnose_path(&tls_config.chain);
                            info!(%diag);
                            return ExitCode::FAILURE;
                        }
                    };
                    if !kubidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", tls_config.chain.display());
                    }
                }

                {
                    let i_meta = match metadata(&tls_config.key) {
                        Ok(m) => m,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for TLS key file '{}' - {:?}",
                                tls_config.key.display(),
                                e
                            );
                            let diag = kubidm_lib_file_permissions::diagnose_path(&tls_config.key);
                            info!(%diag);
                            return ExitCode::FAILURE;
                        }
                    };
                    if !kubidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", tls_config.key.display());
                    }
                    #[cfg(not(target_os = "windows"))]
                    if i_meta.mode() & 0o007 != 0 {
                        warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...", tls_config.key.display());
                    }
                }

                if let Some(ca_dir) = tls_config.client_ca.as_ref() {
                    // check that the TLS client CA config option is what we expect
                    let ca_dir_path = PathBuf::from(&ca_dir);
                    if !ca_dir_path.exists() {
                        error!(
                            "TLS CA folder {} does not exist, server startup will FAIL!",
                            ca_dir.display()
                        );
                        let diag = kubidm_lib_file_permissions::diagnose_path(&ca_dir_path);
                        info!(%diag);
                    }

                    let i_meta = match metadata(&ca_dir_path) {
                        Ok(m) => m,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for '{}' - {:?}",
                                ca_dir.display(),
                                e
                            );
                            let diag = kubidm_lib_file_permissions::diagnose_path(&ca_dir_path);
                            info!(%diag);
                            return ExitCode::FAILURE;
                        }
                    };
                    if !i_meta.is_dir() {
                        error!(
                            "ERROR: Refusing to run - TLS Client CA folder {} may not be a directory",
                            ca_dir.display()
                        );
                        return ExitCode::FAILURE;
                    }
                    if kubidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("WARNING: TLS Client CA folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", ca_dir.display());
                    }
                    #[cfg(not(target_os = "windows"))]
                    if i_meta.mode() & 0o007 != 0 {
                        warn!("WARNING: TLS Client CA folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", ca_dir.display());
                    }
                }
            }

            let sctx_result = create_server_core(config, config_test).await;

            let Ok(mut sctx) = sctx_result else {
                error!("Failed to start server core!");
                return ExitCode::FAILURE;
            };

            if config_test {
                // Config test is done and we didn't hit any errors, lets go.
                return ExitCode::SUCCESS;
            }

            // On linux, notify systemd.
            #[cfg(target_os = "linux")]
            unsafe {
                let _ = sd_notify::notify_and_unset_env(&[sd_notify::NotifyState::Ready]);
                let _ = sd_notify::notify_and_unset_env(&[sd_notify::NotifyState::Status(
                    "Started Kubidm 🦀",
                )]);
            }

            loop {
                #[cfg(target_family = "unix")]
                {
                    let mut listener = sctx.subscribe();
                    tokio::select! {
                        Ok(()) = tokio::signal::ctrl_c() => {
                            break
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::terminate();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            break
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::alarm();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::hangup();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Initiate a reload of server components.
                            sctx.reload().await;
                            info!("Reload complete");
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        // we got a message on thr broadcast from somewhere else
                        Ok(msg) = async move {
                            listener.recv().await
                        } =>
                            match msg {
                                CoreAction::Shutdown => break,
                                CoreAction::Reload => {}
                            },
                    }
                }
                #[cfg(target_family = "windows")]
                {
                    tokio::select! {
                        Ok(()) = tokio::signal::ctrl_c() => {
                            break
                        }
                    }
                }
            }

            info!("Signal received, shutting down");
            // Send a broadcast that we are done.
            sctx.shutdown().await;

            info!("Stopped 🛑 ");
        }
        KubidmdOpt::CertGenerate => {
            info!("Running in certificate generate mode ...");
            cert_generate_core(&config);
        }
        KubidmdOpt::Database {
            commands: DbCommands::Backup(bopt),
        } => {
            info!("Running in backup mode ...");

            if !backup_server_core(&config, Some(&bopt.path), None).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::Database {
            commands: DbCommands::Restore(ropt),
        } => {
            info!("Running in restore mode ...");
            return restore_exit_code(restore_server_core(&config, &ropt.path).await);
        }
        KubidmdOpt::Database {
            commands: DbCommands::Verify,
        } => {
            info!("Running in db verification mode ...");
            verify_server_core(&config).await;
        }
        KubidmdOpt::Database {
            commands: DbCommands::VerifyBackup(vbopt),
        } => {
            info!("Running in backup verification mode ...");
            let level = match vbopt.level {
                VerifyBackupLevel::Structural => BackupVerifyLevel::Structural,
                VerifyBackupLevel::Full => BackupVerifyLevel::Full,
            };
            if !verify_backup_server_core(&config, &vbopt.path, level).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::Database {
            commands: DbCommands::RestoreS3(ropt),
        } => {
            info!("Running in S3 restore mode ...");
            let Ok(s3_config) = s3_config_for_cli(
                &config,
                ropt.bucket.clone(),
                ropt.region.as_deref(),
                ropt.endpoint.clone(),
            ) else {
                return ExitCode::FAILURE;
            };
            return restore_exit_code(restore_s3_database(&config, s3_config, &ropt.key).await);
        }
        KubidmdOpt::Database {
            commands: DbCommands::VerifyS3(vopt),
        } => {
            info!("Running in S3 backup verification mode ...");
            let level = match vopt.level {
                VerifyBackupLevel::Structural => BackupVerifyLevel::Structural,
                VerifyBackupLevel::Full => BackupVerifyLevel::Full,
            };
            let Ok(s3_config) = s3_config_for_cli(
                &config,
                vopt.bucket.clone(),
                vopt.region.as_deref(),
                vopt.endpoint.clone(),
            ) else {
                return ExitCode::FAILURE;
            };
            if !verify_s3_backup_server_core(&config, s3_config, &vopt.key, level).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::Database {
            commands:
                DbCommands::ListBackups {
                    local_only,
                    s3_only,
                    region,
                },
        } => {
            info!("Running in backup listing mode ...");
            if !list_backups_server_core(&config, *local_only, *s3_only, region.as_deref()).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::ShowReplicationCertificate => {
            info!("Running show replication certificate ...");
            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::ShowReplicationCertificate,
            )
            .await;
        }
        KubidmdOpt::ShowReplicationCertificateMetadata => {
            info!("Running show replication certificate metadata ...");
            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::ShowReplicationCertificateMetadata,
            )
            .await;
        }

        KubidmdOpt::RenewReplicationCertificate => {
            info!("Running renew replication certificate ...");
            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::RenewReplicationCertificate,
            )
            .await;
        }
        KubidmdOpt::RefreshReplicationConsumer { proceed, from } => {
            info!("Running refresh replication consumer ...");
            match refresh_replication_consumer_request(*proceed, from.as_deref()) {
                Ok(req) => {
                    submit_admin_req_human(config.adminbindpath.as_str(), req).await;
                }
                Err(message) => error!("{message}"),
            }
        }
        KubidmdOpt::RecoverAccount { name } => {
            info!("Running account recovery ...");

            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::RecoverAccount {
                    name: name.to_owned(),
                },
            )
            .await;
        }
        KubidmdOpt::DisableAccount { name } => {
            info!("Running account disable ...");

            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DisableAccount {
                    name: name.to_owned(),
                },
            )
            .await;
        }
        KubidmdOpt::Database {
            commands: DbCommands::Reindex,
        } => {
            info!("Running in reindex mode ...");
            reindex_server_core(&config).await;
        }
        KubidmdOpt::DbScan {
            commands: DbScanOpt::ListIndexes,
        } => {
            info!("👀 db scan - list indexes");
            dbscan_list_indexes_core(&config);
        }
        KubidmdOpt::DbScan {
            commands: DbScanOpt::ListId2Entry,
        } => {
            info!("👀 db scan - list id2entry");
            dbscan_list_id2entry_core(&config);
        }
        KubidmdOpt::DbScan {
            commands: DbScanOpt::ListIndexAnalysis,
        } => {
            info!("👀 db scan - list index analysis");
            dbscan_list_index_analysis_core(&config);
        }
        KubidmdOpt::DbScan {
            commands: DbScanOpt::ListIndex(dopt),
        } => {
            info!("👀 db scan - list index content - {}", dopt.index_name);
            dbscan_list_index_core(&config, dopt.index_name.as_str());
        }
        KubidmdOpt::DbScan {
            commands: DbScanOpt::GetId2Entry(dopt),
        } => {
            info!("👀 db scan - get id2 entry - {}", dopt.id);
            dbscan_get_id2entry_core(&config, dopt.id);
        }

        KubidmdOpt::DbScan {
            commands: DbScanOpt::QuarantineId2Entry { id },
        } => {
            info!("☣️  db scan - quarantine id2 entry - {}", id);
            if !dbscan_quarantine_id2entry_core(&config, *id).await {
                return ExitCode::FAILURE;
            }
        }

        KubidmdOpt::DbScan {
            commands: DbScanOpt::ListQuarantined,
        } => {
            info!("☣️  db scan - list quarantined");
            dbscan_list_quarantined_core(&config);
        }

        KubidmdOpt::DbScan {
            commands: DbScanOpt::RestoreQuarantined { id },
        } => {
            info!("☣️  db scan - restore quarantined entry - {}", id);
            if !dbscan_restore_quarantined_core(&config, *id).await {
                return ExitCode::FAILURE;
            }
        }

        KubidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Change,
        } => {
            info!("Running in domain name change mode ... this may take a long time ...");
            domain_rename_core(&config).await;
        }

        KubidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Show,
        } => {
            info!("Running domain show ...");

            submit_admin_req_human(config.adminbindpath.as_str(), AdminTaskRequest::DomainShow)
                .await;
        }

        KubidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::UpgradeCheck,
        } => {
            info!("Running domain upgrade check ...");

            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainUpgradeCheck,
            )
            .await;
        }

        KubidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Raise,
        } => {
            info!("Running domain raise ...");

            submit_admin_req_human(config.adminbindpath.as_str(), AdminTaskRequest::DomainRaise)
                .await;
        }

        KubidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Remigrate { level },
        } => {
            info!("⚠️  Running domain remigrate ...");

            submit_admin_req_human(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainRemigrate { level: *level },
            )
            .await;
        }

        KubidmdOpt::Database {
            commands: DbCommands::Vacuum,
        } => {
            info!("Running in vacuum mode ...");
            vacuum_server_core(&config);
        }
        KubidmdOpt::Database {
            commands: DbCommands::Recover(ropt),
        } => {
            let target = match (
                &ropt.target.target_time,
                &ropt.target.target_cid,
                ropt.target.latest,
            ) {
                (Some(time), _, _) => RecoveryTargetSpec::Time(time.clone()),
                (None, Some(cid), _) => RecoveryTargetSpec::Cid(cid.clone()),
                (None, None, _) => RecoveryTargetSpec::Latest,
            };
            match &ropt.region {
                Some(region) => {
                    info!("Running point-in-time recovery to {target} from region {region} ...")
                }
                None => info!("Running point-in-time recovery to {target} ..."),
            }
            match pitr_recover_server_core(&config, &target, ropt.dry_run, ropt.region.as_deref())
                .await
            {
                Ok(_) if ropt.dry_run => {}
                Ok(outcome) if outcome.archive != RestoreStatus::Complete => {
                    warn!(
                        "Recovery finished: the database was recovered, but the WAL archive was \
                         not updated{}",
                        not_recorded_hint(outcome.archive)
                    );
                    return ExitCode::from(outcome.archive.exit_code());
                }
                Ok(_) => info!("✅ Recovery Success!"),
                Err(err) => {
                    error!(%err, "Point-in-time recovery failed");
                    return ExitCode::FAILURE;
                }
            }
        }
        KubidmdOpt::Database {
            commands: DbCommands::PitrList(lopt),
        } => {
            info!("Running in PITR listing mode ...");
            if !pitr_list_server_core(&config, lopt.region.as_deref()).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::Database {
            commands: DbCommands::ReplicateStatus { detailed, deep },
        } => {
            info!("Running in backup replication status mode ...");
            if !replicate_status_server_core(&config, *detailed, *deep).await {
                return ExitCode::FAILURE;
            }
        }
        KubidmdOpt::Scripting { .. } | KubidmdOpt::Maintenance(_) | KubidmdOpt::Version => {}
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const OP: &str = "6f0c1d52-2f64-4b3e-9a5e-0f6a8c2a7d11";

    fn op() -> Uuid {
        Uuid::parse_str(OP).unwrap_or_default()
    }

    fn parse(args: &[&str]) -> Result<MaintenanceOpt, clap::Error> {
        let mut argv = vec!["kubidmd", "maintenance"];
        argv.extend_from_slice(args);
        KubidmdParser::try_parse_from(argv).and_then(|parsed| match parsed.commands {
            KubidmdOpt::Maintenance(opt) => Ok(opt),
            _ => Err(clap::Error::new(clap::error::ErrorKind::InvalidSubcommand)),
        })
    }

    fn request(args: &[&str]) -> Result<AdminTaskRequest, String> {
        let opt = parse(args).map_err(|err| err.to_string())?;
        maintenance_request(&opt.commands)
    }

    fn fence() -> ReplicationFence {
        ReplicationFence {
            version: 1,
            domain_uuid: Uuid::nil(),
            generation: None,
            ranges: BTreeMap::new(),
        }
    }

    fn refresh_request(args: &[&str]) -> Result<AdminTaskRequest, String> {
        let mut argv = vec!["kubidmd", "refresh-replication-consumer"];
        argv.extend_from_slice(args);
        match KubidmdParser::try_parse_from(argv)
            .map_err(|err| err.to_string())?
            .commands
        {
            KubidmdOpt::RefreshReplicationConsumer { proceed, from } => {
                refresh_replication_consumer_request(proceed, from.as_deref())
            }
            _ => Err("not a refresh-replication-consumer command".to_string()),
        }
    }

    #[test]
    fn refresh_replication_consumer_maps_to_request() {
        assert!(matches!(
            refresh_request(&["--i-want-to-refresh-this-servers-database"]),
            Ok(AdminTaskRequest::RefreshReplicationConsumer { from: None })
        ));
        assert!(matches!(
            refresh_request(&[
                "--i-want-to-refresh-this-servers-database",
                "--from",
                "repl://pod-1.example.com:8444",
            ]),
            Ok(AdminTaskRequest::RefreshReplicationConsumer { from: Some(ref from) })
                if from == "repl://pod-1.example.com:8444"
        ));
        // Nothing is sent without the acknowledgement, with or without a source.
        assert!(refresh_request(&[]).is_err());
        assert!(refresh_request(&["--from", "repl://pod-1.example.com:8444"]).is_err());
        // --from needs a value.
        assert!(refresh_request(&["--i-want-to-refresh-this-servers-database", "--from"]).is_err());
    }

    #[test]
    fn maintenance_simple_subcommands_map_to_requests() {
        assert!(matches!(
            request(&["capabilities"]),
            Ok(AdminTaskRequest::MaintenanceCapabilities)
        ));
        assert!(matches!(
            request(&["status"]),
            Ok(AdminTaskRequest::MaintenanceStatus)
        ));
        assert!(matches!(
            request(&["fence"]),
            Ok(AdminTaskRequest::ReplicationFence)
        ));
    }

    #[test]
    fn maintenance_operation_subcommands_map_to_requests() {
        assert!(matches!(
            request(&["drain", "--operation-id", OP]),
            Ok(AdminTaskRequest::MaintenanceDrain { operation_id }) if operation_id == op()
        ));
        assert!(matches!(
            request(&["resume", "--operation-id", OP]),
            Ok(AdminTaskRequest::MaintenanceResume { operation_id }) if operation_id == op()
        ));
        assert!(matches!(
            request(&["run", "--operation-id", OP, "reindex"]),
            Ok(AdminTaskRequest::MaintenanceRun {
                operation_id,
                operation: MaintenanceOperation::Reindex,
            }) if operation_id == op()
        ));
        assert!(matches!(
            request(&["run", "--operation-id", OP, "verify"]),
            Ok(AdminTaskRequest::MaintenanceRun {
                operation_id,
                operation: MaintenanceOperation::Verify,
            }) if operation_id == op()
        ));
    }

    #[test]
    fn maintenance_sync_until_maps_fence_and_timeout() {
        let wanted = fence();
        let json = json_text(&wanted);

        let with_timeout = request(&[
            "sync-until",
            "--operation-id",
            OP,
            "--fence",
            &json,
            "--timeout-seconds",
            "90",
        ]);
        assert!(matches!(
            with_timeout,
            Ok(AdminTaskRequest::ReplicationSyncUntil {
                operation_id,
                ref fence,
                timeout_seconds: Some(90),
            }) if operation_id == op() && *fence == wanted
        ));

        let default_timeout = request(&["sync-until", "--operation-id", OP, "--fence", &json]);
        assert!(matches!(
            default_timeout,
            Ok(AdminTaskRequest::ReplicationSyncUntil {
                timeout_seconds: None,
                ..
            })
        ));
    }

    #[test]
    fn maintenance_sync_until_reads_a_fence_file() {
        let path = std::env::temp_dir().join(format!("kubidmd-fence-{}.json", std::process::id()));
        assert!(std::fs::write(&path, json_text(&fence())).is_ok());
        let path_str = path.to_string_lossy().to_string();

        let req = request(&[
            "sync-until",
            "--operation-id",
            OP,
            "--fence-file",
            &path_str,
        ]);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            req,
            Ok(AdminTaskRequest::ReplicationSyncUntil { ref fence, .. }) if *fence == self::fence()
        ));

        let missing = request(&[
            "sync-until",
            "--operation-id",
            OP,
            "--fence-file",
            "/nonexistent/kubidmd-fence.json",
        ]);
        assert!(matches!(missing, Err(ref msg) if msg.contains("Unable to read")));
    }

    #[test]
    fn maintenance_sync_until_rejects_a_bad_fence() {
        let invalid = request(&["sync-until", "--operation-id", OP, "--fence", "{not json"]);
        assert!(matches!(invalid, Err(ref msg) if msg.contains("Invalid replication fence")));
    }

    #[test]
    fn maintenance_arguments_are_validated() {
        // The operation ID is required, and must be a UUID.
        assert!(parse(&["drain"]).is_err());
        assert!(parse(&["drain", "--operation-id", "not-a-uuid"]).is_err());
        assert!(parse(&["resume"]).is_err());
        // `run` needs a known operation.
        assert!(parse(&["run", "--operation-id", OP]).is_err());
        assert!(parse(&["run", "--operation-id", OP, "vacuum"]).is_err());
        // Exactly one fence source.
        assert!(parse(&["sync-until", "--operation-id", OP]).is_err());
        assert!(parse(&[
            "sync-until",
            "--operation-id",
            OP,
            "--fence",
            "{}",
            "--fence-file",
            "/tmp/fence.json",
        ])
        .is_err());
        // There is no subcommand without a name.
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn maintenance_output_option() {
        assert_eq!(
            parse(&["status"]).map(|opt| opt.output).ok(),
            Some(MaintenanceOutput::Human)
        );
        assert_eq!(
            parse(&["-o", "json", "status"]).map(|opt| opt.output).ok(),
            Some(MaintenanceOutput::Json)
        );
        assert_eq!(
            parse(&["status", "--output", "json"])
                .map(|opt| opt.output)
                .ok(),
            Some(MaintenanceOutput::Json)
        );
        assert!(parse(&["-o", "yaml", "status"]).is_err());
    }

    #[test]
    fn maintenance_busy_is_retryable_in_both_formats() {
        let busy = AdminTaskResponse::MaintenanceError {
            code: MaintenanceErrorCode::Busy,
            message: "step in progress".to_string(),
        };

        let human = maintenance_outcome(&busy, MaintenanceOutput::Human);
        assert!(!human.success);
        assert!(human.text.contains("busy"));
        assert!(human.text.contains("retryable"));

        let json = maintenance_outcome(&busy, MaintenanceOutput::Json);
        assert!(!json.success);
        let value: serde_json::Value = serde_json::from_str(&json.text).unwrap_or_default();
        assert_eq!(value["status"], "error");
        assert_eq!(value["reason"], "busy");
        assert_eq!(value["retryable"], true);

        let other = AdminTaskResponse::MaintenanceError {
            code: MaintenanceErrorCode::InvalidState,
            message: "not drained".to_string(),
        };
        let json = maintenance_outcome(&other, MaintenanceOutput::Json);
        let value: serde_json::Value = serde_json::from_str(&json.text).unwrap_or_default();
        assert_eq!(value["reason"], "invalid_state");
        assert_eq!(value["retryable"], false);
    }

    #[test]
    fn maintenance_drain_output_carries_a_reusable_fence() {
        let drained = AdminTaskResponse::MaintenanceDrain {
            operation_id: op(),
            fence: fence(),
        };

        let json = maintenance_outcome(&drained, MaintenanceOutput::Json);
        assert!(json.success);
        let value: serde_json::Value = serde_json::from_str(&json.text).unwrap_or_default();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["output"]["operation_id"], OP);
        // The printed fence is what `sync-until --fence` accepts.
        let parsed: Result<ReplicationFence, _> =
            serde_json::from_value(value["output"]["fence"].clone());
        assert!(matches!(parsed, Ok(ref f) if *f == fence()));

        let human = maintenance_outcome(&drained, MaintenanceOutput::Human);
        assert!(human.success);
        assert!(human.text.contains(OP));
        assert!(human.text.contains(&json_text(&fence())));
    }

    #[test]
    fn maintenance_run_and_sync_results_set_the_exit_state() {
        let run = |success| AdminTaskResponse::MaintenanceRun {
            result: kubidmd_core::admin::MaintenanceRunResult {
                operation_id: op(),
                operation: MaintenanceOperation::Verify,
                success,
                verification_errors: if success {
                    Vec::new()
                } else {
                    vec!["entry 4 is broken".to_string()]
                },
                fence: None,
                error: None,
            },
        };
        assert!(maintenance_outcome(&run(true), MaintenanceOutput::Human).success);
        let failed = maintenance_outcome(&run(false), MaintenanceOutput::Human);
        assert!(!failed.success);
        assert!(failed.text.contains("entry 4 is broken"));

        let sync = |result| AdminTaskResponse::ReplicationSyncUntil {
            result,
            current_fence: fence(),
        };
        assert!(
            maintenance_outcome(
                &sync(ReplicationSyncResult::Satisfied),
                MaintenanceOutput::Human
            )
            .success
        );

        let timed_out = maintenance_outcome(
            &sync(ReplicationSyncResult::TimedOut),
            MaintenanceOutput::Json,
        );
        assert!(!timed_out.success);
        let value: serde_json::Value = serde_json::from_str(&timed_out.text).unwrap_or_default();
        assert_eq!(value["reason"], "timed_out");
        assert_eq!(value["retryable"], true);

        let mismatch = maintenance_outcome(
            &sync(ReplicationSyncResult::DomainMismatch),
            MaintenanceOutput::Json,
        );
        assert!(!mismatch.success);
        let value: serde_json::Value = serde_json::from_str(&mismatch.text).unwrap_or_default();
        assert_eq!(value["retryable"], false);
    }

    #[test]
    fn maintenance_status_output() {
        let response: Result<AdminTaskResponse, _> = serde_json::from_value(serde_json::json!({
            "MaintenanceStatus": {
                "status": {
                    "state": "fenced",
                    "active_operation_id": OP,
                    "last_error": null,
                    "capabilities": {
                        "api_version": "v1",
                        "drain": true,
                        "replication_fence": true,
                        "sync_until": true,
                        "reindex": true,
                        "verify": true,
                        "vacuum": false,
                        "restore": false
                    }
                },
                "fence": null
            }
        }));
        assert!(response.is_ok(), "the status response must deserialize");
        let Ok(response) = response else {
            return;
        };

        let human = maintenance_outcome(&response, MaintenanceOutput::Human);
        assert!(human.success);
        assert!(human.text.contains("fenced"));
        assert!(human.text.contains(OP));
        assert!(human.text.contains("none"));

        let json = maintenance_outcome(&response, MaintenanceOutput::Json);
        let value: serde_json::Value = serde_json::from_str(&json.text).unwrap_or_default();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["output"]["status"]["state"], "fenced");
        assert_eq!(value["output"]["status"]["active_operation_id"], OP);
    }
}
