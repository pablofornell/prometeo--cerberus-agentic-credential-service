//! The CLI commands. Output goes to stdout; errors go back to `main`, which prints only the
//! code and the request ID. A secret is printed only by `get --show-secret` and
//! `totp --show-secret`, and by nothing else.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::time::Duration;

use cerberus_client::run::{self, RunOptions};
use cerberus_client::{Client, ClientError, TotpResult};
use cerberus_types::ItemId;
use cerberus_types::wire::{
    ApiKeySecret, BrowserSessionSecret, CreateItemRequest, CreateSessionRequest, ItemKind,
    NoteSecret, ResolveMode, ResolveRequest, ResolveResponse, SecretPayload, SecretResponse,
    SessionPayload, SessionTokenSecret, TotpRequest, WireSecret,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::Target;

/// Smallest reason text the server accepts.
const MIN_PURPOSE: usize = 8;

fn emit(text: &str) {
    // A closed pipe is not an error of this command.
    let _ = writeln!(std::io::stdout(), "{text}");
}

fn emit_json(value: &impl Serialize) -> Result<(), ClientError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|_| ClientError::Decode("cannot encode the output".to_owned()))?;
    emit(&text);
    Ok(())
}

fn purpose(given: Option<String>, what: &str) -> Result<String, ClientError> {
    let text = given.unwrap_or_else(|| format!("cerberus cli: {what}"));
    if text.chars().count() < MIN_PURPOSE {
        return Err(ClientError::Config(format!(
            "the purpose needs at least {MIN_PURPOSE} characters"
        )));
    }
    Ok(text)
}

fn environment(text: &str) -> Result<cerberus_types::wire::Environment, ClientError> {
    crate::parse_environment(text).map_err(ClientError::Config)
}

pub async fn status(client: &Client) -> Result<(), ClientError> {
    emit_json(&client.status().await?)
}

#[allow(clippy::too_many_arguments, reason = "one argument per CLI option")]
pub async fn find(
    client: &Client,
    app: String,
    environment: Option<String>,
    role: Option<String>,
    kind: Option<ItemKind>,
    hint: Option<String>,
    purpose_text: Option<String>,
    json: bool,
) -> Result<(), ClientError> {
    let request = ResolveRequest {
        app,
        environment,
        role,
        kind,
        hint,
        purpose: purpose(purpose_text, "find")?,
        mode: Some(ResolveMode::Candidates),
    };
    let ResolveResponse::Candidates(found) = client.resolve(&request).await? else {
        return Err(ClientError::Decode(
            "expected a list of candidates".to_owned(),
        ));
    };
    if json {
        return emit_json(&found);
    }
    for candidate in &found.candidates {
        let item = &candidate.item;
        emit(&format!(
            "{}  {}  {}  {}  {}",
            item.id,
            serde_label(&item.kind),
            serde_label(&item.environment),
            item.role_label.as_deref().unwrap_or("-"),
            item.title
        ));
    }
    Ok(())
}

/// The snake_case wire name of an enum value.
fn serde_label(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn reveal_target(
    client: &Client,
    target: &Target,
    purpose_text: &str,
    wait: Duration,
) -> Result<SecretResponse, ClientError> {
    match (&target.id, &target.app) {
        (Some(id), _) => run::reveal_with_approval(client, *id, purpose_text, wait).await,
        (None, Some(app)) => {
            let request = ResolveRequest {
                app: app.clone(),
                environment: target.environment.clone(),
                role: target.role.clone(),
                kind: target.kind,
                hint: None,
                purpose: purpose_text.to_owned(),
                mode: Some(ResolveMode::Best),
            };
            run::resolve_secret(client, &request, wait).await
        }
        (None, None) => Err(ClientError::Config("give --id or --app".to_owned())),
    }
}

pub async fn get(
    client: &Client,
    target: Target,
    purpose_text: Option<String>,
    show_secret: bool,
    field: Option<String>,
    wait: Duration,
) -> Result<(), ClientError> {
    let purpose_text = purpose(purpose_text, "get")?;
    let revealed = reveal_target(client, &target, &purpose_text, wait).await?;
    if show_secret {
        let mut out = std::io::stdout().lock();
        let written = match field {
            Some(name) => {
                let value = run::field_value(&revealed.secret, &name).ok_or_else(|| {
                    ClientError::Config(format!("this item has no field {name:?}"))
                })?;
                writeln!(out, "{}", value.expose())
            }
            None => serde_json::to_writer_pretty(&mut out, &revealed)
                .map_err(std::io::Error::from)
                .and_then(|()| writeln!(out)),
        };
        // A closed pipe is not an error of this command.
        let _ = written;
        release(client, &revealed).await;
        return Ok(());
    }
    let fields: BTreeMap<String, String> = run::field_names(&revealed.secret)
        .into_iter()
        .map(|(name, secret)| {
            let shown = if secret {
                "[REDACTED]".to_owned()
            } else {
                run::field_value(&revealed.secret, &name)
                    .map(|v| v.expose().to_owned())
                    .unwrap_or_default()
            };
            (name, shown)
        })
        .collect();
    emit_json(&serde_json::json!({
        "handling": revealed.handling,
        "request_id": revealed.request_id,
        "item": revealed.item,
        "secret_fields": fields,
        "lease": revealed.lease,
        "note": "secret values are hidden; pass --show-secret to print them, or use `cerberus run`",
    }))?;
    release(client, &revealed).await;
    Ok(())
}

/// The value was printed or hidden, so nothing uses the lease any more and it can end now.
async fn release(client: &Client, revealed: &SecretResponse) {
    if let Err(error) = client
        .release_lease(cerberus_types::LeaseId(revealed.lease.id))
        .await
    {
        run::report(&error);
    }
}

pub async fn totp(
    client: &Client,
    id: ItemId,
    purpose_text: Option<String>,
    show_secret: bool,
    wait: Duration,
) -> Result<(), ClientError> {
    let purpose_text = purpose(purpose_text, "totp")?;
    let first = TotpRequest {
        purpose: purpose_text.clone(),
        lease_id: None,
    };
    let code = match client.totp(id, &first).await? {
        TotpResult::Code(code) => *code,
        TotpResult::Pending(pending) => {
            let lease = run::approved_lease(client, &pending, wait).await?;
            let second = TotpRequest {
                purpose: purpose_text,
                lease_id: Some(lease),
            };
            match client.totp(id, &second).await? {
                TotpResult::Code(code) => *code,
                TotpResult::Pending(_) => {
                    return Err(ClientError::NotApproved("pending".to_owned()));
                }
            }
        }
    };
    if show_secret {
        emit(code.code.expose());
    } else {
        emit_json(&serde_json::json!({
            "handling": code.handling,
            "request_id": code.request_id,
            "code": "[REDACTED]",
            "period": code.period,
            "expires_in_seconds": code.expires_in_seconds,
            "note": "the code is hidden; pass --show-secret to print it",
        }))?;
    }
    Ok(())
}

pub async fn delete(client: &Client, id: ItemId) -> Result<(), ClientError> {
    client.delete_item(id).await?;
    emit(&format!("deleted {id}"));
    Ok(())
}

pub struct StoreArgs {
    pub workspace: String,
    pub title: String,
    pub environment: String,
    pub kind: ItemKind,
    pub json: bool,
    pub session: bool,
    pub origin: Option<String>,
    pub role: Option<String>,
    pub target: Option<String>,
    pub description: Option<String>,
    pub ttl: Option<u32>,
    pub max_uses: Option<u32>,
}

/// Reads standard input. The buffer is zeroized on drop.
fn read_stdin() -> Result<Zeroizing<String>, ClientError> {
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().lock().read_to_string(&mut input)?;
    Ok(input)
}

/// The value without one trailing newline.
fn trim_newline(input: &str) -> &str {
    let input = input.strip_suffix('\n').unwrap_or(input);
    input.strip_suffix('\r').unwrap_or(input)
}

fn bad_input(text: &str) -> ClientError {
    ClientError::Config(text.to_owned())
}

pub async fn store(client: &Client, args: StoreArgs) -> Result<(), ClientError> {
    let environment = environment(&args.environment)?;
    let input = read_stdin()?;
    let raw = || WireSecret::new(trim_newline(&input).to_owned());
    if args.session {
        let payload = if args.json {
            serde_json::from_str::<SessionPayload>(&input)
                .map_err(|_| bad_input("standard input is not a session payload"))?
        } else {
            match args.kind {
                ItemKind::SessionToken => SessionPayload::SessionToken(SessionTokenSecret {
                    token: raw(),
                    token_type: None,
                    header_name: None,
                }),
                ItemKind::BrowserSession => SessionPayload::BrowserSession(BrowserSessionSecret {
                    storage_state: raw(),
                    origin: args
                        .origin
                        .clone()
                        .ok_or_else(|| bad_input("a browser session needs --origin"))?,
                }),
                _ => {
                    return Err(bad_input(
                        "--session takes the kinds session_token and browser_session",
                    ));
                }
            }
        };
        let created = client
            .create_session(&CreateSessionRequest {
                workspace: args.workspace,
                title: args.title,
                description: args.description,
                environment,
                role_label: args.role,
                target: args.target,
                ttl_seconds: args.ttl,
                payload,
            })
            .await?;
        return emit_json(&created);
    }
    let payload = if args.json {
        serde_json::from_str::<SecretPayload>(&input)
            .map_err(|_| bad_input("standard input is not a payload"))?
    } else {
        match args.kind {
            ItemKind::ApiKey => SecretPayload::ApiKey(ApiKeySecret {
                key: raw(),
                key_id: None,
                header_name: None,
                base_url: None,
            }),
            ItemKind::SessionToken => SecretPayload::SessionToken(SessionTokenSecret {
                token: raw(),
                token_type: None,
                header_name: None,
            }),
            ItemKind::Note => SecretPayload::Note(NoteSecret { text: raw() }),
            _ => {
                return Err(bad_input(
                    "this kind needs --json with the full payload on standard input",
                ));
            }
        }
    };
    let created = client
        .create_item(&CreateItemRequest {
            workspace: args.workspace,
            title: args.title,
            description: args.description,
            environment,
            role_label: args.role,
            category: None,
            tags: None,
            target: args.target,
            ttl_seconds: args.ttl,
            max_uses: args.max_uses,
            payload,
            totp: None,
        })
        .await?;
    emit_json(&created)
}

#[allow(clippy::too_many_arguments, reason = "one argument per CLI option")]
pub async fn run(
    client: &Client,
    target: Target,
    vars: Vec<(String, String)>,
    purpose_text: Option<String>,
    mask_output: bool,
    pass_token: bool,
    wait: Duration,
    command: Vec<OsString>,
) -> i32 {
    let default = command
        .first()
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default();
    let purpose_text = match purpose(purpose_text, &format!("run {default}")) {
        Ok(text) => text,
        Err(error) => {
            run::report(&error);
            return error.exit_code();
        }
    };
    run::run(
        client,
        RunOptions {
            app: target.app.unwrap_or_default(),
            environment: target.environment,
            role: target.role,
            kind: target.kind,
            item_id: target.id,
            purpose: purpose_text,
            vars,
            mask_output,
            pass_token,
            wait,
            command,
        },
    )
    .await
}
