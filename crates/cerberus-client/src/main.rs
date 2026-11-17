//! `cerberus`: command line client of the Cerberus agent API.

mod commands;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use cerberus_client::{Client, ClientConfig, Overrides};
use cerberus_types::ItemId;
use cerberus_types::wire::{Environment, ItemKind};
use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cerberus",
    version,
    about = "Client of the Cerberus credential vault",
    long_about = "Client of the Cerberus credential vault. The token comes from CERBERUS_TOKEN or a \
                  token file (mode 0600), never from an argument. The server is trusted only through \
                  the CA pin or the CA file."
)]
struct Cli {
    #[command(flatten)]
    conn: Connection,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Connection {
    /// Service URL (default https://127.0.0.1:7373).
    #[arg(long, env = "CERBERUS_URL", global = true)]
    url: Option<String>,
    /// File that holds the token (mode 0600).
    #[arg(long, env = "CERBERUS_TOKEN_FILE", global = true)]
    token_file: Option<PathBuf>,
    /// PEM file of the Cerberus CA.
    #[arg(long, env = "CERBERUS_CA_FILE", global = true)]
    ca_file: Option<PathBuf>,
    /// Pin of the CA key: sha256/<base64>.
    #[arg(long, env = "CERBERUS_CA_PIN", global = true)]
    ca_pin: Option<String>,
    /// Client certificate (PEM) for mTLS.
    #[arg(long, env = "CERBERUS_CLIENT_CERT", global = true)]
    client_cert: Option<PathBuf>,
    /// Client key (PEM) for mTLS.
    #[arg(long, env = "CERBERUS_CLIENT_KEY", global = true)]
    client_key: Option<PathBuf>,
}

/// How to pick one item.
#[derive(Args, Clone)]
pub struct Target {
    /// Item ID. Skips the search.
    #[arg(long)]
    pub id: Option<ItemId>,
    /// App name to search for.
    #[arg(long, required_unless_present = "id")]
    pub app: Option<String>,
    /// Environment: dev, staging, prod, other.
    #[arg(long = "env")]
    pub environment: Option<String>,
    /// Role label, for example admin.
    #[arg(long)]
    pub role: Option<String>,
    /// Item kind, for example web_login.
    #[arg(long, value_parser = parse_kind)]
    pub kind: Option<ItemKind>,
}

#[derive(Subcommand)]
enum Command {
    /// Show the vault state and the identity of this token.
    Status,
    /// Find items by app. Shows metadata only, never secrets.
    Find {
        /// App name.
        #[arg(long)]
        app: String,
        /// Environment: dev, staging, prod, other.
        #[arg(long = "env")]
        environment: Option<String>,
        /// Role label.
        #[arg(long)]
        role: Option<String>,
        /// Item kind.
        #[arg(long, value_parser = parse_kind)]
        kind: Option<ItemKind>,
        /// Free text hint.
        #[arg(long)]
        hint: Option<String>,
        /// Reason for the audit log (at least 8 characters).
        #[arg(long)]
        purpose: Option<String>,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Get a secret. The values are hidden unless you pass --show-secret.
    Get {
        #[command(flatten)]
        target: Target,
        /// Reason for the audit log (at least 8 characters).
        #[arg(long)]
        purpose: Option<String>,
        /// Print the secret values. Without it they show as [REDACTED].
        #[arg(long)]
        show_secret: bool,
        /// With --show-secret: print only this field, raw.
        #[arg(long, requires = "show_secret")]
        field: Option<String>,
        /// Longest wait for an approval, in seconds.
        #[arg(long, default_value_t = 120)]
        wait: u64,
    },
    /// Store a secret. The value is read from standard input, never from an argument.
    Store {
        /// Workspace slug.
        #[arg(long)]
        workspace: String,
        /// Title of the item.
        #[arg(long)]
        title: String,
        /// Environment: dev, staging, prod, other.
        #[arg(long = "env", default_value = "dev")]
        environment: String,
        /// Kind: api_key, session_token, browser_session and note read the raw value from standard input.
        #[arg(long, value_parser = parse_kind, default_value = "api_key")]
        kind: ItemKind,
        /// Standard input is the full JSON payload ({"kind": "...", ...}). Any kind.
        #[arg(long)]
        json: bool,
        /// Save as a session item (POST /v1/sessions). Kinds session_token and browser_session.
        #[arg(long)]
        session: bool,
        /// Origin of a browser session.
        #[arg(long)]
        origin: Option<String>,
        /// Role label.
        #[arg(long)]
        role: Option<String>,
        /// Target, for example a URL.
        #[arg(long)]
        target: Option<String>,
        /// Description.
        #[arg(long)]
        description: Option<String>,
        /// Time to live in seconds.
        #[arg(long)]
        ttl: Option<u32>,
        /// Maximum number of reads.
        #[arg(long)]
        max_uses: Option<u32>,
    },
    /// Get the current TOTP code. Hidden unless you pass --show-secret.
    Totp {
        /// Item ID.
        id: ItemId,
        /// Reason for the audit log (at least 8 characters).
        #[arg(long)]
        purpose: Option<String>,
        /// Print the code.
        #[arg(long)]
        show_secret: bool,
        /// Longest wait for an approval, in seconds.
        #[arg(long, default_value_t = 120)]
        wait: u64,
    },
    /// Delete an item that this agent created.
    Delete {
        /// Item ID.
        id: ItemId,
    },
    /// Run a command with the secret in its environment only. Output is masked.
    Run {
        #[command(flatten)]
        target: Target,
        /// Variable from a field: NAME=field. When given, only these variables are set.
        #[arg(long = "var", alias = "map", value_name = "NAME=field", value_parser = parse_var)]
        vars: Vec<(String, String)>,
        /// Reason for the audit log (at least 8 characters).
        #[arg(long)]
        purpose: Option<String>,
        /// Do not mask secrets in the output of the command.
        #[arg(long)]
        no_mask: bool,
        /// Keep CERBERUS_TOKEN in the environment of the command.
        #[arg(long)]
        pass_token: bool,
        /// Longest wait for an approval, in seconds.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },
    /// Print a shell completion script.
    Completions {
        /// Shell.
        shell: clap_complete::Shell,
    },
}

fn parse_kind(text: &str) -> Result<ItemKind, String> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| format!("unknown kind {text:?}"))
}

/// Parses an environment name.
pub fn parse_environment(text: &str) -> Result<Environment, String> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| format!("unknown environment {text:?} (dev, staging, prod, other)"))
}

fn parse_var(text: &str) -> Result<(String, String), String> {
    match text.split_once('=') {
        Some((name, field)) if !name.is_empty() && !field.is_empty() => {
            Ok((name.to_owned(), field.to_owned()))
        }
        _ => Err("expected NAME=field".to_owned()),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Completions { shell } = &cli.command {
        let mut command = Cli::command();
        clap_complete::generate(*shell, &mut command, "cerberus", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cerberus: cannot start the runtime: {error}");
            return ExitCode::from(74);
        }
    };
    let code = runtime.block_on(execute(cli));
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

async fn execute(cli: Cli) -> i32 {
    let overrides = Overrides {
        url: cli.conn.url,
        token_file: cli.conn.token_file,
        ca_file: cli.conn.ca_file,
        ca_pin: cli.conn.ca_pin,
        client_cert: cli.conn.client_cert,
        client_key: cli.conn.client_key,
    };
    let client = match ClientConfig::load(&overrides).and_then(|config| Client::new(&config)) {
        Ok(client) => client,
        Err(error) => {
            cerberus_client::run::report(&error);
            return error.exit_code();
        }
    };
    let result = match cli.command {
        Command::Status => commands::status(&client).await,
        Command::Find {
            app,
            environment,
            role,
            kind,
            hint,
            purpose,
            json,
        } => commands::find(&client, app, environment, role, kind, hint, purpose, json).await,
        Command::Get {
            target,
            purpose,
            show_secret,
            field,
            wait,
        } => {
            commands::get(
                &client,
                target,
                purpose,
                show_secret,
                field,
                Duration::from_secs(wait),
            )
            .await
        }
        Command::Store {
            workspace,
            title,
            environment,
            kind,
            json,
            session,
            origin,
            role,
            target,
            description,
            ttl,
            max_uses,
        } => {
            commands::store(
                &client,
                commands::StoreArgs {
                    workspace,
                    title,
                    environment,
                    kind,
                    json,
                    session,
                    origin,
                    role,
                    target,
                    description,
                    ttl,
                    max_uses,
                },
            )
            .await
        }
        Command::Totp {
            id,
            purpose,
            show_secret,
            wait,
        } => commands::totp(&client, id, purpose, show_secret, Duration::from_secs(wait)).await,
        Command::Delete { id } => commands::delete(&client, id).await,
        Command::Run {
            target,
            vars,
            purpose,
            no_mask,
            pass_token,
            wait,
            command,
        } => {
            return commands::run(
                &client,
                target,
                vars,
                purpose,
                !no_mask,
                pass_token,
                Duration::from_secs(wait),
                command,
            )
            .await;
        }
        Command::Completions { .. } => Ok(()),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            cerberus_client::run::report(&error);
            error.exit_code()
        }
    }
}
