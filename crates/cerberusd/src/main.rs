//! Command line of `cerberusd`: `serve`, `unlock`, `status`, `setup-code` (ADR-0002, DEC-SRV-3), `backup` (ADR-0031) and `admin`
//! (ADR-0034). See `docs/guides/cerberusd.md`.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use cerberus_crypto::memlock::{self, HardeningReport};
use cerberusd::admin::{self, EnrollRequest, Source};
use cerberusd::config::{self, Config};
use cerberusd::{backup, daemon, setup, status, unlock};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};

/// The command line.
#[derive(Parser)]
#[command(
    name = "cerberusd",
    version,
    about = "Cerberus headless daemon: serves the Agent API for a vault that the first client creates over the network, or that is copied from the desktop app."
)]
struct Cli {
    /// Config file. Without this flag the default file is read when it exists.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

/// The commands.
#[derive(Subcommand)]
enum Command {
    /// Serve the Agent API. The vault starts sealed. Unlock it with `cerberusd unlock`. With no vault in the data
    /// directory the daemon waits for the first client to create it (see `setup-code`).
    Serve,
    /// Print the setup code of a daemon that waits for its first client. Paste it into the desktop app to create
    /// the vault. It is a secret until the vault exists.
    SetupCode,
    /// Unlock a running daemon. Asks for the passphrase here, with echo off.
    Unlock {
        /// Operator label. Needed when the vault has more than one owner.
        #[arg(long, value_name = "LABEL")]
        operator: Option<String>,
    },
    /// Check a running daemon over HTTPS. Also shows the CA pin and whether the admin API is on.
    Status,
    /// Make a consistent backup of the vault. Safe while the daemon runs. Needs no passphrase.
    Backup {
        /// A folder, or a file name that ends in `.cerberus-backup`. A folder gets the file
        /// `cerberus-<vault short id>-<UTC time>.cerberus-backup`.
        #[arg(long, value_name = "FOLDER|FILE")]
        out: PathBuf,
        /// Keep this many newest backups of this vault in the folder and remove the older ones that this command
        /// made. Other files are never removed.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
        keep: Option<u32>,
    },
    /// Enrol, list and revoke desktops for the admin API (`[admin] enabled = true`).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

/// The `admin` commands (ADR-0034 point 3).
#[derive(Subcommand)]
enum AdminCommand {
    /// Enrol a desktop: asks for an owner passphrase here, with echo off, and writes a bundle file.
    /// The vault must be unlocked.
    Enroll {
        /// A name for the desktop, 1 to 64 characters.
        #[arg(long, value_name = "TEXT")]
        label: String,
        /// The URL the desktop reaches this daemon at (an SSH tunnel end, for example).
        #[arg(long, value_name = "https://HOST:PORT")]
        url: String,
        /// The owner who types the passphrase. Needed when the vault has more than one owner.
        #[arg(long, value_name = "LABEL")]
        owner: Option<String>,
        /// The operator whose passphrase opens a session with this bundle. Default: the owner.
        #[arg(long, value_name = "LABEL")]
        operator: Option<String>,
        /// The bundle file to write (mode 0600). It must not exist.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// List the enrolments.
    List,
    /// Revoke an enrolment. Its sessions end at once when the daemon runs.
    Revoke {
        /// The enrolment ID (from `cerberusd admin list`).
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let report = memlock::harden_process();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cerberusd: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli, report)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cerberusd: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli, report: HardeningReport) -> Result<(), String> {
    let env = |key: &str| std::env::var(key).ok();
    let config = config::load(cli.config.as_deref(), &env).map_err(|error| error.to_string())?;
    match cli.command {
        Command::Serve => serve(&config, report).await,
        Command::SetupCode => {
            let code = setup::read_setup_code(&config).map_err(|error| error.to_string())?;
            println!("{}", code.as_str());
            Ok(())
        }
        Command::Unlock { operator } => {
            let socket = unlock::socket_path(&config.data_dir);
            let label = unlock::unlock_with(&socket, operator.as_deref(), |prompt| {
                rpassword::prompt_password(prompt)
            })
            .await
            .map_err(|error| error.to_string())?;
            println!("vault unlocked by operator {label}");
            Ok(())
        }
        Command::Status => {
            if !config.data_dir.join(daemon::VAULT_FILE).exists() {
                if config.admin.enabled && setup::is_listening(&config) {
                    println!(
                        "no vault yet: this server waits for its first client to create it; run `cerberusd setup-code` for the setup code"
                    );
                } else if config.admin.enabled {
                    println!(
                        "no vault yet, and no cerberusd waits at {}: start the daemon, then run `cerberusd setup-code`",
                        status::probe_addr(&config)
                    );
                } else {
                    println!(
                        "no vault yet, and the admin API is off, so no client can create it: remove `enabled = false` from [admin] in cerberusd.toml (or set it to true) and restart cerberusd"
                    );
                }
                println!("{}", status::admin_summary(&config));
                return Ok(());
            }
            let health = status::check(&config)
                .await
                .map_err(|error| error.to_string())?;
            println!(
                "cerberusd {} at {}: vault {}",
                health.version, health.address, health.vault
            );
            if let Ok(ca) = status::ca_fingerprints(&config) {
                println!("CA pin: {}", ca.pin);
                println!("CA SHA-256: {}", ca.cert_sha256_hex);
            }
            println!("{}", status::admin_summary(&config));
            Ok(())
        }
        Command::Backup { out, keep } => {
            let report = backup::run(&config, &out, keep, &cerberus_types::SystemClock)
                .await
                .map_err(|error| error.to_string())?;
            println!("{}", report.path.display());
            if !report.pruned.is_empty() {
                eprintln!("removed {} old backup(s)", report.pruned.len());
            }
            Ok(())
        }
        Command::Admin { command } => run_admin(&config, command).await,
    }
}

async fn run_admin(config: &Config, command: AdminCommand) -> Result<(), String> {
    let socket = unlock::socket_path(&config.data_dir);
    match command {
        AdminCommand::Enroll {
            label,
            url,
            owner,
            operator,
            out,
        } => {
            // Fail before the phrase is asked, not after the enrolment is made.
            if out.exists() {
                return Err(format!(
                    "{} exists; choose a new file name for the bundle",
                    out.display()
                ));
            }
            let request = EnrollRequest {
                owner,
                operator,
                label,
                url,
            };
            let bundle = admin::enroll_with(&socket, &request, |prompt| {
                rpassword::prompt_password(prompt)
            })
            .await
            .map_err(|error| error.to_string())?;
            if let Err(error) = bundle.write_new(&out) {
                return Err(format!(
                    "enrolment {} was made but the bundle was not written: {error}. Revoke it with \
                     `cerberusd admin revoke {}` and enrol again.",
                    bundle.id, bundle.id
                ));
            }
            println!(
                "enrolled {:?} ({}) for operator {}, valid until {}",
                bundle.label, bundle.id, bundle.operator_id, bundle.not_after
            );
            println!("bundle written to {} (mode 0600)", out.display());
            println!("CA pin: {}", bundle.ca_pin);
            if let Ok(sha) = bundle.ca_sha256_hex() {
                println!("CA SHA-256: {sha}");
            }
            println!(
                "Move the bundle to the desktop over a trusted channel (for example scp), import it there, \
                 compare the pin and fingerprint with the desktop, then delete the file."
            );
            Ok(())
        }
        AdminCommand::List => {
            let (clients, source) = admin::list_with(&socket, &config.data_dir)
                .await
                .map_err(|error| error.to_string())?;
            if source == Source::File {
                println!("(no daemon answered; read from the registry file)");
            }
            if clients.is_empty() {
                println!("no enrolled clients");
            }
            let now = cerberus_types::Clock::now(&cerberus_types::SystemClock);
            for client in clients {
                let state = if client.revoked_at.is_some() {
                    "revoked"
                } else if client.is_live(now) {
                    "live"
                } else {
                    "expired"
                };
                println!(
                    "{}  {:<8} {:?} operator {} enrolled {} until {}",
                    client.id,
                    state,
                    client.label,
                    client.operator_id,
                    client.created_at,
                    client.not_after
                );
            }
            Ok(())
        }
        AdminCommand::Revoke { id } => {
            let source = admin::revoke_with(&socket, &config.data_dir, &id)
                .await
                .map_err(|error| error.to_string())?;
            match source {
                Source::Daemon => println!("revoked {id}; its sessions are closed"),
                Source::File => println!(
                    "no daemon answered: revoked {id} in the registry file; it takes effect at the next start"
                ),
            }
            Ok(())
        }
    }
}

async fn serve(config: &Config, report: HardeningReport) -> Result<(), String> {
    init_logging();
    if !report.dumpable_off || !report.core_limit_zero {
        tracing::warn!(
            ?report,
            "process hardening incomplete; core dumps may be possible"
        );
    }
    let stop = async {
        if let Err(error) = wait_for_stop_signal().await {
            tracing::error!(%error, "cannot listen for SIGTERM or SIGINT; stop with systemctl");
            std::future::pending::<()>().await;
        }
    };
    daemon::serve(config, stop, |_ready| notify_ready())
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Returns on SIGTERM or SIGINT. Both give the same stop: lock, then stop the server.
async fn wait_for_stop_signal() -> io::Result<()> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received; stopping"),
        _ = int.recv() => tracing::info!("SIGINT received; stopping"),
    }
    Ok(())
}

fn notify_ready() {
    if let Err(error) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        tracing::warn!(%error, "could not tell systemd the daemon is ready");
    }
}

fn init_logging() {
    cerberusd::logging::init();
}
