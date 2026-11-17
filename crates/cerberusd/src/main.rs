//! Command line of `cerberusd`: `serve`, `unlock` and `status` (ADR-0002). See `docs/guides/cerberusd.md`.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use cerberus_crypto::memlock::{self, HardeningReport};
use cerberusd::config::{self, Config};
use cerberusd::{daemon, status, unlock};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};

/// The command line.
#[derive(Parser)]
#[command(
    name = "cerberusd",
    version,
    about = "Cerberus headless daemon: serves the Agent API for a vault copied from the desktop app."
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
    /// Serve the Agent API. The vault starts sealed. Unlock it with `cerberusd unlock`.
    Serve,
    /// Unlock a running daemon. Asks for the passphrase here, with echo off.
    Unlock {
        /// Operator label. Needed when the vault has more than one owner.
        #[arg(long, value_name = "LABEL")]
        operator: Option<String>,
    },
    /// Check a running daemon over HTTPS.
    Status,
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
            let health = status::check(&config)
                .await
                .map_err(|error| error.to_string())?;
            println!(
                "cerberusd {} at {}: vault {}",
                health.version, health.address, health.vault
            );
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
