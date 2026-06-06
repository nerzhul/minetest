// Luanti Rust Server - main entry point
//
// All the packet handling lives in `luanti_server::packet_dispatcher`.
// This file is just the receive/send loop on a UDP socket.

use std::path::PathBuf;

use anyhow::Result;
use log::{error, info};
use tokio::net::UdpSocket;

use luanti_auth_db::AuthDatabase;
use luanti_network::{LATEST_PROTOCOL_VERSION, SERVER_PROTOCOL_VERSION_MIN};
use luanti_server::{parse_env, print_help, AuthDbMode, CommandHandler, PacketDispatcher};

const DEFAULT_PORT: u16 = 30000;
const DEFAULT_WORLD_DIR: &str = "./world";
const BUFFER_SIZE: usize = 65536;

fn program_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|s| {
            let s = s.to_string_lossy().into_owned();
            std::path::Path::new(&s)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .or(Some(s))
        })
        .unwrap_or_else(|| "luanti-server".to_string())
}

fn extract_world_dir(positionals: &[String]) -> PathBuf {
    for raw in positionals {
        if let Some(rest) = raw.strip_prefix("--world-dir=") {
            return PathBuf::from(rest);
        }
    }
    PathBuf::from(DEFAULT_WORLD_DIR)
}

/// Build the configured `AuthDatabase`.
///
/// The synchronous `AuthDatabase` trait is satisfied natively by the
/// in-memory and sqlite3 backends. PostgreSQL exposes an async-only API
/// because it is built on top of `tokio_postgres`; wiring it through the
/// synchronous trait used by `CommandHandler` requires a separate
/// async-driven refactor. We detect that here and bail out with a clear
/// message rather than silently producing a half-broken server.
async fn build_auth_db(
    mode: AuthDbMode,
    world_dir: &std::path::Path,
) -> Result<Box<dyn AuthDatabase>> {
    match mode {
        AuthDbMode::Memory => {
            info!("Auth backend: in-memory (no persistence)");
            Ok(Box::new(luanti_auth_db::memory::AuthDatabaseMemory::new()))
        }
        AuthDbMode::Sqlite3 => {
            info!("Auth backend: sqlite3 (world_dir: {})", world_dir.display());
            let db = luanti_auth_db::sqlite::AuthDatabaseSqlite::new(world_dir).map_err(|e| {
                anyhow::anyhow!("Failed to initialize sqlite3 auth database: {}", e)
            })?;
            Ok(Box::new(db))
        }
        AuthDbMode::Postgres => Err(anyhow::anyhow!(
            "Auth backend 'postgres' is selected but the CommandHandler's auth database \
             interface is currently synchronous, while luanti-auth-db's PostgreSQL backend \
             is async-only. Set the LUANTI_PG_CONN environment variable and either:\n  \
             - wait for the async auth refactor, or\n  \
             - extend the AuthDatabase trait to be async.\n\
             Connection string was: {:?}",
            std::env::var("LUANTI_PG_CONN").unwrap_or_default()
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let program = program_name();

    let config = match parse_env(&program) {
        Ok(cfg) => cfg,
        Err(luanti_server::cli::CliError::HelpRequested) => {
            print_help(&program);
            return Ok(());
        }
        Err(e) => {
            eprintln!("error: {}\n", e);
            print_help(&program);
            std::process::exit(2);
        }
    };

    info!("Luanti Rust Server - Starting");
    info!("Auth DB mode: {}", config.auth_db_mode);

    let world_dir = extract_world_dir(&config.positionals);
    let auth_db = build_auth_db(config.auth_db_mode, &world_dir).await?;
    info!("Authentication database initialized");

    let command_handler = CommandHandler::new(
        SERVER_PROTOCOL_VERSION_MIN,
        LATEST_PROTOCOL_VERSION,
        auth_db,
    );
    let mut dispatcher = PacketDispatcher::new(command_handler);

    let addr = format!("0.0.0.0:{}", DEFAULT_PORT);
    let socket = UdpSocket::bind(&addr).await?;
    info!("Server listening on {}", addr);

    let mut buf = vec![0u8; BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer_addr)) => {
                let datagram = &buf[..len];
                let responses = match dispatcher.handle_datagram(datagram, peer_addr) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error handling packet from {}: {}", peer_addr, e);
                        continue;
                    }
                };
                for response in responses {
                    if let Err(e) = socket.send_to(&response, peer_addr).await {
                        error!("Failed to send response to {}: {}", peer_addr, e);
                    }
                }
            }
            Err(e) => {
                error!("Error receiving packet: {}", e);
            }
        }
    }
}
