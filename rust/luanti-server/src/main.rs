// Luanti Rust Server - main entry point
//
// All the packet handling lives in `luanti_server::packet_dispatcher`.
// This file is just the receive/send loop on a UDP socket.

use anyhow::Result;
use log::{error, info};
use tokio::net::UdpSocket;

use luanti_auth_db::sqlite::AuthDatabaseSqlite;
use luanti_network::{LATEST_PROTOCOL_VERSION, SERVER_PROTOCOL_VERSION_MIN};
use luanti_server::{CommandHandler, PacketDispatcher};

const DEFAULT_PORT: u16 = 30000;
const BUFFER_SIZE: usize = 65536;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Luanti Rust Server - Starting");

    let auth_db = AuthDatabaseSqlite::new("./world")
        .map_err(|e| anyhow::anyhow!("Failed to initialize auth database: {}", e))?;
    info!("Authentication database initialized");

    let command_handler = CommandHandler::new(
        SERVER_PROTOCOL_VERSION_MIN,
        LATEST_PROTOCOL_VERSION,
        Box::new(auth_db),
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
