// Luanti Rust Server - Session Layer Implementation
// Based on Luanti's MTP (Minetest Protocol) network layer

use luanti_server::command_handler;

use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use command_handler::{CommandHandler, CommandPacket};
use luanti_auth_db::sqlite::AuthDatabaseSqlite;
use luanti_network::{
    BaseHeader, ControlType, PacketType, Session, SessionManager, BASE_HEADER_SIZE,
    LATEST_PROTOCOL_VERSION, PROTOCOL_ID, SERVER_PROTOCOL_VERSION_MIN,
};

const DEFAULT_PORT: u16 = 30000;
const BUFFER_SIZE: usize = 65536;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Luanti Rust Server - Starting");

    let auth_db = AuthDatabaseSqlite::new("./world")
        .map_err(|e| anyhow::anyhow!("Failed to initialize auth database: {}", e))?;
    info!("Authentication database initialized");

    let mut session_manager = SessionManager::new();
    let mut command_handler = CommandHandler::new(
        SERVER_PROTOCOL_VERSION_MIN,
        LATEST_PROTOCOL_VERSION,
        Box::new(auth_db),
    );

    let addr = format!("0.0.0.0:{}", DEFAULT_PORT);
    let socket = UdpSocket::bind(&addr).await?;
    info!("Server listening on {}", addr);

    let mut buf = vec![0u8; BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer_addr)) => {
                debug!("Received {} bytes from {}", len, peer_addr);

                if len < BASE_HEADER_SIZE {
                    warn!("Packet too small from {}: {} bytes", peer_addr, len);
                    continue;
                }

                let packet_data = &buf[..len];

                let responses = match handle_packet(
                    &mut session_manager,
                    &mut command_handler,
                    packet_data,
                    peer_addr,
                ) {
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

fn handle_packet(
    session_manager: &mut SessionManager,
    command_handler: &mut CommandHandler,
    data: &[u8],
    peer_addr: SocketAddr,
) -> Result<Vec<Vec<u8>>> {
    let base_header = BaseHeader::parse(data)?;

    debug!(
        "Packet from {}: protocol_id={:08x}, sender_peer_id={}, channel={}",
        peer_addr, base_header.protocol_id, base_header.sender_peer_id, base_header.channel
    );

    if base_header.protocol_id != PROTOCOL_ID {
        warn!(
            "Invalid protocol ID from {}: expected {:08x}, got {:08x}",
            peer_addr, PROTOCOL_ID, base_header.protocol_id
        );
        return Ok(vec![]);
    }

    let session = session_manager.get_or_create_session(base_header.sender_peer_id, peer_addr);

    if data.len() <= BASE_HEADER_SIZE {
        return Ok(vec![]);
    }

    let packet_type = data[BASE_HEADER_SIZE];
    let packet_data = &data[BASE_HEADER_SIZE..];

    match PacketType::from_u8(packet_type) {
        Some(PacketType::Control) => handle_control_packet(session, packet_data, peer_addr),
        Some(PacketType::Original) => {
            handle_command_packet(command_handler, session, packet_data, peer_addr, PacketType::Original, 0)
        }
        Some(PacketType::Split) => handle_split_packet(session, packet_data),
        Some(PacketType::Reliable) => {
            handle_reliable_packet(command_handler, session, packet_data, peer_addr)
        }
        None => {
            warn!("Unknown packet type: {}", packet_type);
            Ok(vec![])
        }
    }
}

fn handle_control_packet(
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        return Ok(vec![]);
    }

    let control_type = data[0];

    match ControlType::from_u8(control_type) {
        Some(ControlType::Ack) => {
            if data.len() < 3 {
                return Ok(vec![]);
            }
            let seqnum = u16::from_be_bytes([data[1], data[2]]);
            debug!("Received ACK for seqnum {} from {}", seqnum, peer_addr);
            session.handle_ack(seqnum);
            Ok(vec![])
        }
        Some(ControlType::SetPeerId) => {
            if data.len() < 3 {
                return Ok(vec![]);
            }
            let new_peer_id = u16::from_be_bytes([data[1], data[2]]);
            info!("Setting peer ID to {} for {}", new_peer_id, peer_addr);
            session.set_peer_id(new_peer_id);
            Ok(vec![])
        }
        Some(ControlType::Ping) => {
            info!("Received PING from {}", peer_addr);
            let mut response = Vec::with_capacity(BASE_HEADER_SIZE + data.len());
            response.extend_from_slice(&create_base_header(session.peer_id, 0));
            response.extend_from_slice(data);
            Ok(vec![response])
        }
        Some(ControlType::Disco) => {
            info!("Received DISCONNECT from {}", peer_addr);
            session.disconnect();
            Ok(vec![])
        }
        None => {
            warn!("Unknown control type: {}", control_type);
            Ok(vec![])
        }
    }
}

/// Dispatch a single command packet and wrap the responses in the
/// appropriate session-layer frame (ORIGINAL or RELIABLE).
///
/// `force_reliable` is `true` if the command arrived in a RELIABLE
/// packet (in which case each response must be sent RELIABLE so the
/// client can ACK them).
fn handle_command_packet(
    command_handler: &mut CommandHandler,
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
    frame_type: PacketType,
    reliable_seqnum: u16,
) -> Result<Vec<Vec<u8>>> {
    if data.len() < 2 {
        return Ok(vec![]);
    }
    session.on_packet_received();

    match CommandPacket::parse(data, session.peer_id) {
        Ok(cmd_packet) => match command_handler.handle_command(session, &cmd_packet, peer_addr) {
            Ok(responses) => {
                let mut out = Vec::with_capacity(responses.len() + 1);
                // Always ACK the incoming reliable packet first.
                if matches!(frame_type, PacketType::Reliable) {
                    out.push(build_control_ack(session.peer_id, reliable_seqnum));
                }
                for r in responses {
                    if matches!(frame_type, PacketType::Reliable) {
                        let seq = session.get_next_outgoing_seqnum();
                        out.push(wrap_reliable(session.peer_id, seq, &r));
                    } else {
                        out.push(wrap_original(session.peer_id, &r));
                    }
                }
                Ok(out)
            }
            Err(e) => {
                error!("Command handler error: {}", e);
                Ok(vec![])
            }
        },
        Err(e) => {
            warn!("Failed to parse command packet: {}", e);
            Ok(vec![])
        }
    }
}

fn handle_split_packet(session: &mut Session, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.len() < 7 {
        return Ok(vec![]);
    }

    let seqnum = u16::from_be_bytes([data[1], data[2]]);
    let chunk_count = u16::from_be_bytes([data[3], data[4]]);
    let chunk_num = u16::from_be_bytes([data[5], data[6]]);

    info!(
        "Received SPLIT packet: seqnum={}, chunk {}/{}",
        seqnum,
        chunk_num + 1,
        chunk_count
    );

    session.on_packet_received();
    // TODO: Implement split packet reassembly
    Ok(vec![])
}

fn handle_reliable_packet(
    command_handler: &mut CommandHandler,
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
) -> Result<Vec<Vec<u8>>> {
    if data.len() < 3 {
        return Ok(vec![]);
    }
    let seqnum = u16::from_be_bytes([data[1], data[2]]);
    debug!("Received RELIABLE packet with seqnum {}", seqnum);

    if data.len() > 3 {
        let inner_data = &data[3..];
        // RELIABLE-wrapped command packet: dispatch through the
        // unified command-packet path, with force_reliable so the
        // ACK is sent and responses are also RELIABLE.
        return handle_command_packet(
            command_handler,
            session,
            inner_data,
            peer_addr,
            PacketType::Reliable,
            seqnum,
        );
    }
    Ok(vec![])
}

// --- Frame helpers ---------------------------------------------------------

fn create_base_header(sender_peer_id: u16, channel: u8) -> Vec<u8> {
    let mut header = Vec::with_capacity(BASE_HEADER_SIZE);
    header.extend_from_slice(&PROTOCOL_ID.to_be_bytes());
    header.extend_from_slice(&sender_peer_id.to_be_bytes());
    header.push(channel);
    header
}

fn wrap_original(peer_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 1 + payload.len());
    out.extend_from_slice(&create_base_header(peer_id, 0));
    out.push(PacketType::Original as u8);
    out.extend_from_slice(payload);
    out
}

fn wrap_reliable(peer_id: u16, seqnum: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 3 + payload.len());
    out.extend_from_slice(&create_base_header(peer_id, 0));
    out.push(PacketType::Reliable as u8);
    out.extend_from_slice(&seqnum.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn build_control_ack(peer_id: u16, seqnum: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 3);
    out.extend_from_slice(&create_base_header(peer_id, 0));
    out.push(PacketType::Control as u8);
    out.push(ControlType::Ack as u8);
    out.extend_from_slice(&seqnum.to_be_bytes());
    out
}
