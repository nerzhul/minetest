//! Top-level MTP packet dispatch.
//!
//! A [`PacketDispatcher`] owns the [`SessionManager`] and the
//! [`CommandHandler`]. Given a single UDP datagram, it:
//!
//! 1. parses the 7-byte base header,
//! 2. obtains / creates the [`Session`] for the sender,
//! 3. dispatches by packet type (`Control` / `Original` / `Split` /
//!    `Reliable`),
//! 4. returns the response datagrams that the main loop should send
//!    back on the socket.
//!
//! Split reassembly is intentionally not implemented yet (TODO).

use std::net::SocketAddr;

use anyhow::Result;
use log::{debug, error, info, warn};

use luanti_network::{
    ControlType, NetworkPacket, PacketType, Session, SessionManager, BASE_HEADER_SIZE,
};

use crate::command_handler::CommandHandler;
use crate::frame::{
    build_control_ack, build_set_peer_id, hex_preview, parse_base_header, wrap_original,
    wrap_reliable,
};

/// Server-side packet dispatcher. Cheap to clone if you wrap it in
/// `Arc<Mutex<...>>`, but the main loop is single-threaded so a
/// mutable borrow is fine.
pub struct PacketDispatcher {
    sessions: SessionManager,
    commands: CommandHandler,
}

impl PacketDispatcher {
    pub fn new(commands: CommandHandler) -> Self {
        Self {
            sessions: SessionManager::new(),
            commands,
        }
    }

    /// Access to the underlying session manager (read-only).
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Mutable access to the underlying session manager.
    pub fn sessions_mut(&mut self) -> &mut SessionManager {
        &mut self.sessions
    }

    /// Access to the underlying command handler.
    pub fn commands(&self) -> &CommandHandler {
        &self.commands
    }

    /// Mutable access to the underlying command handler.
    pub fn commands_mut(&mut self) -> &mut CommandHandler {
        &mut self.commands
    }

    /// Process a single UDP datagram and return the response datagrams
    /// to send back to `peer_addr`.
    pub fn handle_datagram(
        &mut self,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        if data.len() < BASE_HEADER_SIZE {
            warn!("Packet too small from {}: {} bytes", peer_addr, data.len());
            return Ok(vec![]);
        }

        let header = match parse_base_header(data) {
            Some(h) => h,
            None => {
                warn!("Failed to parse base header from {}", peer_addr);
                return Ok(vec![]);
            }
        };

        debug!(
            "Packet from {}: protocol_id={:08x}, sender_peer_id={}, channel={}",
            peer_addr, header.protocol_id, header.sender_peer_id, header.channel
        );

        if header.protocol_id != luanti_network::PROTOCOL_ID {
            warn!(
                "Invalid protocol ID from {}: expected {:08x}, got {:08x}",
                peer_addr,
                luanti_network::PROTOCOL_ID,
                header.protocol_id
            );
            return Ok(vec![]);
        }

        // Borrow both fields independently so we can still call
        // self-methods (e.g. handle_command takes &mut self).
        let Self { sessions, commands } = self;
        let session = sessions.get_or_create_session(header.sender_peer_id, peer_addr);
        let was_newly_created = session.take_newly_created();

        if data.len() <= BASE_HEADER_SIZE {
            // Pure base-header packet, e.g. a probe: reply with
            // SET_PEER_ID if this is a brand new peer.
            return Ok(if was_newly_created {
                vec![build_set_peer_id(session.peer_id)]
            } else {
                vec![]
            });
        }

        let packet_type = data[BASE_HEADER_SIZE];
        // The "frame payload" is everything after the type byte, i.e.
        // the per-type-specific header (e.g. seqnum for Reliable,
        // control type for Control) plus the command and its data.
        let frame_payload = &data[BASE_HEADER_SIZE + 1..];

        let mut responses = match PacketType::from_u8(packet_type) {
            Some(PacketType::Control) => handle_control(session, frame_payload, peer_addr),
            Some(PacketType::Original) => {
                handle_command(commands, session, frame_payload, peer_addr, false, 0)
            }
            Some(PacketType::Split) => handle_split(session, frame_payload),
            Some(PacketType::Reliable) => {
                handle_reliable(commands, session, frame_payload, peer_addr)
            }
            None => {
                warn!(
                    "Unknown packet type 0x{:02x} from {} (raw: {})",
                    packet_type,
                    peer_addr,
                    hex_preview(data, 32),
                );
                vec![]
            }
        };

        if was_newly_created {
            responses.insert(0, build_set_peer_id(session.peer_id));
        }
        Ok(responses)
    }

    // --- Per-type handlers ----------------------------------------------
}

// --- Free functions for each packet-type path. Pulled out of the impl
// block so the borrow checker can see the disjoint borrows of the
// SessionManager and CommandHandler fields of `PacketDispatcher`.

fn handle_control(
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
) -> Vec<Vec<u8>> {
    // `data` has already had the MTP type byte stripped, so
    // `data[0]` is the control sub-type.
    if data.is_empty() {
        return vec![];
    }
    let control_type = data[0];

    match ControlType::from_u8(control_type) {
        Some(ControlType::Ack) => {
            if data.len() < 3 {
                return vec![];
            }
            let seqnum = u16::from_be_bytes([data[1], data[2]]);
            debug!("Received ACK for seqnum {} from {}", seqnum, peer_addr);
            session.handle_ack(seqnum);
            vec![]
        }
        Some(ControlType::SetPeerId) => {
            if data.len() < 3 {
                return vec![];
            }
            let new_peer_id = u16::from_be_bytes([data[1], data[2]]);
            info!("Setting peer ID to {} for {}", new_peer_id, peer_addr);
            session.set_peer_id(new_peer_id);
            vec![]
        }
        Some(ControlType::Ping) => {
            info!("Received PING from {}", peer_addr);
            // Echo the entire frame (type byte + control sub-type) back.
            let mut response = Vec::with_capacity(BASE_HEADER_SIZE + 1 + data.len());
            response.extend_from_slice(&crate::frame::build_base_header(
                luanti_network::PEER_ID_SERVER,
                0,
            ));
            response.push(PacketType::Control as u8);
            response.extend_from_slice(data);
            vec![response]
        }
        Some(ControlType::Disco) => {
            info!("Received DISCONNECT from {}", peer_addr);
            session.disconnect();
            vec![]
        }
        None => {
            warn!(
                "Unknown control type 0x{:02x} from {} (raw: {})",
                control_type,
                peer_addr,
                hex_preview(data, 32),
            );
            vec![]
        }
    }
}

fn handle_reliable(
    commands: &mut CommandHandler,
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
) -> Vec<Vec<u8>> {
    // `data` has the outer MTP type byte stripped. For a Reliable
    // packet the next 2 bytes are the u16 sequence number, then the
    // *inner* packet type byte (the C++ MTP wraps every reliable
    // command in an Original/Split envelope — see
    // `processReliableSendCommand` in `src/network/mtp/impl.cpp`),
    // and finally the command + payload.
    if data.len() < 2 {
        return vec![];
    }
    let seqnum = u16::from_be_bytes([data[0], data[1]]);
    debug!("Received RELIABLE packet with seqnum {}", seqnum);

    if data.len() <= 2 {
        return vec![];
    }

    // Strip the inner type byte. For the C++ MTP, this is always
    // PACKET_TYPE_ORIGINAL (or PACKET_TYPE_SPLIT for large payloads).
    let inner = &data[2..];
    if inner.is_empty() {
        return vec![];
    }
    let inner_type = inner[0];
    let inner_payload = &inner[1..];

    match PacketType::from_u8(inner_type) {
        Some(PacketType::Control) => handle_control(session, inner_payload, peer_addr),
        Some(PacketType::Original) => {
            handle_command(commands, session, inner_payload, peer_addr, true, seqnum)
        }
        Some(PacketType::Split) => handle_split(session, inner_payload),
        Some(PacketType::Reliable) => {
            warn!(
                "Nested reliable packet from {} (not allowed in MTP)",
                peer_addr
            );
            vec![]
        }
        None => {
            warn!(
                "Unknown inner packet type 0x{:02x} inside RELIABLE from {}",
                inner_type, peer_addr
            );
            vec![]
        }
    }
}

fn handle_split(session: &mut Session, data: &[u8]) -> Vec<Vec<u8>> {
    // Split header: seqnum (2) | chunk_count (2) | chunk_num (2)
    if data.len() < 6 {
        return vec![];
    }
    let seqnum = u16::from_be_bytes([data[0], data[1]]);
    let chunk_count = u16::from_be_bytes([data[2], data[3]]);
    let chunk_num = u16::from_be_bytes([data[4], data[5]]);
    info!(
        "Received SPLIT packet: seqnum={}, chunk {}/{}",
        chunk_num + 1,
        chunk_count,
        seqnum
    );
    session.on_packet_received();
    // TODO: reassemble and dispatch as command packet.
    vec![]
}

/// Dispatch a command packet. `force_reliable` is `true` if the
/// command was carried by a RELIABLE frame, in which case we must
/// ACK the incoming seqnum and send every response RELIABLE.
fn handle_command(
    commands: &mut CommandHandler,
    session: &mut Session,
    data: &[u8],
    peer_addr: SocketAddr,
    force_reliable: bool,
    reliable_seqnum: u16,
) -> Vec<Vec<u8>> {
    // `data` starts with the 2-byte command opcode, then the
    // command payload.
    let packet = match NetworkPacket::from_raw(data, session.peer_id) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "Failed to parse command packet from {}: {} -- raw payload: {}",
                peer_addr,
                e,
                hex_preview(data, 64),
            );
            return vec![];
        }
    };

    session.on_packet_received();

    match commands.handle_command(session, &packet, peer_addr) {
        Ok(responses) => {
            let mut out = Vec::with_capacity(responses.len() + 1);
            if force_reliable {
                out.push(build_control_ack(reliable_seqnum));
            }
            for r in responses {
                if force_reliable {
                    let seq = session.get_next_outgoing_seqnum();
                    out.push(wrap_reliable(seq, &r));
                } else {
                    out.push(wrap_original(&r));
                }
            }
            out
        }
        Err(e) => {
            let cmd_name = luanti_network::ToServerCommand::from_u16(packet.command())
                .map(|c| c.name().to_string())
                .unwrap_or_else(|| format!("0x{:04x}", packet.command()));
            error!(
                "Command handler error for {} (peer {}, from {}): {} -- raw payload: {}",
                cmd_name,
                session.peer_id,
                peer_addr,
                e,
                hex_preview(packet.as_slice(), 64),
            );
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luanti_auth_db::sqlite::AuthDatabaseSqlite;
    use std::net::SocketAddrV4;
    use std::str::FromStr;

    /// Simulate the full TOSERVER_INIT -> TOSERVER_SRP_BYTES_A flow a
    /// C++ client would do. Verifies that the dispatcher correctly
    /// parses the SRP_BYTES_A command (0x0051) instead of mis-reading
    /// it as 0x0100 the way the pre-refactor code did.
    ///
    /// The C++ MTP wraps every reliable command in an Original
    /// envelope (see `processReliableSendCommand` in
    /// `src/network/mtp/impl.cpp`), so the wire for a reliable
    /// command is actually:
    ///
    /// ```text
    /// [base(7)] [0x03 Reliable] [seqnum(2)] [0x01 Original] [command + payload]
    /// ```
    ///
    /// The test sends the packets in that exact shape, matching what
    /// the official C++ Minetest client puts on the wire.
    #[test]
    fn reliable_srp_bytes_a_after_init() {
        let tmp = tempfile::TempDir::new().unwrap();
        let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
        let cmd_handler = crate::CommandHandler::new(37, 43, Box::new(auth_db));
        let mut d = PacketDispatcher::new(cmd_handler);
        let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:55555").unwrap().into();

        // ---- 1. INIT ----------------------------------------------------
        // Build a TOSERVER_INIT (0x0002) on channel 1, reliable, with
        // ser_ver=29, compression=0, proto=37..43, name="nrz".
        let mut init_cmd = Vec::new();
        init_cmd.extend_from_slice(&0x0002u16.to_be_bytes());
        init_cmd.push(29); // ser_ver
        init_cmd.extend_from_slice(&0u16.to_be_bytes()); // compression
        init_cmd.extend_from_slice(&37u16.to_be_bytes());
        init_cmd.extend_from_slice(&43u16.to_be_bytes());
        init_cmd.extend_from_slice(&3u16.to_be_bytes());
        init_cmd.extend_from_slice(b"nrz");

        let mut datagram = vec![0u8; BASE_HEADER_SIZE];
        datagram[0..4].copy_from_slice(&luanti_network::PROTOCOL_ID.to_be_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_be_bytes());
        datagram[6] = 1;
        datagram.push(PacketType::Reliable as u8);
        datagram.extend_from_slice(&0xFFFBu16.to_be_bytes()); // seqnum
        // C++ MTP wraps every non-raw reliable command in an Original
        // envelope, so the wire includes an inner type byte.
        datagram.push(PacketType::Original as u8);
        datagram.extend_from_slice(&init_cmd);

        let responses = d.handle_datagram(&datagram, peer).unwrap();
        // The first response is SET_PEER_ID, the second is the ACK
        // for our reliable, the third is HELLO wrapped in reliable.
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[2][7], PacketType::Reliable as u8);
        // The C++ MTP double-wraps every reliable send, so the
        // response wire is [base][0x03][seqnum(2)][0x01][command(2)]...
        assert_eq!(responses[2][10], PacketType::Original as u8,
            "reliable response must include inner Original type byte for C++ client");
        let cmd = u16::from_be_bytes([responses[2][11], responses[2][12]]);
        assert_eq!(cmd, 0x0002, "expected TOCLIENT_HELLO (0x0002)");

        // ---- 2. SRP_BYTES_A --------------------------------------------
        // Wire payload: command (0x0051) | u16 len (256) | 256 bytes |
        // u8 based_on (= 1).
        let mut srp_cmd = Vec::new();
        srp_cmd.extend_from_slice(&0x0051u16.to_be_bytes());
        srp_cmd.extend_from_slice(&256u16.to_be_bytes());
        srp_cmd.extend_from_slice(&vec![0xAAu8; 256]);
        srp_cmd.push(0x01);

        let mut datagram = vec![0u8; BASE_HEADER_SIZE];
        datagram[0..4].copy_from_slice(&luanti_network::PROTOCOL_ID.to_be_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_be_bytes());
        datagram[6] = 1;
        datagram.push(PacketType::Reliable as u8);
        datagram.extend_from_slice(&0xFFFCu16.to_be_bytes());
        datagram.push(PacketType::Original as u8);
        datagram.extend_from_slice(&srp_cmd);

        let responses = d.handle_datagram(&datagram, peer).unwrap();
        // ACK + ACCESS_DENIED (because the session has no auth record
        // and only FirstSrp is allowed, SRP is rejected with
        // "Auth mechanism not allowed" reason code 1).
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0][7], PacketType::Control as u8);
        assert_eq!(responses[0][8], ControlType::Ack as u8);
        assert_eq!(responses[1][7], PacketType::Reliable as u8);
        assert_eq!(responses[1][10], PacketType::Original as u8,
            "reliable response must include inner Original type byte for C++ client");
        let cmd = u16::from_be_bytes([responses[1][11], responses[1][12]]);
        assert_eq!(cmd, 0x000A, "expected TOCLIENT_ACCESS_DENIED (0x000A)");
    }

    /// Regression test for the FIRST_SRP mis-parse observed with the
    /// official C++ Minetest client. The client sends TOSERVER_FIRST_SRP
    /// (0x0050) as a reliable command on channel 1. The C++ MTP
    /// double-wraps the command in:
    ///
    ///   [base(7)] [0x03 Reliable] [seqnum(2)] [0x01 Original] [0x00 0x50 ...]
    ///
    /// Before the fix, `handle_reliable` would only strip the seqnum and
    /// pass the inner `[0x01 0x00 0x50 ...]` to `from_raw`, which would
    /// read command = 0x0100 ("Unknown command"). This test exercises
    /// the exact wire format observed in the bug report and asserts the
    /// dispatcher dispatches it as TOSERVER_FIRST_SRP (0x0050) and
    /// responds with TOCLIENT_AUTH_ACCEPT (0x0003).
    #[test]
    fn first_srp_double_wrapped_is_recognised() {
        let tmp = tempfile::TempDir::new().unwrap();
        let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
        let cmd_handler = crate::CommandHandler::new(37, 43, Box::new(auth_db));
        let mut d = PacketDispatcher::new(cmd_handler);
        let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:55556").unwrap().into();

        // ---- 1. INIT (also double-wrapped, matches the C++ client) -----
        let mut init_cmd = Vec::new();
        init_cmd.extend_from_slice(&0x0002u16.to_be_bytes());
        init_cmd.push(29);
        init_cmd.extend_from_slice(&0u16.to_be_bytes());
        init_cmd.extend_from_slice(&37u16.to_be_bytes());
        init_cmd.extend_from_slice(&43u16.to_be_bytes());
        init_cmd.extend_from_slice(&3u16.to_be_bytes());
        init_cmd.extend_from_slice(b"nrz");

        let mut datagram = vec![0u8; BASE_HEADER_SIZE];
        datagram[0..4].copy_from_slice(&luanti_network::PROTOCOL_ID.to_be_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_be_bytes());
        datagram[6] = 1;
        datagram.push(PacketType::Reliable as u8);
        datagram.extend_from_slice(&0xFFFBu16.to_be_bytes());
        datagram.push(PacketType::Original as u8);
        datagram.extend_from_slice(&init_cmd);
        let _ = d.handle_datagram(&datagram, peer).unwrap();

        // ---- 2. FIRST_SRP (double-wrapped) -----------------------------
        // FirstSrp wire format: u16 salt_len | salt | u16 verifier_len
        // | verifier | u8 is_empty. We use a 16-byte salt and a
        // 256-byte verifier (matching what the C++ SRP library
        // produces) so the server accepts the new player.
        let salt = vec![0x42u8; 16];
        let verifier = vec![0xAAu8; 256];

        let mut first_srp = Vec::new();
        first_srp.extend_from_slice(&0x0050u16.to_be_bytes());
        first_srp.extend_from_slice(&(salt.len() as u16).to_be_bytes());
        first_srp.extend_from_slice(&salt);
        first_srp.extend_from_slice(&(verifier.len() as u16).to_be_bytes());
        first_srp.extend_from_slice(&verifier);
        first_srp.push(0); // is_empty

        let mut datagram = vec![0u8; BASE_HEADER_SIZE];
        datagram[0..4].copy_from_slice(&luanti_network::PROTOCOL_ID.to_be_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_be_bytes());
        datagram[6] = 1;
        datagram.push(PacketType::Reliable as u8);
        datagram.extend_from_slice(&0xFFFCu16.to_be_bytes());
        datagram.push(PacketType::Original as u8);
        datagram.extend_from_slice(&first_srp);

        let responses = d.handle_datagram(&datagram, peer).unwrap();
        // ACK for the reliable + AUTH_ACCEPT (0x0003) wrapped in a
        // reliable response. Before the fix the dispatcher would log
        // "Unknown command 0x0100" and return only the ACK.
        assert_eq!(
            responses.len(),
            2,
            "expected ACK + AUTH_ACCEPT, got {} responses",
            responses.len()
        );
        assert_eq!(responses[0][7], PacketType::Control as u8);
        assert_eq!(responses[0][8], ControlType::Ack as u8);
        assert_eq!(responses[1][7], PacketType::Reliable as u8);
        // Reliable responses are double-wrapped by `wrap_reliable`:
        // [base][0x03][seqnum(2)][0x01 Original][command(2)]...
        assert_eq!(
            responses[1][10], PacketType::Original as u8,
            "reliable response must include inner Original type byte for C++ client"
        );
        let cmd = u16::from_be_bytes([responses[1][11], responses[1][12]]);
        assert_eq!(
            cmd, 0x0003,
            "expected TOCLIENT_AUTH_ACCEPT (0x0003), got 0x{:04x}",
            cmd
        );
        // AUTH_ACCEPT payload must match the C++ client's reader:
        // v3f(12) + u64(8) + f32(4) + u32(4) = 28 bytes after the
        // 2-byte command.
        assert_eq!(
            responses[1].len(),
            7 + 1 + 2 + 1 + 2 + 12 + 8 + 4 + 4,
            "AUTH_ACCEPT response total wire size mismatch"
        );
    }
}
