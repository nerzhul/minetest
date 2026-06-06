//! TOCLIENT packet creation functions
//!
//! This module provides functions to create protocol packets sent from the server to clients.
//! These are pure functions that don't depend on session state and can be reused across
//! different server implementations.
//!
//! All creators build a `NetworkPacket` and return its serialized bytes
//! (command opcode + payload), exactly mirroring how the C++ server uses
//! `NetworkPacket` (e.g. `NetworkPacket resp_pkt(TOCLIENT_FOO, 0,
//! peer_id); resp_pkt << ...; Send(&resp_pkt);`).

use std::io::Write;

use crate::network_packet::NetworkPacket;
use crate::opcodes::{AccessDeniedCode, ModChannelSignal, ToClientCommand};

/// Create TOCLIENT_HELLO response
///
/// This packet is sent in response to TOSERVER_INIT and negotiates the protocol version
/// and authentication mechanisms.
///
/// # Arguments
/// * `serialization_version` - Negotiated serialization version
/// * `protocol_version` - Negotiated protocol version
/// * `auth_mechs` - Bitmask of supported authentication mechanisms
pub fn create_hello_response(
    serialization_version: u8,
    protocol_version: u16,
    auth_mechs: u32,
) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::Hello as u16, 1 + 2 + 2 + 4 + 2);
    p.write_u8(serialization_version);
    p.write_u16(0); // compression (unused)
    p.write_u16(protocol_version);
    p.write_u32(auth_mechs);
    p.write_utf8(""); // unused username
    p
}

/// Create TOCLIENT_SRP_BYTES_S_B response
///
/// This packet is sent in response to TOSERVER_SRP_BYTES_A during the
/// SRP-6a handshake. It carries the salt and the server's public
/// ephemeral B.
///
/// # Arguments
/// * `salt` - The per-user salt
/// * `bytes_b` - The server's B value (256 bytes for 2048-bit SRP)
pub fn create_srp_bytes_s_b_response(salt: &[u8], bytes_b: &[u8]) -> NetworkPacket {
    let mut p = NetworkPacket::new(
        ToClientCommand::SrpBytesSB as u16,
        2 + salt.len() + 2 + bytes_b.len(),
    );
    p.write_string(salt);
    p.write_string(bytes_b);
    p
}

/// Create TOCLIENT_AUTH_ACCEPT response
///
/// This packet is sent when the client's authentication is accepted, allowing them
/// to enter the game.
///
/// # Wire format
///
/// The protocol comment in `networkprotocol.h` claims the send-interval
/// field is `f1000` (a 2-byte fixed-point u16), but the C++ server
/// actually writes it as a raw `float` (4 bytes, see
/// `Server::acceptAuth` in `src/server.cpp`) and the C++ client reads
/// it as a `float` too (`Client::handleCommand_AuthAccept` in
/// `src/network/clientpackethandler.cpp`). We follow the wire
/// reality, not the comment, so the official client can parse the
/// response.
///
/// # Arguments
/// * `map_seed` - u64 seed of the map
/// * `send_interval` - recommended send interval in seconds (server -> client)
/// * `sudo_auth_mechs` - bitmask of auth mechanisms available for sudo mode
pub fn create_auth_accept_response(
    map_seed: u64,
    send_interval: f32,
    sudo_auth_mechs: u32,
) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::AuthAccept as u16, 12 + 8 + 4 + 4);
    p.write_v3f(0.0, 0.0, 0.0); // unused position
    p.write_u64(map_seed);
    p.write_f32(send_interval);
    p.write_u32(sudo_auth_mechs);
    p
}

/// Create TOCLIENT_ACCESS_DENIED response
///
/// This packet denies access to a client with a specific reason code and message.
///
/// # Arguments
/// * `code` - The denial reason code
/// * `message` - Human-readable message explaining the denial
pub fn create_access_denied(code: AccessDeniedCode, message: &str) -> NetworkPacket {
    let mut p = NetworkPacket::new(
        ToClientCommand::AccessDenied as u16,
        1 + 2 + message.len() + 1,
    );
    p.write_u8(code as u8);
    p.write_utf8(message);
    p.write_u8(0); // reconnect
    p
}

/// Create `TOCLIENT_CHAT_MESSAGE` (0x2F) — a chat message sent to the
/// client.
///
/// Wire format (matches `Server::SendChatMessage` in
/// [`src/server.cpp`](../../../../src/server.cpp) and
/// `Client::handleCommand_ChatMessage` in
/// [`src/network/clientpackethandler.cpp`](../../../../src/network/clientpackethandler.cpp)):
///
/// ```text
/// [0]    u8   version            (must be 1; older clients used version 0)
/// [1]    u8   message_type       (0 = normal, 1 = system, 2 = announce…)
/// [2]    u16  sendername_char_count
/// [..]   wstring sendername     (BE u16 chars, the player name, or "" for system)
/// [..]   u16  message_char_count
/// [..]   wstring message        (BE u16 chars, the actual chat content)
/// [..]   u64  timestamp          (seconds since the Unix epoch)
/// ```
///
/// The client formats the displayed line itself (typically
/// `"<sender> message"`); the server must NOT pre-format the
/// `<sender> ` prefix into the message field — that would render
/// as `"<sender> <sender> message"` on the client. Pass the raw
/// player name as `sender` and the raw chat text as `message`.
///
/// `timestamp` is the wall-clock time the message was generated
/// (seconds since the Unix epoch). The client uses it for ordering
/// and to debounce replays.
///
/// # Arguments
/// * `sender`    — the player name (or `""` for system messages).
/// * `message`   — the raw chat text (no `<sender> ` prefix).
/// * `timestamp` — Unix epoch seconds, as a `u64`.
pub fn create_chat_message_response(sender: &str, message: &str, timestamp: u64) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::ChatMessage as u16, 0);
    p.write_u8(1); // version
    p.write_u8(0); // message type (normal)
    p.write_wstring(sender);
    p.write_wstring(message);
    p.write_u64(timestamp);
    p
}

/// A single media file entry for `TOCLIENT_ANNOUNCE_MEDIA`.
#[derive(Debug, Clone)]
pub struct MediaAnnounceEntry {
    /// Filename (relative path).
    pub name: String,
    /// SHA-1 digest of the file contents, as raw 20 bytes.
    pub sha1_digest: [u8; 20],
}

/// Create `TOCLIENT_ANNOUNCE_MEDIA` (protocol < 48).
///
/// Lists the server's media files together with their SHA-1 hashes so
/// the client can request only the ones it doesn't already have.
///
/// # Arguments
/// * `files` - the media files to announce
/// * `remote_media` - the comma-separated list of remote media server URLs
pub fn create_announce_media(files: &[MediaAnnounceEntry], remote_media: &str) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::AnnounceMedia as u16, 0);
    p.write_u16(files.len() as u16);
    for f in files {
        p.write_utf8(&f.name);
        // base64-encode the raw SHA-1 digest
        let b64 = crate::base64_util::encode(&f.sha1_digest);
        p.write_utf8(&b64);
    }
    p.write_utf8(remote_media);
    p
}

/// A single media file entry for `TOCLIENT_MEDIA` (one bunch).
#[derive(Debug, Clone)]
pub struct MediaBunchFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Create `TOCLIENT_MEDIA` packet (a single bunch of media files).
///
/// # Arguments
/// * `total_bunches` - total number of bunches the client should expect
/// * `bunch_index` - index of this bunch (0-based)
/// * `files` - the files to include in this bunch
pub fn create_media_bunch(
    total_bunches: u16,
    bunch_index: u16,
    files: &[MediaBunchFile],
) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::Media as u16, 0);
    p.write_u16(total_bunches);
    p.write_u16(bunch_index);
    p.write_u32(files.len() as u32);
    for f in files {
        p.write_utf8(&f.name);
        // data: u32 length + raw bytes (long string, no compression)
        p.write_long_string(&f.data);
    }
    p
}

/// Create `TOCLIENT_NODEDEF` packet (compressed node definitions).
///
/// The payload is a serialized `NodeDefManager`, compressed with zlib
/// (protocol < 48) or zstd (protocol >= 48) to match what the C++ client
/// expects. The compressed blob is written as a Luanti `long string`
/// (u32 length + raw bytes).
///
/// `serialized` should be the output of `serialize_nodedef_manager` (or
/// a compatible implementation). It must not be empty — even an "empty"
/// manager must serialize to at least 7 bytes (version + count + string
/// length prefix), because the client's decompressor rejects an empty
/// input stream with `EOF`.
pub fn create_nodedef_response(serialized: &[u8], protocol_version: u16) -> NetworkPacket {
    let compressed = compress_definitions(serialized, protocol_version);
    let mut p = NetworkPacket::new(ToClientCommand::NodeDef as u16, compressed.len() + 4);
    p.write_long_string(&compressed);
    p
}

/// Create `TOCLIENT_ITEMDEF` packet (compressed item definitions).
///
/// The payload is a serialized `ItemDefManager`, compressed with zlib
/// (protocol < 48) or zstd (protocol >= 48). See `create_nodedef_response`
/// for the rationale behind the compression.
pub fn create_itemdef_response(serialized: &[u8], protocol_version: u16) -> NetworkPacket {
    let compressed = compress_definitions(serialized, protocol_version);
    let mut p = NetworkPacket::new(ToClientCommand::ItemDef as u16, compressed.len() + 4);
    p.write_long_string(&compressed);
    p
}

/// Serialize an empty `ItemDefManager` in the C++ wire format.
///
/// On the wire, `ItemDefManager::serialize` writes:
///
/// ```text
/// u8   version       (= 0)
/// u16  count         (= 0 for no registered items)
/// u16  alias_count   (= 0 for no aliases)
/// ```
///
/// The receiving C++ `ItemDefManager::deSerialize` calls `clear()` first
/// (which re-registers the four builtins: hand, unknown, air, ignore) and
/// then reads `count` items and `alias_count` aliases. So sending an
/// "empty" manager is equivalent to a server with no registered items
/// and produces a working client-side manager.
pub fn serialize_empty_itemdef() -> Vec<u8> {
    let mut p = NetworkPacket::new(0, 0);
    p.write_u8(0); // version
    p.write_u16(0); // count
    p.write_u16(0); // alias_count
    p.take_payload()
}

/// Serialize an empty `NodeDefManager` in the C++ wire format.
///
/// On the wire, `NodeDefManager::serialize` writes:
///
/// ```text
/// u8   version       (= 1)
/// u16  count         (= 0 for no registered nodes)
/// string32           (= serializeString32 of the inner per-node data;
///                      length prefix only, since count == 0)
/// ```
///
/// `string32` is a u32 length prefix followed by the raw bytes.
pub fn serialize_empty_nodedef() -> Vec<u8> {
    let mut p = NetworkPacket::new(0, 0);
    p.write_u8(1); // version
    p.write_u16(0); // count
    p.write_u32(0); // string32 length = 0 (no inner data)
    p.take_payload()
}

/// Compress a serialized def manager with the codec the negotiated
/// protocol version mandates.
///
/// - protocol >= 48 → zstd (the official C++ server uses
///   `compressZstd(..., level=0)`).
/// - protocol <  48 → zlib (the official C++ server uses
///   `compressZlib(..., level=-1)` i.e. the default).
///
/// Falling back to an empty buffer is **not** acceptable: the C++
/// `decompressZstd` / `decompressZlib` will throw on EOF, which
/// surfaces to the client as `A serialization error occurred: EOF`
/// and aborts the connection.
fn compress_definitions(serialized: &[u8], protocol_version: u16) -> Vec<u8> {
    if protocol_version >= 48 {
        // level 0 matches the C++ default; this is a tiny payload so
        // compression level is irrelevant in practice.
        zstd::stream::encode_all(serialized, 0).unwrap_or_default()
    } else {
        // flate2's `ZlibEncoder` produces zlib-format data (RFC 1950)
        // with the standard 2-byte header + Adler-32 checksum, which
        // is exactly what `inflate` on the C++ side expects.
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(serialized).expect("zlib write");
        encoder.finish().expect("zlib finish")
    }
}

/// Create `TOCLIENT_TIME_OF_DAY`.
///
/// The protocol comment in `networkprotocol.h` claims `time_speed` is
/// `f1000` (2 bytes), but the C++ server writes it as a `float`
/// (`SendTimeOfDay` -> `*pkt << time_speed`) and the C++ client reads
/// it as a `float` (`Client::handleCommand_TimeOfDay`). We match the
/// wire reality so the official client can parse the response.
///
/// # Arguments
/// * `time_of_day` - 0..=23999, 0 = midnight, 12000 = noon
/// * `time_speed` - speed of the day/night cycle (in game-time units per real second)
pub fn create_time_of_day(time_of_day: u16, time_speed: f32) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::TimeOfDay as u16, 2 + 4);
    p.write_u16(time_of_day);
    p.write_f32(time_speed);
    p
}

/// Create `TOCLIENT_CSM_RESTRICTION_FLAGS` (client-side mod restrictions).
///
/// Wire format (matches `Server::SendCSMRestrictionFlags` in
/// `src/server.cpp` and `Client::handleCommand_CSMRestrictionFlags` in
/// `src/network/clientpackethandler.cpp`):
///
/// ```text
/// u32 CSMRestrictionFlags byteflag
/// u32 csm_restriction_noderange
/// ```
///
/// `flags` is a `CSMRestrictionFlags` bitmask. `0` disables all
/// restrictions; `CSM_RF_ALL` (0xFFFFFFFF) enables all.
///
/// `noderange` caps the radius (in nodes) of the CSM `get_node` /
/// `get_node_or_nil` lookups, used when the `LOOKUP_NODES_LIMIT`
/// restriction flag is set. The C++ server's default is `8`
/// (`g_settings->getU32("csm_restriction_noderange")`); we use the
/// same default here. **Both fields must be present** on the wire —
/// sending only `flags` makes the C++ client abort with
/// `Reading outside packet (offset: 4, packet size: 4)`.
pub fn create_csm_restriction_flags(flags: u64, noderange: u32) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::CsmRestrictionFlags as u16, 8);
    p.write_u64(flags);
    p.write_u32(noderange);
    p
}

/// Create `TOCLIENT_MOVEMENT` (default movement parameters).
///
/// Wire format (matches `Server::SendMovement` in `src/server.cpp` and
/// `Client::handleCommand_Movement` in
/// `src/network/clientpackethandler.cpp`):
///
/// ```text
/// f32 movement_acceleration_default
/// f32 movement_acceleration_air
/// f32 movement_acceleration_fast
/// f32 movement_speed_walk
/// f32 movement_speed_crouch
/// f32 movement_speed_fast
/// f32 movement_speed_climb
/// f32 movement_speed_jump
/// f32 movement_liquid_fluidity
/// f32 movement_liquid_fluidity_smooth
/// f32 movement_liquid_sink
/// f32 movement_gravity
/// ```
///
/// **Exactly 12 floats** must be sent. The previous version of this
/// function sent 20 fields (which the C++ client silently truncates
/// after reading 12) but the extra 32 bytes of trailing payload
/// shifted the parse cursor and could mask other wire bugs. We now
/// match the C++ exactly: 12 × 4 = 48 bytes of payload.
pub fn create_movement(
    acceleration_default: f32,
    acceleration_air: f32,
    acceleration_fast: f32,
    speed_walk: f32,
    speed_crouch: f32,
    speed_fast: f32,
    speed_climb: f32,
    speed_jump: f32,
    liquid_fluidity: f32,
    liquid_fluidity_smooth: f32,
    liquid_sink: f32,
    gravity: f32,
) -> NetworkPacket {
    let mut p = NetworkPacket::new(ToClientCommand::Movement as u16, 12 * 4);
    p.write_f32(acceleration_default);
    p.write_f32(acceleration_air);
    p.write_f32(acceleration_fast);
    p.write_f32(speed_walk);
    p.write_f32(speed_crouch);
    p.write_f32(speed_fast);
    p.write_f32(speed_climb);
    p.write_f32(speed_jump);
    p.write_f32(liquid_fluidity);
    p.write_f32(liquid_fluidity_smooth);
    p.write_f32(liquid_sink);
    p.write_f32(gravity);
    p
}

// --- Mod channel packets ---------------------------------------------------

/// Create `TOCLIENT_MODCHANNEL_SIGNAL`.
///
/// Wire format (matches `Server::handleCommand_ModChannelJoin/Leave` in
/// `src/network/serverpackethandler.cpp`):
///
/// ```text
/// u8  signal       (one of ModChannelSignal)
/// std::string channel_name
/// ```
///
/// # Arguments
/// * `signal` - the kind of signal to send
/// * `channel_name` - the channel name the signal refers to
pub fn create_modchannel_signal(signal: ModChannelSignal, channel_name: &str) -> NetworkPacket {
    let mut p = NetworkPacket::new(
        ToClientCommand::ModChannelSignal as u16,
        1 + 2 + channel_name.len(),
    );
    p.write_u8(signal as u8);
    p.write_utf8(channel_name);
    p
}

/// Create `TOCLIENT_MODCHANNEL_MSG`.
///
/// Wire format:
///
/// ```text
/// std::string channel_name
/// std::string channel_msg
/// ```
pub fn create_modchannel_msg(channel_name: &str, channel_msg: &str) -> NetworkPacket {
    let mut p = NetworkPacket::new(
        ToClientCommand::ModChannelMsg as u16,
        2 + channel_name.len() + 2 + channel_msg.len(),
    );
    p.write_utf8(channel_name);
    p.write_utf8(channel_msg);
    p
}

// Re-exports for convenience -----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::ToClientCommand;

    /// Render a `NetworkPacket` (command + payload) back into raw bytes
    /// for byte-level assertions. The tests below rely on the exact
    /// wire layout of each packet.
    fn bytes(p: &NetworkPacket) -> Vec<u8> {
        p.into_raw_bytes()
    }

    #[test]
    fn test_create_hello_response() {
        let packet = bytes(&create_hello_response(29, 42, 0x01));
        assert_eq!(packet[0..2], (ToClientCommand::Hello as u16).to_be_bytes());
        assert_eq!(packet[2], 29); // serialization version
    }

    #[test]
    fn test_create_auth_accept_response() {
        let packet = bytes(&create_auth_accept_response(12345, 0.1, 0));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::AuthAccept as u16).to_be_bytes()
        );
        // The C++ client reads this packet with:
        //   *pkt >> v3f >> u64 >> float >> u32
        // i.e. 2 (cmd) + 12 (v3f) + 8 (seed) + 4 (f32) + 4 (u32) = 30.
        // If we used `f1000` (2 bytes) the client would over-read into
        // the next field and abort with "Connection aborted
        // (protocol error?)".
        assert_eq!(
            packet.len(),
            30,
            "AUTH_ACCEPT must be 30 bytes (matches C++ Server::acceptAuth)"
        );
    }

    #[test]
    fn test_create_time_of_day() {
        let packet = bytes(&create_time_of_day(6000, 1.0));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::TimeOfDay as u16).to_be_bytes()
        );
        // The C++ client reads `time_speed` as a `float` (4 bytes),
        // not f1000. Wire: 2 (cmd) + 2 (time_of_day) + 4 (f32) = 8.
        assert_eq!(
            packet.len(),
            8,
            "TIME_OF_DAY must be 8 bytes (matches C++ Client::handleCommand_TimeOfDay)"
        );
    }

    #[test]
    fn test_create_srp_bytes_s_b_response() {
        let salt = [0u8; 16];
        let b = [0u8; 256];
        let packet = bytes(&create_srp_bytes_s_b_response(&salt, &b));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::SrpBytesSB as u16).to_be_bytes()
        );
        // salt length is u16 BE
        assert_eq!(packet[2..4], (16u16).to_be_bytes());
    }

    #[test]
    fn test_create_access_denied() {
        let packet = bytes(&create_access_denied(
            AccessDeniedCode::WrongVersion,
            "Test message",
        ));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::AccessDenied as u16).to_be_bytes()
        );
        assert_eq!(packet[2], AccessDeniedCode::WrongVersion as u8);
    }

    #[test]
    fn test_create_chat_message_response() {
        // Wire layout: u8 version | u8 type | u16 sender_char_count |
        // wstring sender (BE u16 chars) | u16 message_char_count |
        // wstring message (BE u16 chars) | u64 timestamp.
        let ts: u64 = 1_700_000_000;
        let packet = bytes(&create_chat_message_response("nrz", "Hello", ts));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ChatMessage as u16).to_be_bytes()
        );
        assert_eq!(packet[2], 1); // version
        assert_eq!(packet[3], 0); // message type

        // sender: u16 char count (3 chars for "nrz") + 6 bytes BE u16
        assert_eq!(&packet[4..6], &3u16.to_be_bytes());
        let sender_bytes = &packet[6..12];
        let sender = String::from_utf16(
            &sender_bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(sender, "nrz");

        // message: u16 char count (5 chars for "Hello") + 10 bytes BE u16
        assert_eq!(&packet[12..14], &5u16.to_be_bytes());
        let message_bytes = &packet[14..24];
        let message = String::from_utf16(
            &message_bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(message, "Hello");

        // timestamp: u64 BE
        let ts_offset = packet.len() - 8;
        assert_eq!(
            u64::from_be_bytes(packet[ts_offset..].try_into().unwrap()),
            ts
        );
    }

    #[test]
    fn test_serialize_empty_itemdef_matches_cpp_wire_format() {
        // C++ ItemDefManager::serialize writes:
        //   u8 version (= 0)
        //   u16 count (= 0)
        //   u16 alias_count (= 0)
        let payload = serialize_empty_itemdef();
        assert_eq!(payload, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_empty_nodedef_matches_cpp_wire_format() {
        // C++ NodeDefManager::serialize writes:
        //   u8 version (= 1)
        //   u16 count (= 0)
        //   string32 of inner data (= u32 length prefix 0, no body)
        let payload = serialize_empty_nodedef();
        assert_eq!(payload, vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_itemdef_response_uses_zlib_below_proto_48() {
        // proto < 48 → zlib. A zlib stream starts with a 2-byte header
        // whose first byte is `0x78` (CMF: deflate, 32K window).
        let packet = bytes(&create_itemdef_response(&serialize_empty_itemdef(), 42));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ItemDef as u16).to_be_bytes()
        );
        // The long string is u32 length (4 bytes) + compressed data.
        // Total packet = 2 (cmd) + 4 (len) + compressed payload.
        let compressed_len =
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        assert_eq!(
            compressed_len,
            packet.len() - 6,
            "long string length must match payload"
        );
        assert!(
            compressed_len > 0,
            "compressed payload must be non-empty (was 0 → client EOF)"
        );
        // zlib magic: 0x78 xx
        assert_eq!(packet[6], 0x78, "expected zlib CMF byte");
    }

    #[test]
    fn test_nodedef_response_uses_zlib_below_proto_48() {
        let packet = bytes(&create_nodedef_response(&serialize_empty_nodedef(), 42));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::NodeDef as u16).to_be_bytes()
        );
        let compressed_len =
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        assert_eq!(compressed_len, packet.len() - 6);
        assert!(compressed_len > 0);
        assert_eq!(packet[6], 0x78, "expected zlib CMF byte");
    }

    #[test]
    fn test_itemdef_response_uses_zstd_at_or_above_proto_48() {
        // proto >= 48 → zstd. A zstd frame starts with magic 0x28 0xB5
        // 0x2F 0xFD.
        let packet = bytes(&create_itemdef_response(&serialize_empty_itemdef(), 48));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ItemDef as u16).to_be_bytes()
        );
        let compressed_len =
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        assert_eq!(compressed_len, packet.len() - 6);
        assert!(compressed_len > 0);
        assert_eq!(
            &packet[6..10],
            &[0x28, 0xB5, 0x2F, 0xFD],
            "expected zstd magic number"
        );
    }

    #[test]
    fn test_nodedef_response_uses_zstd_at_or_above_proto_48() {
        let packet = bytes(&create_nodedef_response(&serialize_empty_nodedef(), 48));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::NodeDef as u16).to_be_bytes()
        );
        let compressed_len =
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        assert_eq!(compressed_len, packet.len() - 6);
        assert!(compressed_len > 0);
        assert_eq!(&packet[6..10], &[0x28, 0xB5, 0x2F, 0xFD]);
    }

    #[test]
    fn test_itemdef_zlib_roundtrip_decompresses() {
        // The C++ client uses zlib's `inflate`. Make sure our payload
        // decompresses to exactly the bytes we serialized (so the
        // client's deSerialize won't see EOF).
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let original = serialize_empty_itemdef();
        let packet = bytes(&create_itemdef_response(&original, 42));
        let compressed_len =
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        let mut decoder = ZlibDecoder::new(&packet[6..6 + compressed_len]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .expect("zlib decode must not fail (would trigger client EOF)");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_create_modchannel_signal() {
        let packet = bytes(&create_modchannel_signal(
            ModChannelSignal::JoinOk,
            "test_chan",
        ));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ModChannelSignal as u16).to_be_bytes()
        );
        assert_eq!(packet[2], ModChannelSignal::JoinOk as u8);
        // u16 length prefix (9 = "test_chan".len())
        assert_eq!(packet[3..5], 9u16.to_be_bytes());
        assert_eq!(&packet[5..14], b"test_chan");
    }

    #[test]
    fn test_create_modchannel_msg() {
        let packet = bytes(&create_modchannel_msg("chan", "hello"));
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ModChannelMsg as u16).to_be_bytes()
        );
        // u16 length prefix (4 = "chan".len()) + "chan"
        assert_eq!(&packet[2..8], &[0x00, 0x04, b'c', b'h', b'a', b'n']);
        // u16 length prefix (5 = "hello".len()) + "hello"
        assert_eq!(&packet[8..15], &[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }
}
