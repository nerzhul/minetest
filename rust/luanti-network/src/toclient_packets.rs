//! TOCLIENT packet creation functions
//!
//! This module provides functions to create protocol packets sent from the server to clients.
//! These are pure functions that don't depend on session state and can be reused across
//! different server implementations.

use std::io::Write;

use crate::opcodes::{AccessDeniedCode, ToClientCommand};
use crate::wire::WireWriter;

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
) -> Vec<u8> {
    let mut w = WireWriter::with_capacity(2 + 1 + 2 + 2 + 4 + 2);
    w.write_u16(ToClientCommand::Hello as u16);
    w.write_u8(serialization_version);
    w.write_u16(0); // compression (unused)
    w.write_u16(protocol_version);
    w.write_u32(auth_mechs);
    w.write_string(b""); // unused username
    w.into_bytes()
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
pub fn create_srp_bytes_s_b_response(salt: &[u8], bytes_b: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::with_capacity(2 + 2 + salt.len() + 2 + bytes_b.len());
    w.write_u16(ToClientCommand::SrpBytesSB as u16);
    w.write_string(salt);
    w.write_string(bytes_b);
    w.into_bytes()
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
) -> Vec<u8> {
    let mut w = WireWriter::with_capacity(2 + 12 + 8 + 4 + 4);
    w.write_u16(ToClientCommand::AuthAccept as u16);
    w.write_v3f(0.0, 0.0, 0.0); // unused position
    w.write_u64(map_seed);
    w.write_f32(send_interval);
    w.write_u32(sudo_auth_mechs);
    w.into_bytes()
}

/// Create TOCLIENT_ACCESS_DENIED response
///
/// This packet denies access to a client with a specific reason code and message.
///
/// # Arguments
/// * `code` - The denial reason code
/// * `message` - Human-readable message explaining the denial
pub fn create_access_denied(code: AccessDeniedCode, message: &str) -> Vec<u8> {
    let mut w = WireWriter::with_capacity(2 + 1 + 2 + message.len() + 1);
    w.write_u16(ToClientCommand::AccessDenied as u16);
    w.write_u8(code as u8);
    w.write_utf8(message);
    w.write_u8(0); // reconnect
    w.into_bytes()
}

/// Create TOCLIENT_CHAT_MESSAGE response
///
/// This packet sends a chat message to the client. The message is encoded in UTF-16
/// as per the protocol specification.
///
/// # Arguments
/// * `message` - The message text to send
pub fn create_chat_message_response(message: &str) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::ChatMessage as u16);
    w.write_u8(1); // version
    w.write_u8(0); // message type (normal)
    w.write_wstring(""); // sender name
    w.write_wstring(message);
    w.into_bytes()
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
pub fn create_announce_media(files: &[MediaAnnounceEntry], remote_media: &str) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::AnnounceMedia as u16);
    w.write_u16(files.len() as u16);
    for f in files {
        w.write_utf8(&f.name);
        // base64-encode the raw SHA-1 digest
        let b64 = crate::base64_util::encode(&f.sha1_digest);
        w.write_utf8(&b64);
    }
    w.write_utf8(remote_media);
    w.into_bytes()
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
) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::Media as u16);
    w.write_u16(total_bunches);
    w.write_u16(bunch_index);
    w.write_u32(files.len() as u32);
    for f in files {
        w.write_utf8(&f.name);
        // data: u32 length + raw bytes (long string, no compression)
        w.write_long_string(&f.data);
    }
    w.into_bytes()
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
pub fn create_nodedef_response(serialized: &[u8], protocol_version: u16) -> Vec<u8> {
    let compressed = compress_definitions(serialized, protocol_version);
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::NodeDef as u16);
    w.write_long_string(&compressed);
    w.into_bytes()
}

/// Create `TOCLIENT_ITEMDEF` packet (compressed item definitions).
///
/// The payload is a serialized `ItemDefManager`, compressed with zlib
/// (protocol < 48) or zstd (protocol >= 48). See `create_nodedef_response`
/// for the rationale behind the compression.
pub fn create_itemdef_response(serialized: &[u8], protocol_version: u16) -> Vec<u8> {
    let compressed = compress_definitions(serialized, protocol_version);
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::ItemDef as u16);
    w.write_long_string(&compressed);
    w.into_bytes()
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
    let mut w = WireWriter::new();
    w.write_u8(0); // version
    w.write_u16(0); // count
    w.write_u16(0); // alias_count
    w.into_bytes()
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
    let mut w = WireWriter::new();
    w.write_u8(1); // version
    w.write_u16(0); // count
    w.write_u32(0); // string32 length = 0 (no inner data)
    w.into_bytes()
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
pub fn create_time_of_day(time_of_day: u16, time_speed: f32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::TimeOfDay as u16);
    w.write_u16(time_of_day);
    w.write_f32(time_speed);
    w.into_bytes()
}

/// Create `TOCLIENT_CSM_RESTRICTION_FLAGS` (client-side mod restrictions).
///
/// `flags` is a `CSMRestrictionFlags` bitmask. `0` disables all
/// restrictions; `CSM_RF_ALL` (0xFFFFFFFF) enables all.
pub fn create_csm_restriction_flags(flags: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::CsmRestrictionFlags as u16);
    w.write_u32(flags);
    w.into_bytes()
}

/// Create `TOCLIENT_MOVEMENT` (default movement parameters).
///
/// # Arguments
/// * `default_speed` - default movement speed (units/s)
/// * `walk_speed` - walking speed
/// * `crouch_speed` - crouching speed
/// * `fast_speed` - fast (sprint) speed
/// * `climb_speed` - climbing speed
/// * `jump_speed` - jump velocity
/// * `gravity` - gravity acceleration
/// * `liquid_fluidity` - liquid fluidity multiplier
/// * `liquid_fluidity_smooth` - liquid smoothing
/// * `liquid_sink` - sink rate in liquids
/// * `acceleration_default` - default acceleration in air
/// * `acceleration_fast` - fast (sprint) acceleration in air
/// * `speed_fast` - fast (sprint) movement speed
/// * `acceleration_air` - midair acceleration
/// * `speed_air` - midair speed
/// * `speed_climb` - climb speed
/// * `speed_crouch` - crouch walk speed
/// * `speed_fast_crouch` - crouch fast speed
/// * `speed_walk` - walk speed
/// * `liquid_sensitivity` - liquid jump sensitivity
pub fn create_movement(
    default_speed: f32,
    walk_speed: f32,
    crouch_speed: f32,
    fast_speed: f32,
    climb_speed: f32,
    jump_speed: f32,
    gravity: f32,
    liquid_fluidity: f32,
    liquid_fluidity_smooth: f32,
    liquid_sink: f32,
    acceleration_default: f32,
    acceleration_fast: f32,
    speed_fast: f32,
    acceleration_air: f32,
    speed_air: f32,
    speed_climb: f32,
    speed_crouch: f32,
    speed_fast_crouch: f32,
    speed_walk: f32,
    liquid_sensitivity: f32,
) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::Movement as u16);
    w.write_f32(default_speed);
    w.write_f32(walk_speed);
    w.write_f32(crouch_speed);
    w.write_f32(fast_speed);
    w.write_f32(climb_speed);
    w.write_f32(jump_speed);
    w.write_f32(gravity);
    w.write_f32(liquid_fluidity);
    w.write_f32(liquid_fluidity_smooth);
    w.write_f32(liquid_sink);
    w.write_f32(acceleration_default);
    w.write_f32(acceleration_fast);
    w.write_f32(speed_fast);
    w.write_f32(acceleration_air);
    w.write_f32(speed_air);
    w.write_f32(speed_climb);
    w.write_f32(speed_crouch);
    w.write_f32(speed_fast_crouch);
    w.write_f32(speed_walk);
    w.write_f32(liquid_sensitivity);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_hello_response() {
        let packet = create_hello_response(29, 42, 0x01);
        assert_eq!(packet[0..2], (ToClientCommand::Hello as u16).to_be_bytes());
        assert_eq!(packet[2], 29); // serialization version
    }

    #[test]
    fn test_create_auth_accept_response() {
        let packet = create_auth_accept_response(12345, 0.1, 0);
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
        let packet = create_time_of_day(6000, 1.0);
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
        let packet = create_srp_bytes_s_b_response(&salt, &b);
        assert_eq!(
            packet[0..2],
            (ToClientCommand::SrpBytesSB as u16).to_be_bytes()
        );
        // salt length is u16 BE
        assert_eq!(packet[2..4], (16u16).to_be_bytes());
    }

    #[test]
    fn test_create_access_denied() {
        let packet = create_access_denied(AccessDeniedCode::WrongVersion, "Test message");
        assert_eq!(
            packet[0..2],
            (ToClientCommand::AccessDenied as u16).to_be_bytes()
        );
        assert_eq!(packet[2], AccessDeniedCode::WrongVersion as u8);
    }

    #[test]
    fn test_create_chat_message_response() {
        let packet = create_chat_message_response("Hello");
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ChatMessage as u16).to_be_bytes()
        );
        assert_eq!(packet[2], 1); // version
        assert_eq!(packet[3], 0); // message type
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
        let packet = create_itemdef_response(&serialize_empty_itemdef(), 42);
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ItemDef as u16).to_be_bytes()
        );
        // The long string is u32 length (4 bytes) + compressed data.
        // Total packet = 2 (cmd) + 4 (len) + compressed payload.
        let compressed_len = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]])
            as usize;
        assert_eq!(compressed_len, packet.len() - 6, "long string length must match payload");
        assert!(compressed_len > 0, "compressed payload must be non-empty (was 0 → client EOF)");
        // zlib magic: 0x78 xx
        assert_eq!(packet[6], 0x78, "expected zlib CMF byte");
    }

    #[test]
    fn test_nodedef_response_uses_zlib_below_proto_48() {
        let packet = create_nodedef_response(&serialize_empty_nodedef(), 42);
        assert_eq!(
            packet[0..2],
            (ToClientCommand::NodeDef as u16).to_be_bytes()
        );
        let compressed_len = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]])
            as usize;
        assert_eq!(compressed_len, packet.len() - 6);
        assert!(compressed_len > 0);
        assert_eq!(packet[6], 0x78, "expected zlib CMF byte");
    }

    #[test]
    fn test_itemdef_response_uses_zstd_at_or_above_proto_48() {
        // proto >= 48 → zstd. A zstd frame starts with magic 0x28 0xB5
        // 0x2F 0xFD.
        let packet = create_itemdef_response(&serialize_empty_itemdef(), 48);
        assert_eq!(
            packet[0..2],
            (ToClientCommand::ItemDef as u16).to_be_bytes()
        );
        let compressed_len = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]])
            as usize;
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
        let packet = create_nodedef_response(&serialize_empty_nodedef(), 48);
        assert_eq!(
            packet[0..2],
            (ToClientCommand::NodeDef as u16).to_be_bytes()
        );
        let compressed_len = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]])
            as usize;
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
        let packet = create_itemdef_response(&original, 42);
        let compressed_len = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]])
            as usize;
        let mut decoder = ZlibDecoder::new(&packet[6..6 + compressed_len]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .expect("zlib decode must not fail (would trigger client EOF)");
        assert_eq!(decompressed, original);
    }
}
