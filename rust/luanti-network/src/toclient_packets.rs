//! TOCLIENT packet creation functions
//!
//! This module provides functions to create protocol packets sent from the server to clients.
//! These are pure functions that don't depend on session state and can be reused across
//! different server implementations.

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
/// # Arguments
/// * `map_seed` - u64 seed of the map
/// * `send_interval` - recommended send interval in seconds (server -> client)
/// * `sudo_auth_mechs` - bitmask of auth mechanisms available for sudo mode
pub fn create_auth_accept_response(
    map_seed: u64,
    send_interval: f32,
    sudo_auth_mechs: u32,
) -> Vec<u8> {
    let mut w = WireWriter::with_capacity(2 + 12 + 8 + 2 + 4);
    w.write_u16(ToClientCommand::AuthAccept as u16);
    w.write_v3f(0.0, 0.0, 0.0); // unused position
    w.write_u64(map_seed);
    w.write_f1000(send_interval);
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

/// Create `TOCLIENT_NODEDEF` packet (zstd-compressed node definitions).
///
/// For now this is a stub that sends a valid (empty) packet so the
/// client can proceed. A full implementation will serialize the
/// NodeDefManager and zstd-compress it.
pub fn create_nodedef_response(serialized: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::NodeDef as u16);
    w.write_long_string(serialized);
    w.into_bytes()
}

/// Create `TOCLIENT_ITEMDEF` packet (zstd-compressed item definitions).
///
/// Same as `create_nodedef_response`, a stub sending the raw
/// (possibly empty) serialized buffer.
pub fn create_itemdef_response(serialized: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::ItemDef as u16);
    w.write_long_string(serialized);
    w.into_bytes()
}

/// Create `TOCLIENT_TIME_OF_DAY`.
///
/// # Arguments
/// * `time_of_day` - 0..=23999, 0 = midnight, 12000 = noon
/// * `time_speed` - speed of the day/night cycle (in game-time units per real second)
pub fn create_time_of_day(time_of_day: u16, time_speed: f32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u16(ToClientCommand::TimeOfDay as u16);
    w.write_u16(time_of_day);
    w.write_f1000(time_speed);
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
}
