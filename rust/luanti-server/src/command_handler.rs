// Command handler for processing protocol commands
// This layer sits on top of the session layer and processes application-level commands
//
// Each handler is fed a `NetworkPacket` (the C++ `NetworkPacket` is
// ported to `luanti_network::NetworkPacket`). The handler reads the
// fields it needs from the packet and returns a list of response
// payloads, each of which is the raw `command (u16 BE) + payload` bytes
// the dispatcher will wrap in an MTP `Original` or `Reliable` frame.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::net::SocketAddr;

use luanti_auth_db::AuthDatabase;
use luanti_network::{
    auth as auth_helpers,
    base64_util as base64,
    create_access_denied, create_announce_media, create_auth_accept_response,
    create_chat_message_response, create_csm_restriction_flags, create_hello_response,
    create_itemdef_response, create_media_bunch, create_movement, create_nodedef_response,
    create_srp_bytes_s_b_response, create_time_of_day,
    srp as srp_helpers,
    AccessDeniedCode, AuthMechanism, MediaAnnounceEntry, MediaBunchFile, NetworkPacket, Session,
    SrpVerifier, ToServerCommand, ToServerConnectionState,
};

use crate::frame::hex_preview;

/// Highest serialization version the server can write.
///
/// Corresponds to C++ `SER_FMT_VER_HIGHEST_WRITE`.
const SER_FMT_VER_HIGHEST_WRITE: u8 = 29;

/// Default map seed reported in `TOCLIENT_AUTH_ACCEPT`.
const DEFAULT_MAP_SEED: u64 = 12345;

/// Recommended send interval reported in `TOCLIENT_AUTH_ACCEPT` (seconds).
const DEFAULT_SEND_INTERVAL: f32 = 0.1;

/// Default time of day (0 = midnight).
const DEFAULT_TIME_OF_DAY: u16 = 6000; // ~ 6am

/// Default day/night speed.
const DEFAULT_TIME_SPEED: f32 = 1.0;

/// State stored per-peer between the SRP `_A` and `_M` packets.
pub struct PendingSrp {
    #[allow(dead_code)]
    pub verifier: SrpVerifier,
    #[allow(dead_code)]
    pub salt: Vec<u8>,
}

/// Command handler that processes application-level protocol commands
pub struct CommandHandler {
    pub min_protocol_version: u16,
    pub max_protocol_version: u16,

    auth_db: Box<dyn AuthDatabase>,
    pending_srp: std::collections::HashMap<u16, PendingSrp>,
}

impl CommandHandler {
    pub fn new(
        min_protocol_version: u16,
        max_protocol_version: u16,
        auth_db: Box<dyn AuthDatabase>,
    ) -> Self {
        CommandHandler {
            min_protocol_version,
            max_protocol_version,
            auth_db,
            pending_srp: std::collections::HashMap::new(),
        }
    }

    /// Process a command packet from a client.
    ///
    /// Returns a vector of response payloads (each one is the raw
    /// `command (2 bytes BE) + payload` bytes the dispatcher will
    /// wrap in an MTP `Original` or `Reliable` frame).
    pub fn handle_command(
        &mut self,
        session: &mut Session,
        packet: &NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let cmd = ToServerCommand::from_u16(packet.command());
        let Some(cmd) = cmd else {
            let preview = hex_preview(packet.as_slice(), 32);
            warn!(
                "Unknown command 0x{:04x} from {} (peer {}, {} bytes payload: {}{})",
                packet.command(),
                peer_addr,
                session.peer_id,
                packet.len(),
                preview,
                if packet.len() > 32 { "…" } else { "" },
            );
            return Ok(vec![]);
        };

        debug!("Processing command {} from {}", cmd, peer_addr);

        // Check if session state allows this command
        if !self.check_command_state(session, cmd) {
            warn!(
                "Command {} not allowed in current state {:?} from {}",
                cmd, session.connection_state, peer_addr
            );
            return Ok(vec![]);
        }

        // Each handler takes a fresh clone of the packet so the read
        // cursor is independent. Cloning a NetworkPacket is cheap (it
        // is just a Vec<u8> + usize + two u16s).
        let mut pkt = packet.clone();

        match cmd {
            ToServerCommand::Init => self.handle_init(session, &mut pkt, peer_addr),
            ToServerCommand::FirstSrp => self.handle_first_srp(session, &mut pkt, peer_addr),
            ToServerCommand::SrpBytesA => self.handle_srp_bytes_a(session, &mut pkt, peer_addr),
            ToServerCommand::SrpBytesM => self.handle_srp_bytes_m(session, &mut pkt, peer_addr),
            ToServerCommand::Init2 => self.handle_init2(session, &mut pkt, peer_addr),
            ToServerCommand::RequestMedia => {
                self.handle_request_media(session, &mut pkt, peer_addr)
            }
            ToServerCommand::HaveMedia => self.handle_have_media(session, &mut pkt, peer_addr),
            ToServerCommand::GotBlocks => self.handle_got_blocks(session, &mut pkt),
            ToServerCommand::PlayerPos => self.handle_player_pos(session, &pkt),
            ToServerCommand::ChatMessage => self.handle_chat_message(session, &mut pkt),
            ToServerCommand::ClientReady => self.handle_client_ready(session, &mut pkt),
            _ => {
                info!("Handler not implemented for {}", cmd);
                Ok(vec![])
            }
        }
    }

    /// Check if command is allowed in current session state.
    fn check_command_state(&self, session: &Session, cmd: ToServerCommand) -> bool {
        // Special case: media-loading commands are only allowed after
        // TOSERVER_INIT2 has been received.
        if matches!(
            cmd,
            ToServerCommand::RequestMedia
                | ToServerCommand::HaveMedia
                | ToServerCommand::GotBlocks
                | ToServerCommand::ClientReady
        ) {
            return std::mem::discriminant(&cmd.required_state())
                == std::mem::discriminant(&session.connection_state)
                && session.media_loading;
        }
        std::mem::discriminant(&cmd.required_state())
            == std::mem::discriminant(&session.connection_state)
    }

    // ------------------------------------------------------------------
    // Handlers
    // ------------------------------------------------------------------

    /// Handle TOSERVER_INIT command
    fn handle_init(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        // TOSERVER_INIT:
        //   u8  serialization_version (= SER_FMT_VER_HIGHEST_READ)
        //   u16 unused (supported network compression modes)
        //   u16 min_net_proto_version
        //   u16 max_net_proto_version
        //   std::string player name
        let client_ser_ver = packet.read_u8()?;
        let _compression = packet.read_u16()?;
        let min_proto = packet.read_u16()?;
        let max_proto = packet.read_u16()?;
        let player_name = packet.read_utf8()?;

        info!(
            "Client {} INIT: ser_ver={}, proto={}-{}, name='{}'",
            peer_addr, client_ser_ver, min_proto, max_proto, player_name
        );

        if !auth_helpers::is_valid_player_name(&player_name) {
            warn!(
                "Player with invalid name '{}' tried to connect from {}",
                player_name, peer_addr
            );
            return Ok(vec![create_access_denied(
                AccessDeniedCode::WrongCharsInName,
                "Invalid characters in player name",
            )]);
        }

        let negotiated_ser_ver = std::cmp::min(client_ser_ver, SER_FMT_VER_HIGHEST_WRITE);
        let negotiated_proto = std::cmp::min(max_proto, self.max_protocol_version);
        if negotiated_proto < self.min_protocol_version || negotiated_proto < min_proto {
            warn!("Protocol version mismatch with {}", peer_addr);
            return Ok(vec![create_access_denied(
                AccessDeniedCode::WrongVersion,
                "Protocol version mismatch",
            )]);
        }

        let (auth_mechs, enc_pwd) = self.determine_auth_mechanism(&player_name)?;
        debug!("Auth mechanisms for {}: 0x{:08x}", player_name, auth_mechs);

        session.protocol_version = Some(negotiated_proto);
        session.player_name = Some(player_name);
        session.enc_pwd = enc_pwd;
        session.allowed_auth_mechs = auth_mechs;
        session.chosen_mech = AuthMechanism::None as u32;
        session.create_player_on_auth_success = false;
        session.media_loading = false;
        session.client_ready = false;
        session.connection_state = ToServerConnectionState::Startup;

        debug!(
            "Negotiated with {}: ser_ver={}, proto={}",
            peer_addr, negotiated_ser_ver, negotiated_proto
        );

        Ok(vec![create_hello_response(
            negotiated_ser_ver,
            negotiated_proto,
            auth_mechs,
        )])
    }

    /// Handle TOSERVER_FIRST_SRP command.
    ///
    /// Wire format: `std::string salt | std::string verifier | u8 is_empty`
    fn handle_first_srp(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let salt = packet.read_string()?;
        let verifier = packet.read_string()?;
        let is_empty = packet.read_u8()?;

        info!(
            "FIRST_SRP from {}: is_empty={}, salt_len={}, verifier_len={}",
            peer_addr,
            is_empty,
            salt.len(),
            verifier.len()
        );

        let player_name = session
            .player_name
            .clone()
            .ok_or_else(|| anyhow!("FIRST_SRP without player name"))?;

        if is_empty == 1 {
            return Ok(vec![create_access_denied(
                AccessDeniedCode::EmptyPassword,
                "Empty passwords are not allowed",
            )]);
        }

        if !session.create_player_on_auth_success
            && self.auth_db.get_auth(&player_name).is_ok()
        {
            return Ok(vec![create_access_denied(
                AccessDeniedCode::AlreadyConnected,
                "Player already exists",
            )]);
        }

        let enc_pwd = auth_helpers::encode_srp_verifier(&verifier, &salt);

        if session.create_player_on_auth_success {
            self.auth_db.save_auth(&luanti_auth_db::AuthEntry {
                id: 0,
                name: player_name.clone(),
                password: enc_pwd.clone(),
                privileges: vec![],
                last_login: now_secs(),
            })?;
            session.create_player_on_auth_success = false;
        } else {
            let mut entry = luanti_auth_db::AuthEntry {
                id: 0,
                name: player_name.clone(),
                password: enc_pwd.clone(),
                privileges: vec![],
                last_login: now_secs(),
            };
            self.auth_db.create_auth(&mut entry)?;
        }

        session.enc_pwd = Some(enc_pwd);
        // Stays in Startup, the client must follow up with INIT2 once
        // it receives AUTH_ACCEPT.

        Ok(vec![create_auth_accept_response(
            DEFAULT_MAP_SEED,
            DEFAULT_SEND_INTERVAL,
            AuthMechanism::FirstSrp as u32,
        )])
    }

    /// Handle TOSERVER_SRP_BYTES_A command.
    ///
    /// Wire format: `std::string bytes_A | u8 based_on`
    fn handle_srp_bytes_a(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let bytes_a = packet.read_string()?;
        let based_on = packet.read_u8()?;

        let chosen = if based_on == 0 {
            AuthMechanism::LegacyPassword as u32
        } else {
            AuthMechanism::Srp as u32
        };

        if session.allowed_auth_mechs & chosen == 0 {
            warn!(
                "Client from {} tried to use disallowed auth mech {}",
                peer_addr, chosen
            );
            return Ok(vec![create_access_denied(
                AccessDeniedCode::UnexpectedData,
                "Auth mechanism not allowed",
            )]);
        }
        session.chosen_mech = chosen;

        let enc_pwd = session
            .enc_pwd
            .as_ref()
            .ok_or_else(|| anyhow!("SRP_BYTES_A without stored enc_pwd"))?;
        let player_name = session
            .player_name
            .clone()
            .ok_or_else(|| anyhow!("SRP_BYTES_A without player name"))?;

        let (verifier, salt) = match based_on {
            0 => {
                let lower = player_name.to_lowercase();
                let (s, v) =
                    srp_helpers::create_salted_verification_key(&lower, enc_pwd.as_bytes(), None)?;
                (v, s)
            }
            1 => {
                let mut v = Vec::new();
                let mut s = Vec::new();
                if !auth_helpers::decode_srp_verifier_and_salt(enc_pwd, &mut v, &mut s) {
                    return Ok(vec![create_access_denied(
                        AccessDeniedCode::ServerFail,
                        "Invalid stored verifier",
                    )]);
                }
                (v, s)
            }
            _ => {
                return Ok(vec![create_access_denied(
                    AccessDeniedCode::UnexpectedData,
                    "Unknown based_on value",
                )]);
            }
        };

        let (verifier_obj, bytes_b) = SrpVerifier::new(
            &player_name.to_lowercase(),
            &salt,
            &verifier,
            &bytes_a,
            None,
        )
        .map_err(|e| {
            anyhow!("SRP safety check failed: {} (likely A mod N == 0 or invalid A)", e)
        })?;

        self.pending_srp.insert(
            session.peer_id,
            PendingSrp {
                verifier: verifier_obj,
                salt: salt.clone(),
            },
        );

        info!(
            "SRP_BYTES_A from {}: based_on={}, len_A={}, sending B ({} bytes)",
            peer_addr,
            based_on,
            bytes_a.len(),
            bytes_b.len()
        );

        Ok(vec![create_srp_bytes_s_b_response(&salt, &bytes_b)])
    }

    /// Handle TOSERVER_SRP_BYTES_M command.
    ///
    /// Wire format: `std::string bytes_M`
    fn handle_srp_bytes_m(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        _peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let bytes_m = packet.read_string()?;

        let mut pending = match self.pending_srp.remove(&session.peer_id) {
            Some(p) => p,
            None => {
                return Ok(vec![create_access_denied(
                    AccessDeniedCode::UnexpectedData,
                    "No pending SRP session",
                )]);
            }
        };

        let player_name = session
            .player_name
            .clone()
            .ok_or_else(|| anyhow!("SRP_M without player name"))?;

        match pending.verifier.verify_session(&bytes_m) {
            Ok(Some(_hamk)) => {
                info!("SRP auth succeeded for {}", player_name);

                if session.create_player_on_auth_success {
                    let mut entry = luanti_auth_db::AuthEntry {
                        id: 0,
                        name: player_name.clone(),
                        password: session.enc_pwd.clone().unwrap_or_default(),
                        privileges: vec![],
                        last_login: now_secs(),
                    };
                    if let Err(e) = self.auth_db.create_auth(&mut entry) {
                        warn!("Failed to create auth entry: {}", e);
                        return Ok(vec![create_access_denied(
                            AccessDeniedCode::ServerFail,
                            "Failed to create account",
                        )]);
                    }
                    session.create_player_on_auth_success = false;
                }

                Ok(vec![create_auth_accept_response(
                    DEFAULT_MAP_SEED,
                    DEFAULT_SEND_INTERVAL,
                    AuthMechanism::FirstSrp as u32,
                )])
            }
            Ok(None) => {
                warn!("SRP auth failed for {} (wrong M)", player_name);
                Ok(vec![create_access_denied(
                    AccessDeniedCode::WrongPassword,
                    "Wrong password",
                )])
            }
            Err(e) => {
                warn!("SRP_M verification error: {}", e);
                Ok(vec![create_access_denied(
                    AccessDeniedCode::UnexpectedData,
                    "Invalid M",
                )])
            }
        }
    }

    /// Handle TOSERVER_INIT2 command.
    ///
    /// The client sends this as an ACK for TOCLIENT_AUTH_ACCEPT. We send
    /// it back the init data: ItemDef, NodeDef, media announcement, time
    /// of day, CSM restrictions, default movement, and announce that
    /// media is being loaded.
    fn handle_init2(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        // Wire format: optional std::string lang_code
        let lang = packet.read_utf8().ok();

        info!(
            "Client {} ({}) sent INIT2 (lang={:?})",
            peer_addr,
            session.player_name.as_deref().unwrap_or("?"),
            lang
        );

        // Mark the session as in the media-loading phase but keep
        // connection_state == Startup so the state machine still
        // accepts the media-related commands.
        session.media_loading = true;

        // Clear any pending SRP state
        self.pending_srp.remove(&session.peer_id);

        // Build the init-data packet stream.
        // For a minimal server with no mods, the ItemDef/NodeDef
        // payloads can be empty (the client will accept this).
        let mut responses = Vec::new();
        responses.push(create_itemdef_response(&[]));
        responses.push(create_nodedef_response(&[]));
        responses.push(create_announce_media(&MEDIA_FILES, ""));
        responses.push(create_time_of_day(DEFAULT_TIME_OF_DAY, DEFAULT_TIME_SPEED));
        responses.push(create_csm_restriction_flags(CSM_RF_NONE));
        responses.push(create_movement(
            DEFAULT_MOVEMENT.default_speed,
            DEFAULT_MOVEMENT.walk_speed,
            DEFAULT_MOVEMENT.crouch_speed,
            DEFAULT_MOVEMENT.fast_speed,
            DEFAULT_MOVEMENT.climb_speed,
            DEFAULT_MOVEMENT.jump_speed,
            DEFAULT_MOVEMENT.gravity,
            DEFAULT_MOVEMENT.liquid_fluidity,
            DEFAULT_MOVEMENT.liquid_fluidity_smooth,
            DEFAULT_MOVEMENT.liquid_sink,
            DEFAULT_MOVEMENT.acceleration_default,
            DEFAULT_MOVEMENT.acceleration_fast,
            DEFAULT_MOVEMENT.speed_fast,
            DEFAULT_MOVEMENT.acceleration_air,
            DEFAULT_MOVEMENT.speed_air,
            DEFAULT_MOVEMENT.speed_climb,
            DEFAULT_MOVEMENT.speed_crouch,
            DEFAULT_MOVEMENT.speed_fast_crouch,
            DEFAULT_MOVEMENT.speed_walk,
            DEFAULT_MOVEMENT.liquid_sensitivity,
        ));

        Ok(responses)
    }

    /// Handle TOSERVER_REQUEST_MEDIA command.
    ///
    /// Wire format: `u16 count | count * std::string name`
    fn handle_request_media(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let count = packet.read_u16()? as usize;
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            names.push(packet.read_utf8()?);
        }
        info!(
            "Client {} ({}) requested {} media file(s)",
            peer_addr,
            session.player_name.as_deref().unwrap_or("?"),
            names.len()
        );

        // Find the requested files that the server actually has.
        // For now MEDIA_FILES is empty, so we always send an empty
        // bunch (count=0). The client will interpret this as "all
        // requested files are missing/unavailable" and proceed.
        let available: Vec<String> = names
            .into_iter()
            .filter(|n| MEDIA_FILES.iter().any(|m| &m.name == n))
            .collect();

        let bunches: Vec<Vec<MediaBunchFile>> = if available.is_empty() {
            // Send one empty bunch to signal the end of the media
            // transfer without sending any data.
            vec![vec![]]
        } else {
            available
                .chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|n| {
                            let data = MEDIA_DATA
                                .iter()
                                .find(|(name, _)| name == n)
                                .map(|(_, d)| d.clone())
                                .unwrap_or_default();
                            MediaBunchFile {
                                name: n.clone(),
                                data,
                            }
                        })
                        .collect()
                })
                .collect()
        };

        let total = bunches.len() as u16;
        let mut responses = Vec::new();
        for (i, bunch) in bunches.into_iter().enumerate() {
            responses.push(create_media_bunch(total, i as u16, &bunch));
        }
        Ok(responses)
    }

    /// Handle TOSERVER_HAVE_MEDIA command.
    ///
    /// Wire format: `u8 count | count * u32 token`
    fn handle_have_media(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<Vec<u8>>> {
        let count = packet.read_u8()? as usize;
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            tokens.push(packet.read_u32()?);
        }
        info!(
            "Client {} ({}) acknowledged {} media token(s): {:?}",
            peer_addr,
            session.player_name.as_deref().unwrap_or("?"),
            tokens.len(),
            tokens
        );
        Ok(vec![])
    }

    /// Handle TOSERVER_GOTBLOCKS command.
    ///
    /// Wire format: `u8 count | count * v3s16 pos`
    fn handle_got_blocks(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<Vec<u8>>> {
        let count = packet.read_u8()?;
        // We don't have a real map yet, so we just acknowledge.
        debug!(
            "GOTBLOCKS from peer {} ({} blocks)",
            session.peer_id, count
        );
        let _ = packet.rest(); // drop any remaining positions
        Ok(vec![])
    }

    /// Handle TOSERVER_PLAYERPOS command
    fn handle_player_pos(
        &mut self,
        session: &mut Session,
        _packet: &NetworkPacket,
    ) -> Result<Vec<Vec<u8>>> {
        debug!("Received PLAYERPOS from peer {}", session.peer_id);
        Ok(vec![])
    }

    /// Handle TOSERVER_CHAT_MESSAGE command
    fn handle_chat_message(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<Vec<u8>>> {
        let message = packet.read_wstring()?;

        info!(
            "Chat message from {} ({}): {}",
            session.player_name.as_deref().unwrap_or("unknown"),
            session.peer_id,
            message
        );

        Ok(vec![create_chat_message_response(&format!(
            "<{}> {}",
            session.player_name.as_deref().unwrap_or("Player"),
            message
        ))])
    }

    /// Handle TOSERVER_CLIENT_READY command.
    ///
    /// Wire format: `u8 major | u8 minor | u8 patch | u8 reserved | std::string full_version | u16 formspec_version`
    fn handle_client_ready(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<Vec<u8>>> {
        let major = packet.read_u8()?;
        let minor = packet.read_u8()?;
        let patch = packet.read_u8()?;
        let _reserved = packet.read_u8()?;
        let full_version = packet.read_utf8().unwrap_or_default();
        // Optional formspec version (since 5.1.0)
        let _formspec_ver = packet.read_u16().ok();

        info!(
            "Client {} ready: {}.{}.{} ({})",
            session.peer_id, major, minor, patch, full_version
        );

        // Client is fully connected.
        session.client_ready = true;
        session.connection_state = ToServerConnectionState::Ingame;

        Ok(vec![])
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Determine authentication mechanism for a player.
    fn determine_auth_mechanism(
        &mut self,
        player_name: &str,
    ) -> Result<(u32, Option<String>)> {
        match self.auth_db.get_auth(player_name) {
            Ok(auth_entry) => {
                let enc_pwd = auth_entry.password.clone();
                if base64::is_valid(&enc_pwd) && enc_pwd.starts_with('#') {
                    Ok((AuthMechanism::Srp as u32, Some(enc_pwd)))
                } else if base64::is_valid(&enc_pwd) {
                    Ok((AuthMechanism::LegacyPassword as u32, Some(enc_pwd)))
                } else {
                    warn!("Player {} has invalid stored password format", player_name);
                    Err(anyhow!("Invalid stored password format"))
                }
            }
            Err(_) => {
                info!("Player {} not found, allowing first SRP", player_name);
                Ok((AuthMechanism::FirstSrp as u32, None))
            }
        }
    }
}

// --- Module-level constants & helpers --------------------------------------

/// `CSM_RF_NONE` from the C++ `CSMRestrictionFlags` enum.
const CSM_RF_NONE: u32 = 0x0000_0000;

/// Default movement parameters. Matches the C++ defaults so the client
/// gets a sane experience.
struct MovementDefaults {
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
}

const DEFAULT_MOVEMENT: MovementDefaults = MovementDefaults {
    default_speed: 1.0,
    walk_speed: 1.0,
    crouch_speed: 1.0,
    fast_speed: 1.0,
    climb_speed: 1.0,
    jump_speed: 1.0,
    gravity: 1.0,
    liquid_fluidity: 1.0,
    liquid_fluidity_smooth: 1.0,
    liquid_sink: 1.0,
    acceleration_default: 1.0,
    acceleration_fast: 1.0,
    speed_fast: 1.0,
    acceleration_air: 1.0,
    speed_air: 1.0,
    speed_climb: 1.0,
    speed_crouch: 1.0,
    speed_fast_crouch: 1.0,
    speed_walk: 1.0,
    liquid_sensitivity: 1.0,
};

/// Server-side media files. Empty by default — extend at startup to
/// serve actual mods.
static MEDIA_FILES: Vec<MediaAnnounceEntry> = Vec::new();
static MEDIA_DATA: Vec<(String, Vec<u8>)> = Vec::new();

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a `NetworkPacket` with the given command code and
    /// the given raw payload bytes (which will be prepended with the
    /// 2-byte BE command).
    fn pkt(command: u16, payload: &[u8]) -> NetworkPacket {
        let mut p = NetworkPacket::new(command, payload.len());
        for b in payload {
            p.write_u8(*b);
        }
        p
    }

    /// Test fixture: a fresh auth DB plus the `TempDir` that backs it.
    /// Both must be kept alive for the lifetime of the test or the
    /// sqlite database goes read-only once the directory is dropped.
    struct AuthFixture {
        _tmp: tempfile::TempDir,
        db: luanti_auth_db::sqlite::AuthDatabaseSqlite,
    }

    fn make_auth_fixture() -> AuthFixture {
        let tmp = tempfile::TempDir::new().expect("tmp dir");
        let db = luanti_auth_db::sqlite::AuthDatabaseSqlite::new(tmp.path()).expect("auth db");
        AuthFixture { _tmp: tmp, db }
    }

    fn make_auth() -> luanti_auth_db::sqlite::AuthDatabaseSqlite {
        let f = make_auth_fixture();
        // We need the AuthDatabase trait object; the TempDir backing
        // it lives as long as the returned AuthDatabaseSqlite because
        // we move it into a Box. HACK: we leak the TempDir so the
        // sqlite file stays alive. Tests that need write access
        // should use `make_auth_fixture` directly.
        let db = f.db;
        std::mem::forget(f._tmp);
        db
    }

    #[test]
    fn init_rejects_wrong_version() {
        // Build a fake session in NotConnected state.
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));

        // INIT: ser_ver=29, compression=0, min_proto=10, max_proto=20, name="x"
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(10);
        p.write_u16(20);
        p.write_utf8("x");

        let responses = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        // Should respond with access denied
        assert_eq!(responses.len(), 1);
        // The response starts with TOCLIENT_ACCESS_DENIED = 0x0A
        let cmd = u16::from_be_bytes([responses[0][0], responses[0][1]]);
        assert_eq!(cmd, 0x0A);
    }

    #[test]
    fn init_rejects_invalid_name() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));

        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(40);
        p.write_u16(42);
        p.write_utf8("x x"); // space is invalid

        let responses = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_eq!(responses.len(), 1);
        let cmd = u16::from_be_bytes([responses[0][0], responses[0][1]]);
        assert_eq!(cmd, 0x0A);
    }

    #[test]
    fn media_commands_rejected_before_init2() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));
        session.connection_state = ToServerConnectionState::Startup;

        // REQUEST_MEDIA with count=0
        let p = pkt(0x0040, &[0x00, 0x00]);
        let responses = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert!(responses.is_empty());
    }

    #[test]
    fn srp_bytes_a_rejects_disallowed_mech() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        session.connection_state = ToServerConnectionState::Startup;
        session.player_name = Some("nrz".to_string());
        session.enc_pwd = Some("#1#fake".to_string());
        session.allowed_auth_mechs = AuthMechanism::LegacyPassword as u32; // only legacy

        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));

        // SRP_BYTES_A with based_on=1 (SRP mech) which is disallowed.
        let mut p = NetworkPacket::new(0x0051, 0);
        p.write_string(b"some-bytes");
        p.write_u8(1);

        let responses = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_eq!(responses.len(), 1);
        let cmd = u16::from_be_bytes([responses[0][0], responses[0][1]]);
        assert_eq!(cmd, 0x0A);
    }

    #[test]
    fn full_handshake() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let fixture = make_auth_fixture();
        let mut h = CommandHandler::new(40, 42, Box::new(fixture.db));

        // 1. INIT
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(40);
        p.write_u16(42);
        p.write_utf8("nrz");
        let r = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_eq!(r.len(), 1);
        let cmd = u16::from_be_bytes([r[0][0], r[0][1]]);
        assert_eq!(cmd, 0x0002); // TOCLIENT_HELLO
        assert_eq!(
            session.connection_state,
            ToServerConnectionState::Startup
        );

        // 2. FIRST_SRP
        let mut p = NetworkPacket::new(0x0050, 0);
        p.write_string(b"salt");
        p.write_string(b"verifier");
        p.write_u8(0);
        let r = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_eq!(r.len(), 1);
        let cmd = u16::from_be_bytes([r[0][0], r[0][1]]);
        assert_eq!(cmd, 0x0003); // TOCLIENT_AUTH_ACCEPT

        // 3. INIT2
        let p = NetworkPacket::new(0x0011, 0);
        let r = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        // Should send ItemDef + NodeDef + AnnounceMedia + TimeOfDay +
        // CsmRestrictionFlags + Movement = 6 packets.
        assert!(r.len() >= 6);
        assert!(session.media_loading);

        // 4. CLIENT_READY
        let mut p = NetworkPacket::new(0x0043, 0);
        p.write_u8(5);
        p.write_u8(8);
        p.write_u8(0);
        p.write_u8(0);
        p.write_utf8("5.8.0");
        let r = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert!(r.is_empty());
        assert!(session.client_ready);
        assert_eq!(
            session.connection_state,
            ToServerConnectionState::Ingame
        );
    }
}
