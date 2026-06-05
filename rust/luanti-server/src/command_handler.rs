// Command handler for processing protocol commands
// This layer sits on top of the session layer and processes application-level commands
//
// Each handler is fed a `NetworkPacket` (the C++ `NetworkPacket` is
// ported to `luanti_network::NetworkPacket`). The handler reads the
// fields it needs from the packet and returns a list of response
// packets, each one a fully-formed `NetworkPacket` (command opcode +
// payload) that the dispatcher will serialize to bytes and wrap in an
// MTP `Original` or `Reliable` frame. This matches the C++ style of
// `NetworkPacket resp_pkt(TOCLIENT_FOO, 0, peer_id); resp_pkt << ...;`.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::net::SocketAddr;

use luanti_auth_db::AuthDatabase;
use luanti_network::{
    auth as auth_helpers,
    base64_util as base64,
    create_access_denied, create_announce_media, create_auth_accept_response,
    create_chat_message_response, create_csm_restriction_flags, create_hello_response,
    create_itemdef_response, create_media_bunch, create_modchannel_signal, create_movement,
    create_nodedef_response, create_srp_bytes_s_b_response, create_time_of_day,
    serialize_empty_itemdef, serialize_empty_nodedef,
    srp as srp_helpers,
    AccessDeniedCode, AuthMechanism, ClientDynamicInfo, InteractAction, MediaAnnounceEntry,
    MediaBunchFile, ModChannelSignal, NetworkPacket, Session, SessionPhase, SrpVerifier,
    ToServerCommand, ToServerConnectionState,
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
    /// Returns a list of fully-formed `NetworkPacket` responses (one
    /// per `ToClientCommand` we want to send back). The dispatcher
    /// serializes each one to bytes and wraps it in an MTP
    /// `Original` or `Reliable` frame.
    pub fn handle_command(
        &mut self,
        session: &mut Session,
        packet: &NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<NetworkPacket>> {
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
            ToServerCommand::Init2 => self.handle_init2(session, &mut pkt, peer_addr),
            ToServerCommand::ModChannelJoin => self.handle_modchannel_join(session, &mut pkt),
            ToServerCommand::ModChannelLeave => self.handle_modchannel_leave(session, &mut pkt),
            ToServerCommand::ModChannelMsg => self.handle_modchannel_msg(session, &mut pkt),
            ToServerCommand::PlayerPos => self.handle_player_pos(session, &pkt),
            ToServerCommand::GotBlocks => self.handle_got_blocks(session, &mut pkt),
            ToServerCommand::DeletedBlocks => self.handle_deleted_blocks(session, &mut pkt),
            ToServerCommand::InventoryAction => self.handle_inventory_action(session, &mut pkt),
            ToServerCommand::ChatMessage => self.handle_chat_message(session, &mut pkt),
            ToServerCommand::Damage => self.handle_damage(session, &mut pkt),
            ToServerCommand::PlayerItem => self.handle_player_item(session, &mut pkt),
            ToServerCommand::RespawnLegacy => self.handle_respawn_legacy(session, &mut pkt),
            ToServerCommand::Interact => self.handle_interact(session, &mut pkt, peer_addr),
            ToServerCommand::RemovedSounds => self.handle_removed_sounds(session, &mut pkt),
            ToServerCommand::NodeMetaFields => self.handle_node_meta_fields(session, &mut pkt),
            ToServerCommand::InventoryFields => self.handle_inventory_fields(session, &mut pkt),
            ToServerCommand::RequestMedia => {
                self.handle_request_media(session, &mut pkt, peer_addr)
            }
            ToServerCommand::HaveMedia => self.handle_have_media(session, &mut pkt, peer_addr),
            ToServerCommand::ClientReady => self.handle_client_ready(session, &mut pkt),
            ToServerCommand::FirstSrp => self.handle_first_srp(session, &mut pkt, peer_addr),
            ToServerCommand::SrpBytesA => self.handle_srp_bytes_a(session, &mut pkt, peer_addr),
            ToServerCommand::SrpBytesM => self.handle_srp_bytes_m(session, &mut pkt, peer_addr),
            ToServerCommand::UpdateClientInfo => self.handle_update_client_info(session, &mut pkt),
        }
    }

    /// Check if command is allowed in current session state.
    fn check_command_state(&self, session: &Session, cmd: ToServerCommand) -> bool {
        // Special case: media-loading commands are only allowed once the
        // session has reached the `MediaLoading` or `Active` phase (i.e.
        // TOSERVER_INIT2 has been processed).
        if matches!(
            cmd,
            ToServerCommand::RequestMedia
                | ToServerCommand::HaveMedia
                | ToServerCommand::GotBlocks
                | ToServerCommand::DeletedBlocks
                | ToServerCommand::ClientReady
        ) {
            return std::mem::discriminant(&cmd.required_state())
                == std::mem::discriminant(&session.connection_state)
                && session.phase != SessionPhase::Init;
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
    ) -> Result<Vec<NetworkPacket>> {
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
        session.phase = SessionPhase::Init;
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
        // Wire format: optional std::string lang_code
        let lang = packet.read_utf8().ok();

        match lang.as_deref() {
            Some(l) if !l.is_empty() => info!(
                "Client {} ({}) sent INIT2 (lang={})",
                peer_addr,
                session.player_name.as_deref().unwrap_or("?"),
                l
            ),
            _ => info!(
                "Client {} ({}) sent INIT2 (no language code reported)",
                peer_addr,
                session.player_name.as_deref().unwrap_or("?"),
            ),
        }

        // Mark the session as in the media-loading phase but keep
        // connection_state == Startup so the state machine still
        // accepts the media-related commands.
        session.phase = SessionPhase::MediaLoading;

        // Clear any pending SRP state
        self.pending_srp.remove(&session.peer_id);

        // Build the init-data packet stream.
        // The ItemDef/NodeDef payloads cannot be empty: the C++ client
        // runs the bytes through zlib/zstd and then deserializes a
        // versioned manager, so an empty (or zero-length compressed)
        // stream trips `decompressZlib`/`decompressZstd` with EOF and
        // aborts the connection. We send a valid *empty* manager
        // (just version + zero counts) which the client decompresses
        // and deserializes successfully.
        let negotiated_proto = session
            .protocol_version
            .ok_or_else(|| anyhow!("INIT2 before protocol negotiation"))?;
        let itemdef_payload = serialize_empty_itemdef();
        let nodedef_payload = serialize_empty_nodedef();

        let mut responses = Vec::new();
        responses.push(create_itemdef_response(&itemdef_payload, negotiated_proto));
        responses.push(create_nodedef_response(&nodedef_payload, negotiated_proto));
        responses.push(create_announce_media(&MEDIA_FILES, ""));
        responses.push(create_time_of_day(DEFAULT_TIME_OF_DAY, DEFAULT_TIME_SPEED));
        responses.push(create_csm_restriction_flags(CSM_RF_NONE, DEFAULT_CSM_NODE_RANGE));
        responses.push(create_movement(
            DEFAULT_MOVEMENT.acceleration_default,
            DEFAULT_MOVEMENT.acceleration_air,
            DEFAULT_MOVEMENT.acceleration_fast,
            DEFAULT_MOVEMENT.speed_walk,
            DEFAULT_MOVEMENT.speed_crouch,
            DEFAULT_MOVEMENT.speed_fast,
            DEFAULT_MOVEMENT.speed_climb,
            DEFAULT_MOVEMENT.speed_jump,
            DEFAULT_MOVEMENT.liquid_fluidity,
            DEFAULT_MOVEMENT.liquid_fluidity_smooth,
            DEFAULT_MOVEMENT.liquid_sink,
            DEFAULT_MOVEMENT.gravity,
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
        debug!("Received PLAYERPOS from peer {}", session.peer_id);
        Ok(vec![])
    }

    /// Handle TOSERVER_CHAT_MESSAGE command
    fn handle_chat_message(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
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
    ) -> Result<Vec<NetworkPacket>> {
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
        session.phase = SessionPhase::Active;
        session.connection_state = ToServerConnectionState::Ingame;

        Ok(vec![])
    }

    /// Handle TOSERVER_DELETEDBLOCKS command.
    ///
    /// Wire format (mirrors `TOSERVER_GOTBLOCKS`):
    /// ```text
    /// [0] u8 count
    /// [1] v3s16 pos_0
    /// [7] v3s16 pos_1
    /// ...
    /// ```
    ///
    /// Each position is a mapblock the client is no longer interested
    /// in (e.g. out of view distance). The C++ server forwards these
    /// to `RemoteClient::SetBlockNotSent` so the next time the client
    /// comes into range the block is re-sent instead of being skipped
    /// by the existing "we already sent this block" cache.
    fn handle_deleted_blocks(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let count = packet.read_u8()?;
        let mut positions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (x, y, z) = packet.read_v3s16()?;
            positions.push((x, y, z));
        }
        debug!(
            "DELETEDBLOCKS from peer {} ({} blocks)",
            session.peer_id, count
        );
        // TODO: forward positions to the server's RemoteClient tracker
        // (Server::RemoteClient::SetBlockNotSent in C++) once we have a
        // per-peer block-pending map. For now we just drop them: the
        // block-sending layer in the C++ server also re-sends blocks
        // when their underlying mapblock changes, so a missed
        // "SetBlockNotSent" only causes stale-block artifacts that are
        // repaired on the next edit.
        let _ = positions;
        Ok(vec![])
    }

    /// Handle TOSERVER_INVENTORY_ACTION command.
    ///
    /// Wire format: the C++ `Client::sendInventoryAction` writes the
    /// `InventoryAction::serialize` output to the packet **without any
    /// length prefix** (`pkt.putRawString(s.c_str(), s.size())` in
    /// `src/client/client.cpp`). The server then deserializes it via
    /// `InventoryAction::deSerialize` from a string stream.
    ///
    /// The on-the-wire format is a text-based command string, e.g.:
    /// ```text
    /// "Move 1 player:nrz\n main 0 player:nrz\n craftresult 1\n"
    /// "MoveSomewhere 5 detached:creative\n src 0\n"
    /// "Drop 99 player:nrz\n main 0\n"
    /// "Craft 2 player:nrz\n craft\n"
    /// ```
    ///
    /// Each line is a single `InventoryAction` type and its arguments.
    /// We mirror the C++ `InventoryLocation::deSerialize` parsing
    /// exactly so a real Luanti client can drive the handler.
    fn handle_inventory_action(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        // The action payload is the remaining bytes of the packet.
        // C++ reads via `pkt->getString(0)` (which includes the 2
        // command bytes); we re-add the command so the text format
        // matches what the C++ istringstream parser expects.
        let mut blob = Vec::with_capacity(2 + packet.remaining());
        blob.extend_from_slice(&packet.command().to_be_bytes());
        blob.extend_from_slice(packet.rest());

        // Try to parse it as one of the well-known action types.
        let preview = String::from_utf8_lossy(&blob[2..]).into_owned();
        debug!(
            "INVENTORY_ACTION from peer {}: {:?}",
            session.peer_id, preview
        );

        // TODO: dispatch into the inventory manager once a Rust
        // implementation of `InventoryAction` is available. The full
        // action handling in C++ requires:
        //   * `InventoryManager` (player, node, detached inventories)
        //   * `PlayerSAO` (to set the wielded item after a move/drop)
        //   * `m_script` (to call `on_player_inventory_action` Lua hook)
        //   * `RollbackInterface` (to report the action for rollback)
        //   * `m_itemdef` (to look up tool capabilities, item metadata)
        // For now we just consume the packet and acknowledge the
        // client (no automatic inventory re-send is necessary: the
        // client's predicted state stays in sync with itself, and the
        // next `SendInventory` triggered by the Lua layer or any
        // inventory-modifying path will reconcile).
        Ok(vec![])
    }

    /// Handle TOSERVER_DAMAGE command.
    ///
    /// Wire format: `u16 damage`
    fn handle_damage(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let damage = packet.read_u16()?;
        debug!(
            "DAMAGE from peer {} ({} hp, player={:?})",
            session.peer_id, damage, session.player_name
        );
        // TODO: route to PlayerSAO::setHP. Requires the Lua ServerActiveObject
        // bridge (and `PlayerHPChangeReason::FALL` semantics). For now we
        // log and drop.
        Ok(vec![])
    }

    /// Handle TOSERVER_PLAYERITEM command.
    ///
    /// Wire format: `u16 item` (the new wield index in the hotbar).
    fn handle_player_item(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let item = packet.read_u16()?;
        debug!(
            "PLAYERITEM from peer {} (wield index {})",
            session.peer_id, item
        );
        // TODO: store on the RemotePlayer via Player::setWieldIndex after
        // bounds-checking against `getMaxHotbarItemcount()`. Requires the
        // RemotePlayer + PlayerSAO bridge.
        Ok(vec![])
    }

    /// Handle TOSERVER_RESPAWN_LEGACY command.
    ///
    /// Wire format: empty (legacy respawn signal, used by clients < 5.0.0
    /// that don't have the modern death-screen formspec).
    fn handle_respawn_legacy(
        &mut self,
        session: &mut Session,
        _packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        debug!("RESPAWN_LEGACY from peer {}", session.peer_id);
        // TODO: forward to the Lua on_respawnplayer callback via
        // Server::respawnPlayer. The C++ respawn resets HP, position,
        // breath, attached children and re-sends the player list.
        Ok(vec![])
    }

    /// Handle TOSERVER_INTERACT command.
    ///
    /// Wire format:
    /// ```text
    /// [0] u8    action         (InteractAction)
    /// [1] u16   item           (wield index)
    /// [3] u32   plen           (length of the following PointedThing)
    /// [7] PointedThing (serialized, plen bytes)
    /// [7+plen] player position information (writePlayerPos payload)
    /// ```
    ///
    /// The C++ handler (`Server::handleCommand_Interact`) decodes the
    /// player-position block via `process_PlayerPos`, exactly the same
    /// shape as `TOSERVER_PLAYERPOS`. We decode both for symmetry, but
    /// since we have no `PlayerSAO` yet we just log and drop the
    /// gameplay-relevant fields.
    fn handle_interact(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
        peer_addr: SocketAddr,
    ) -> Result<Vec<NetworkPacket>> {
        let action_byte = packet.read_u8()?;
        let action = match InteractAction::from_u8(action_byte) {
            Some(a) => a,
            None => {
                warn!(
                    "INTERACT: unknown action 0x{:02x} from {}",
                    action_byte, peer_addr
                );
                return Ok(vec![]);
            }
        };
        let item = packet.read_u16()?;
        let plen = packet.read_u32()? as usize;
        if packet.remaining() < plen {
            return Err(anyhow!(
                "INTERACT: PointedThing length {} exceeds remaining packet ({} bytes)",
                plen,
                packet.remaining()
            ));
        }
        let pointed_bytes = &packet.as_slice()[packet.read_pos()..packet.read_pos() + plen];
        // Decode the PointedThing using the same wire format as C++:
        //   u8 version (must be 0)
        //   u8 type
        //   then either nothing (NOTHING) / 2 * v3s16 (NODE) / u16 (OBJECT)
        let pointed_summary = parse_pointed_thing(pointed_bytes)
            .unwrap_or_else(|| "<malformed PointedThing>".to_string());
        packet.skip(plen)?;

        // The remaining bytes are the writePlayerPos payload: 12 + 12 +
        // 4 + 4 + 4 + 1 + 1 + (optional 8). We consume them so the
        // cursor stays consistent and so any future handling code can
        // read the player's reported position. We do not need to act on
        // it; the next TOSERVER_PLAYERPOS packet will carry the
        // authoritative position.
        let _ = decode_player_pos_payload(packet);

        debug!(
            "INTERACT from peer {}: action={:?}, item={}, pointed={}",
            session.peer_id, action, item, pointed_summary
        );

        // TODO: route to PlayerSAO::interact / Lua callbacks. The C++
        // implementation in `Server::handleCommand_Interact` does:
        //   * check `interact` privilege and distance to target
        //   * call `node_on_punch` / `node_on_dig` Lua hooks for nodes
        //   * call `item_OnSecondaryUse` / `item_OnPlace` / `item_OnUse`
        //     Lua hooks for items
        //   * call `ServerActiveObject::rightClick` / `punch` for objects
        //   * re-send the affected block on the wire (via
        //     `RemoteClient::SetBlockNotSent` or `ResendBlockIfOnWire`)
        Ok(vec![])
    }

    /// Handle TOSERVER_REMOVED_SOUNDS command.
    ///
    /// Wire format: `u16 num | num * s32 id`
    fn handle_removed_sounds(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let num = packet.read_u16()? as usize;
        let mut ids = Vec::with_capacity(num);
        for _ in 0..num {
            ids.push(packet.read_i32()?);
        }
        debug!(
            "REMOVED_SOUNDS from peer {} ({} id(s): {:?})",
            session.peer_id, num, ids
        );
        // TODO: remove the peer from `m_playing_sounds[id].clients` and
        // drop sounds whose client set is empty (C++: `Server::handleCommand_RemovedSounds`).
        Ok(vec![])
    }

    /// Handle TOSERVER_NODEMETA_FIELDS command.
    ///
    /// Wire format:
    /// ```text
    /// [0]  v3s16 pos
    /// [6]  std::string formname
    /// [6+slen] u16 field_count
    /// then for each field: std::string name | long_string value
    /// ```
    ///
    /// Long string is `u32 length + bytes`.
    fn handle_node_meta_fields(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let (x, y, z) = packet.read_v3s16()?;
        let form_name = packet.read_utf8().unwrap_or_default();
        let field_count = packet.read_u16()? as usize;
        let mut total_size = 0usize;
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let name = packet.read_utf8().unwrap_or_default();
            let value = packet.read_long_string().unwrap_or_default();
            total_size += name.len() + value.len();
            fields.push((name, value));
        }
        if total_size >= 640 * 1024 {
            warn!(
                "Too large formspec fields for nodemeta at ({},{},{}): {} bytes, ignoring",
                x, y, z, total_size
            );
            return Ok(vec![]);
        }
        debug!(
            "NODEMETA_FIELDS from peer {}: pos=({},{},{}), form={:?}, {} field(s)",
            session.peer_id,
            x,
            y,
            z,
            form_name,
            field_count
        );
        // TODO: forward to the Lua `node_on_receive_fields(p, form_name,
        // fields, playersao)` callback. Requires the script engine
        // (ServerScripting) and the player/node lookup.
        let _ = fields;
        Ok(vec![])
    }

    /// Handle TOSERVER_INVENTORY_FIELDS command.
    ///
    /// Wire format:
    /// ```text
    /// [0]    std::string formname
    /// [slen] u16 field_count
    /// then for each field: std::string name | long_string value
    /// ```
    fn handle_inventory_fields(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let form_name = packet.read_utf8().unwrap_or_default();
        let field_count = packet.read_u16()? as usize;
        let mut total_size = 0usize;
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let name = packet.read_utf8().unwrap_or_default();
            let value = packet.read_long_string().unwrap_or_default();
            total_size += name.len() + value.len();
            fields.push((name, value));
        }
        if total_size >= 640 * 1024 {
            warn!(
                "Too large formspec fields for inventory form={:?}: {} bytes, ignoring",
                form_name, total_size
            );
            return Ok(vec![]);
        }
        debug!(
            "INVENTORY_FIELDS from peer {}: form={:?}, {} field(s)",
            session.peer_id, form_name, field_count
        );
        // TODO: forward to `Server::handleCommand_InventoryFields`:
        //   * pass through to `on_playerReceiveFields` if `formname` is
        //     empty (an inventory-submit from the client)
        //   * otherwise verify the formname against `m_formspec_state_data`
        //     and reject if it does not match (anti-cheat)
        let _ = fields;
        Ok(vec![])
    }

    /// Handle TOSERVER_MODCHANNEL_JOIN command.
    ///
    /// Wire format: `std::string channel_name`
    fn handle_modchannel_join(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let channel = packet.read_utf8().unwrap_or_default();
        debug!(
            "MODCHANNEL_JOIN from peer {}: {:?}",
            session.peer_id, channel
        );
        // TODO: call into a `ModChannelMgr` (mirroring C++ ModChannelMgr::joinChannel).
        // The manager tracks per-channel state and the set of joined peers; the
        // C++ server returns JOIN_OK or JOIN_FAILURE depending on whether the
        // channel is already registered, the peer is already in it, and whether
        // `enable_mod_channels` is on. Since we don't have a Lua mod-channel
        // registry yet, we return JOIN_FAILURE so the client knows the channel
        // is unavailable — this matches the C++ behaviour when mod channels
        // are disabled at runtime.
        Ok(vec![create_modchannel_signal(
            ModChannelSignal::JoinFailure,
            &channel,
        )])
    }

    /// Handle TOSERVER_MODCHANNEL_LEAVE command.
    ///
    /// Wire format: `std::string channel_name`
    fn handle_modchannel_leave(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let channel = packet.read_utf8().unwrap_or_default();
        debug!(
            "MODCHANNEL_LEAVE from peer {}: {:?}",
            session.peer_id, channel
        );
        // TODO: ModChannelMgr::leaveChannel. Without a manager we report
        // LEAVE_OK so the client stops resending.
        Ok(vec![create_modchannel_signal(
            ModChannelSignal::LeaveOk,
            &channel,
        )])
    }

    /// Handle TOSERVER_MODCHANNEL_MSG command.
    ///
    /// Wire format: `std::string channel_name | std::string channel_msg`
    fn handle_modchannel_msg(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let channel = packet.read_utf8().unwrap_or_default();
        let msg = packet.read_utf8().unwrap_or_default();
        debug!(
            "MODCHANNEL_MSG from peer {} on {:?}: {:?}",
            session.peer_id, channel, msg
        );
        // TODO: broadcast via ModChannelMgr::broadcastToChannel after
        // rate-limiting / filtering. Without a manager we drop the
        // message and return nothing.
        let _ = channel;
        let _ = msg;
        Ok(vec![])
    }

    /// Handle TOSERVER_UPDATE_CLIENT_INFO command.
    ///
    /// Wire format:
    /// ```text
    /// [0] s32 render_target_size.X
    /// [4] s32 render_target_size.Y
    /// [8] f32 real_gui_scaling
    /// [12] f32 real_hud_scaling
    /// [16] s32 max_fs_size.X
    /// [20] s32 max_fs_size.Y
    /// [24] bool touch_controls (added in 5.9.0, may be absent on older clients)
    /// ```
    fn handle_update_client_info(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let mut info = ClientDynamicInfo::default();
        if packet.remaining() < 4 + 4 + 4 + 4 + 4 + 4 {
            // C++ uses try/catch around individual reads; we use
            // `read_u32` which returns Err, so a short packet is
            // silently ignored — same as the C++ behaviour with older
            // clients.
            debug!(
                "UPDATE_CLIENT_INFO from peer {}: too short ({} bytes), ignoring",
                session.peer_id,
                packet.remaining()
            );
            return Ok(vec![]);
        }
        info.render_target_size.0 = packet.read_i32()?;
        info.render_target_size.1 = packet.read_i32()?;
        info.real_gui_scaling = packet.read_f32()?;
        info.real_hud_scaling = packet.read_f32()?;
        info.max_fs_size.0 = packet.read_i32()?;
        info.max_fs_size.1 = packet.read_i32()?;
        // touch_controls was added in 5.9.0; older clients don't send it.
        info.touch_controls = packet.read_u8().map(|b| b != 0).unwrap_or(false);
        debug!(
            "UPDATE_CLIENT_INFO from peer {}: render={}x{}, gui_scale={}, hud_scale={}, max_fs={}x{}, touch={}",
            session.peer_id,
            info.render_target_size.0,
            info.render_target_size.1,
            info.real_gui_scaling,
            info.real_hud_scaling,
            info.max_fs_size.0,
            info.max_fs_size.1,
            info.touch_controls,
        );
        // TODO: store on the per-peer RemoteClient (`Client::setDynamicInfo`
        // in C++) so that the HUD renderer can re-scale on the fly. The
        // server itself only stores it for the Lua `minetest.get_player_information`
        // API; no outbound packets are sent in response.
        let _ = info;
        Ok(vec![])
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Determine authentication mechanism for a player.
    ///
    /// Mirrors `Server::handleCommand_Init` in `src/network/serverpackethandler.cpp`:
    /// the stored password is split on `#`; a 4-component string with `"1"` as
    /// the second component is the SRP-encoded `#1#<salt>#<verifier>` format,
    /// otherwise if it is valid base64 it is treated as a legacy password.
    fn determine_auth_mechanism(
        &mut self,
        player_name: &str,
    ) -> Result<(u32, Option<String>)> {
        match self.auth_db.get_auth(player_name) {
            Ok(auth_entry) => {
                let enc_pwd = auth_entry.password.clone();
                let components: Vec<&str> = enc_pwd.split('#').collect();
                if components.len() == 4 && components[1] == "1" {
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
const CSM_RF_NONE: u64 = 0x0000_0000;

/// Default `csm_restriction_noderange` (matches the C++ default
/// in `Server::startup` -> `m_csm_restriction_noderange = 8`).
const DEFAULT_CSM_NODE_RANGE: u32 = 8;

/// Default movement parameters. Matches the C++ defaults so the client
/// gets a sane experience. Field order matches the wire format
/// expected by `Client::handleCommand_Movement` (12 floats).
struct MovementDefaults {
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
}

const DEFAULT_MOVEMENT: MovementDefaults = MovementDefaults {
    acceleration_default: 1.0,
    acceleration_air: 1.0,
    acceleration_fast: 1.0,
    speed_walk: 1.0,
    speed_crouch: 1.0,
    speed_fast: 1.0,
    speed_climb: 1.0,
    speed_jump: 1.0,
    liquid_fluidity: 1.0,
    liquid_fluidity_smooth: 1.0,
    liquid_sink: 1.0,
    gravity: 1.0,
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

// --- Wire-format decoders for non-NetworkPacket payloads --------------------

/// Decode a `PointedThing` (the inner blob of `TOSERVER_INTERACT`).
///
/// Wire format (matches `PointedThing::deSerialize` in
/// `src/util/pointedthing.cpp`):
///
/// ```text
/// u8 version (must be 0)
/// u8 type
///   POINTEDTHING_NOTHING:   no body
///   POINTEDTHING_NODE:      v3s16 node_undersurface | v3s16 node_abovesurface
///   POINTEDTHING_OBJECT:    u16 object_id
/// ```
fn parse_pointed_thing(buf: &[u8]) -> Option<String> {
    if buf.len() < 2 {
        return None;
    }
    let version = buf[0];
    if version != 0 {
        return None;
    }
    let type_byte = buf[1];
    let body = &buf[2..];
    match type_byte {
        0 => Some("[nothing]".to_string()),
        1 => {
            // POINTEDTHING_NODE: 2 * v3s16
            if body.len() < 12 {
                return None;
            }
            let ux = i16::from_be_bytes([body[0], body[1]]);
            let uy = i16::from_be_bytes([body[2], body[3]]);
            let uz = i16::from_be_bytes([body[4], body[5]]);
            let ax = i16::from_be_bytes([body[6], body[7]]);
            let ay = i16::from_be_bytes([body[8], body[9]]);
            let az = i16::from_be_bytes([body[10], body[11]]);
            Some(format!(
                "[node under=({},{},{}) above=({},{},{})]",
                ux, uy, uz, ax, ay, az
            ))
        }
        2 => {
            // POINTEDTHING_OBJECT: u16
            if body.len() < 2 {
                return None;
            }
            let id = u16::from_be_bytes([body[0], body[1]]);
            Some(format!("[object {}]", id))
        }
        _ => None,
    }
}

/// Decode (and discard) the trailing `writePlayerPos` payload of
/// `TOSERVER_INTERACT` (and the standalone `TOSERVER_PLAYERPOS`).
///
/// Wire format (matches `Client::writePlayerPos` in
/// `src/client/client.cpp` + the C++ `process_PlayerPos` reader):
///
/// ```text
/// v3s32 position
/// v3s32 speed
/// s32   pitch (× 100, i.e. f1000)
/// s32   yaw   (× 100)
/// u32   keyPressed
/// u8    fov (× 80)
/// u8    wanted_range
/// u8    camera_inverted (since 5.4.0)
/// f32   movement_speed  (optional, since 5.4.0)
/// f32   movement_direction (optional, since 5.4.0)
/// ```
///
/// The total size is therefore 12 + 12 + 4 + 4 + 4 + 1 + 1 = 38 bytes
/// for the always-present block, plus 8 optional bytes.
fn decode_player_pos_payload(packet: &mut NetworkPacket) -> Result<()> {
    if packet.remaining() < 12 + 12 + 4 + 4 + 4 + 1 + 1 {
        // Truncated: silently stop, matching the C++ behaviour in
        // process_PlayerPos which just returns.
        return Ok(());
    }
    packet.skip(12 + 12 + 4 + 4 + 4 + 1 + 1)?;
    // Optional f32 movement_speed + f32 movement_direction.
    let _ = packet.skip(8);
    Ok(())
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
        assert_eq!(responses[0].command(), 0x0A);
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
        assert_eq!(responses[0].command(), 0x0A);
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
        assert_eq!(responses[0].command(), 0x0A);
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
        assert_eq!(r[0].command(), 0x0002); // TOCLIENT_HELLO
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
        assert_eq!(r[0].command(), 0x0003); // TOCLIENT_AUTH_ACCEPT

        // 3. INIT2
        let p = NetworkPacket::new(0x0011, 0);
        let r = h
            .handle_command(&mut session, &p, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        // Should send ItemDef + NodeDef + AnnounceMedia + TimeOfDay +
        // CsmRestrictionFlags + Movement = 6 packets.
        assert!(r.len() >= 6);
        assert_eq!(session.phase, SessionPhase::MediaLoading);

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
        assert_eq!(session.phase, SessionPhase::Active);
        assert_eq!(
            session.connection_state,
            ToServerConnectionState::Ingame
        );
    }
}
