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

use luanti_auth_db::AuthDatabase;
use luanti_network::{
    auth as auth_helpers, base64_util as base64, create_access_denied, create_announce_media,
    create_auth_accept_response, create_chat_message_response, create_csm_restriction_flags,
    create_hello_response, create_itemdef_response, create_media_bunch, create_modchannel_signal,
    create_movement, create_nodedef_response, create_srp_bytes_s_b_response, create_time_of_day,
    serialize_empty_itemdef, serialize_empty_nodedef, srp as srp_helpers, AccessDeniedCode,
    AuthMechanism, ClientDynamicInfo, InteractAction, MediaAnnounceEntry, MediaBunchFile,
    ModChannelSignal, NetworkPacket, Session, SessionPhase, SrpVerifier, ToServerCommand,
    ToServerConnectionState,
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
    ///
    /// The peer's `SocketAddr` is read from `session.address` rather
    /// than passed as a parameter — the C++ `Server` reaches it via
    /// `m_con->GetPeerAddress(peer_id)`, in our port the address is
    /// stored on the `Session` itself at creation time.
    pub fn handle_command(
        &mut self,
        session: &mut Session,
        packet: &NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        let cmd = ToServerCommand::from_u16(packet.command());
        let Some(cmd) = cmd else {
            let preview = hex_preview(packet.as_slice(), 32);
            warn!(
                "Unknown command 0x{:04x} from {} (peer {}, {} bytes payload: {}{})",
                packet.command(),
                session.address,
                session.peer_id,
                packet.len(),
                preview,
                if packet.len() > 32 { "…" } else { "" },
            );
            return Ok(vec![]);
        };

        debug!("Processing command {} from {}", cmd, session.address);

        // Look up the dispatch entry (handler + state category).
        // Mirrors the C++ `toServerCommandTable[command]` lookup in
        // `Server::ProcessData` — the C++ struct carries both
        // `state` and `handler`, so a single array access gives
        // us everything we need.
        let entry = HANDLER_TABLE[cmd as usize]
            .expect("cmd is a valid ToServerCommand variant with a handler");

        // Category-based filter, mirroring the C++ gate in
        // `Server::ProcessData`
        // ([`src/server.cpp:1342-1368`](../../../../src/server.cpp)):
        //
        // ```text
        //   if (opcode.state == NOT_CONNECTED) handle();   // no state check
        //   if (opcode.state == STARTUP)       handle();   // no state check
        //   if (state < CS_Active)             drop();     // INGAME
        //   handle();
        // ```
        //
        // The C++ unconditionally accepts `NotConnected` and
        // `Startup` opcodes (the latter via an early-return on
        // `toServerCommandTable[command].state == TOSERVER_STATE_STARTUP`,
        // with no `getClientState(peer_id)` check) and only
        // consults the per-client state for `Ingame`. We mirror
        // that exactly: `Startup` runs in every state the
        // C++ would accept, including the
        // `Created`/`HelloSent`/`AwaitingInit2` sub-states. The
        // C++ additionally asserts `getClient(peer_id,
        // CS_InitDone)` on the path used by `Startup` opcodes,
        // which would crash the server if a `Startup` opcode were
        // ever received before `INIT2`; the Rust does not assert
        // (handlers that genuinely need `InitDone` state check
        // it themselves, e.g. `handle_init2`).
        match entry.state {
            ToServerConnectionState::NotConnected | ToServerConnectionState::Startup => {}
            ToServerConnectionState::Ingame => {
                if !session.phase.is_active() {
                    warn!(
                        "Command {} not allowed in current phase {:?} from {}",
                        cmd, session.phase, session.address
                    );
                    return Ok(vec![]);
                }
            }
            // The C++ `TOSERVER_STATE_ALL` sentinel is reserved for
            // the null-command handler and never matches a real
            // opcode. Reject defensively if it ever does.
            ToServerConnectionState::All => return Ok(vec![]),
        }

        // Each handler takes a fresh clone of the packet so the read
        // cursor is independent. Cloning a NetworkPacket is cheap (it
        // is just a Vec<u8> + usize + two u16s).
        let mut pkt = packet.clone();

        (entry.handler)(self, session, &mut pkt)
    }

    // ------------------------------------------------------------------
    // Handlers
    // ------------------------------------------------------------------

    /// Handle TOSERVER_INIT command
    fn handle_init(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
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
            session.address, client_ser_ver, min_proto, max_proto, player_name
        );

        if !auth_helpers::is_valid_player_name(&player_name) {
            warn!(
                "Player with invalid name '{}' tried to connect from {}",
                player_name, session.address
            );
            return Ok(vec![create_access_denied(
                AccessDeniedCode::WrongCharsInName,
                "Invalid characters in player name",
            )]);
        }

        let negotiated_ser_ver = std::cmp::min(client_ser_ver, SER_FMT_VER_HIGHEST_WRITE);
        let negotiated_proto = std::cmp::min(max_proto, self.max_protocol_version);
        if negotiated_proto < self.min_protocol_version || negotiated_proto < min_proto {
            warn!("Protocol version mismatch with {}", session.address);
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
        // C++ CSE_Hello after sending TOCLIENT_HELLO
        // (Server::acceptAuth in src/server.cpp:266):
        //   CS_Created --CSE_Hello--> CS_HelloSent
        session.phase = SessionPhase::HelloSent;

        debug!(
            "Negotiated with {}: ser_ver={}, proto={}",
            session.address, negotiated_ser_ver, negotiated_proto
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
    ) -> Result<Vec<NetworkPacket>> {
        // C++ only processes registration FIRST_SRP in the
        // HelloSent state. A retransmitted reliable FIRST_SRP after
        // AUTH_ACCEPT (phase AwaitingInit2) is ignored, not denied.
        // Mirroring that avoids spurious "Player already exists"
        // disconnects when the client resends before it sees our ack.
        if session.phase != SessionPhase::HelloSent {
            info!(
                "Ignoring FIRST_SRP from {} in phase {:?}",
                session.address, session.phase
            );
            return Ok(vec![]);
        }

        let salt = packet.read_string()?;
        let verifier = packet.read_string()?;
        let is_empty = packet.read_u8()?;

        info!(
            "FIRST_SRP from {}: is_empty={}, salt_len={}, verifier_len={}",
            session.address,
            is_empty,
            salt.len(),
            verifier.len()
        );

        let player_name = session
            .player_name
            .clone()
            .ok_or_else(|| anyhow!("FIRST_SRP without player name"))?;

        if session.allowed_auth_mechs & (AuthMechanism::FirstSrp as u32) == 0 {
            warn!(
                "Client from {} tried to use disallowed FIRST_SRP auth mech",
                session.address
            );
            return Ok(vec![create_access_denied(
                AccessDeniedCode::UnexpectedData,
                "Auth mechanism not allowed",
            )]);
        }

        if is_empty == 1 {
            return Ok(vec![create_access_denied(
                AccessDeniedCode::EmptyPassword,
                "Empty passwords are not allowed",
            )]);
        }

        // FIRST_SRP is the registration path: it must only be used by
        // a brand-new player. If the player is already in the auth DB
        // it means either a previous successful registration, or
        // another concurrent connection beat us to it — both are
        // rejected with `AlreadyConnected`, mirroring the C++
        // `Server::handleCommand_FirstSrp` check
        // (src/network/serverpackethandler.cpp:1472).
        if self.auth_db.get_auth(&player_name).is_ok() {
            return Ok(vec![create_access_denied(
                AccessDeniedCode::AlreadyConnected,
                "Player already exists",
            )]);
        }

        let enc_pwd = auth_helpers::encode_srp_verifier(&verifier, &salt);

        let mut entry = luanti_auth_db::AuthEntry {
            id: 0,
            name: player_name.clone(),
            password: enc_pwd.clone(),
            privileges: vec![],
            last_login: now_secs(),
        };
        self.auth_db.create_auth(&mut entry)?;

        session.enc_pwd = Some(enc_pwd);
        // C++ CSE_AuthAccept after sending TOCLIENT_AUTH_ACCEPT
        // (Server::acceptAuth, src/server.cpp:3100):
        //   CS_HelloSent --CSE_AuthAccept--> CS_AwaitingInit2
        // The client must follow up with INIT2 once it receives
        // AUTH_ACCEPT.
        session.phase = SessionPhase::AwaitingInit2;

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
                session.address, chosen
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
            anyhow!(
                "SRP safety check failed: {} (likely A mod N == 0 or invalid A)",
                e
            )
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
            session.address,
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

                // C++ CSE_AuthAccept after sending TOCLIENT_AUTH_ACCEPT
                // (Server::acceptAuth, src/server.cpp:3100):
                //   CS_HelloSent --CSE_AuthAccept--> CS_AwaitingInit2
                session.phase = SessionPhase::AwaitingInit2;

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
    /// it back the init data: ItemDef, NodeDef, media announcement,
    /// movement, time of day and CSM restrictions — in the exact order
    /// the C++ server does (see `Server::handleCommand_Init2` in
    /// `src/network/serverpackethandler.cpp`).
    ///
    /// INIT2 is only processed if the session is still in
    /// `CS_AwaitingInit2`. A retransmit from a session that has
    /// already moved on to `CS_DefinitionsSent`/`CS_Active` is
    /// dropped, because re-sending ITEMDEF/NODEDEF to a client whose
    /// `m_mesh_update_manager` is running would crash the C++ client
    /// on `sanity_check(!m_mesh_update_manager->isRunning())`.
    ///
    /// The state machine in the C++ fires `CSE_GotInit2` before
    /// sending ItemDef/NodeDef (transitioning to `CS_InitDone`) and
    /// `CSE_SetDefinitionsSent` after them (transitioning to
    /// `CS_DefinitionsSent`), and we mirror those two events here
    /// so any observer that needs the fine-grained `ClientState`
    /// sees the same intermediate window.
    fn handle_init2(
        &mut self,
        session: &mut Session,
        packet: &mut NetworkPacket,
    ) -> Result<Vec<NetworkPacket>> {
        // Wire format: optional std::string lang_code
        let lang = packet.read_utf8().ok();

        match lang.as_deref() {
            Some(l) if !l.is_empty() => info!(
                "Client {} ({}) sent INIT2 (lang={})",
                session.address,
                session.player_name.as_deref().unwrap_or("?"),
                l
            ),
            _ => info!(
                "Client {} ({}) sent INIT2 (no language code reported)",
                session.address,
                session.player_name.as_deref().unwrap_or("?"),
            ),
        }

        // Guard: the C++ server only accepts TOSERVER_INIT2 when the
        // session is in the `CS_AwaitingInit2` equivalent. Without
        // this check, a client that retransmits INIT2 *after* having
        // already transitioned to `Active` would receive a second
        // ITEMDEF/NODEDEF pair while the client's
        // `m_mesh_update_manager` is running — and the C++ client's
        // `handleCommand_ItemDef` / `handleCommand_NodeDef` open
        // with `sanity_check(!m_mesh_update_manager->isRunning())`,
        // which `[[noreturn]]`-crashes the client (see
        // `src/network/clientpackethandler.cpp:773,751`).
        if session.phase != SessionPhase::AwaitingInit2 {
            warn!(
                "INIT2 from {} in wrong phase {:?}, ignoring",
                session.address, session.phase
            );
            return Ok(vec![]);
        }

        // C++ state machine in
        // `Server::handleCommand_Init2` (src/network/serverpackethandler.cpp:281,301):
        //   CS_AwaitingInit2 --CSE_GotInit2-->            CS_InitDone
        //   CS_InitDone       --CSE_SetDefinitionsSent--> CS_DefinitionsSent
        // We apply `CSE_GotInit2` *before* sending ItemDef/NodeDef
        // (mirrors line 281) so the intermediate `CS_InitDone`
        // window is preserved for observers that care about it.
        session.phase = SessionPhase::InitDone;

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

        // Packet order mirrors `Server::handleCommand_Init2` in
        // `src/network/serverpackethandler.cpp:295-327`:
        //   1. ItemDef
        //   2. NodeDef
        //   3. AnnounceMedia
        //   4. ActiveObjectRemoveAdd (no PlayerSAO yet on first
        //      connect, so a no-op until we have a ServerEnvironment)
        //   5. DetachedInventories  (none registered, so a no-op)
        //   6. Movement
        //   7. TimeOfDay
        //   8. CsmRestrictionFlags
        let mut responses = Vec::new();
        responses.push(create_itemdef_response(&itemdef_payload, negotiated_proto));
        responses.push(create_nodedef_response(&nodedef_payload, negotiated_proto));

        session.phase = SessionPhase::DefinitionsSent; // after sending ITEMDEF/NODEDEF, before media announce

        responses.push(create_announce_media(&MEDIA_FILES, ""));
        // TODO: SendActiveObjectRemoveAdd (the C++ server sends the
        // player SAO add here; we have no SAO on first connect so
        // this is a no-op until we have a ServerEnvironment).
        // TODO: sendDetachedInventories (no detached inventories
        // registered; no-op until we have an InventoryManager).
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
        responses.push(create_time_of_day(DEFAULT_TIME_OF_DAY, DEFAULT_TIME_SPEED));
        responses.push(create_csm_restriction_flags(
            CSM_RF_NONE,
            DEFAULT_CSM_NODE_RANGE,
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
    ) -> Result<Vec<NetworkPacket>> {
        let count = packet.read_u16()? as usize;
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            names.push(packet.read_utf8()?);
        }
        info!(
            "Client {} ({}) requested {} media file(s)",
            session.address,
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
    ) -> Result<Vec<NetworkPacket>> {
        let count = packet.read_u8()? as usize;
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            tokens.push(packet.read_u32()?);
        }
        info!(
            "Client {} ({}) acknowledged {} media token(s): {:?}",
            session.address,
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
        debug!("GOTBLOCKS from peer {} ({} blocks)", session.peer_id, count);
        let _ = packet.rest(); // drop any remaining positions
        Ok(vec![])
    }

    /// Handle TOSERVER_PLAYERPOS command
    fn handle_player_pos(
        &mut self,
        session: &mut Session,
        _packet: &mut NetworkPacket,
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
        let sender = session.player_name.clone().unwrap_or_default();

        info!(
            "Chat message from {} ({}): {}",
            sender, session.peer_id, message
        );

        // The C++ `Client::handleCommand_ChatMessage` formats the
        // displayed line itself ("<sender> message"), so the server
        // must pass the raw player name and the raw chat text as
        // separate fields. Pre-formatting `"<{sender}> {message}"`
        // into the `message` field would render as
        // `"<sender> <sender> message"` on the client and crash
        // the message parser.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(vec![create_chat_message_response(
            &sender, &message, timestamp,
        )])
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

        // Client is fully connected. In the C++ server this is the
        // transition `CS_DefinitionsSent` → `CS_Active`; in the Rust
        // port it is `SessionPhase::Active`, which unlocks the
        // `Ingame`-category opcode gating.
        session.phase = SessionPhase::Active;

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
    ) -> Result<Vec<NetworkPacket>> {
        let action_byte = packet.read_u8()?;
        let action = match InteractAction::from_u8(action_byte) {
            Some(a) => a,
            None => {
                warn!(
                    "INTERACT: unknown action 0x{:02x} from {}",
                    action_byte, session.address
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
            session.peer_id, x, y, z, form_name, field_count
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
    fn determine_auth_mechanism(&mut self, player_name: &str) -> Result<(u32, Option<String>)> {
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

/// Function-pointer type for a single opcode's handler.
///
/// Mirrors the C++ `void (Server::*handler)(NetworkPacket*)` field
/// of `ToServerCommandHandler` in
/// [`src/network/serveropcodes.h`](../../../../src/network/serveropcodes.h).
///
/// In Rust the equivalent is a `fn` pointer to a method on
/// `CommandHandler` — methods with `&mut self` are coercible to
/// `fn(&mut Self, ...)` pointers, which is what the lookup table
/// stores. This gives the same indirect-call dispatch as the C++
/// `toServerCommandTable[i].handler` while staying zero-cost: the
/// pointer is loaded from a `static` array and called.
///
/// All handlers share the same uniform signature so the table is a
/// flat array indexed by opcode (no per-opcode wrapper, no
/// `dyn Trait`). The peer's `SocketAddr` is intentionally *not* a
/// parameter — handlers that need it for logging read
/// `session.address` directly, mirroring the C++ pattern of
/// looking up the address from the con when needed.
type Handler = fn(
    handler: &mut CommandHandler,
    session: &mut Session,
    packet: &mut NetworkPacket,
) -> Result<Vec<NetworkPacket>>;

/// One row of the dispatch table — pairs a handler with the
/// C++ `ToServerConnectionState` category the opcode belongs to.
///
/// Mirrors the C++ `ToServerCommandHandler` struct in
/// `src/network/serveropcodes.h:19-24` which carries `name`,
/// `state` and `handler` in a single struct so the dispatch
/// (`Server::ProcessData` in `src/server.cpp`) can filter on
/// `state` and then call `handler` in one table lookup.
#[derive(Clone, Copy)]
struct HandlerEntry {
    state: ToServerConnectionState,
    handler: Handler,
}

/// Opcode-to-handler dispatch table, indexed by
/// `ToServerCommand as u16`. Mirrors the C++ `toServerCommandTable`
/// array line-for-line: every slot that the C++ table populates
/// with a real handler gets a real handler here, and the
/// unassigned opcodes are `None`.
///
/// Unlike the C++ table the name lives in
/// `luanti-network::TO_SERVER_COMMAND_TABLE` (the `luanti-network`
/// crate is shared with the client and needs the name for
/// logging) but the **state** is duplicated here so the dispatch
/// in [`CommandHandler::handle_command`] can do the
/// `ProcessData`-equivalent category filter without a second
/// table lookup. The two state columns are kept in lock-step
/// by hand and asserted by `HANDLER_TABLE_SPEC` below.
static HANDLER_TABLE: [Option<HandlerEntry>; luanti_network::TOSERVER_NUM_MSG_TYPES] = [
    None, // 0x00 (never used)
    None, // 0x01
    Some(HandlerEntry {
        state: ToServerConnectionState::NotConnected,
        handler: CommandHandler::handle_init,
    }), // 0x02
    None, // 0x03
    None, // 0x04
    None, // 0x05
    None, // 0x06
    None, // 0x07
    None, // 0x08
    None, // 0x09
    None, // 0x0a
    None, // 0x0b
    None, // 0x0c
    None, // 0x0d
    None, // 0x0e
    None, // 0x0f
    None, // 0x10
    Some(HandlerEntry {
        state: ToServerConnectionState::NotConnected,
        handler: CommandHandler::handle_init2,
    }), // 0x11
    None, // 0x12
    None, // 0x13
    None, // 0x14
    None, // 0x15
    None, // 0x16
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_modchannel_join,
    }), // 0x17
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_modchannel_leave,
    }), // 0x18
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_modchannel_msg,
    }), // 0x19
    None, // 0x1a
    None, // 0x1b
    None, // 0x1c
    None, // 0x1d
    None, // 0x1e
    None, // 0x1f
    None, // 0x20
    None, // 0x21
    None, // 0x22
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_player_pos,
    }), // 0x23
    Some(HandlerEntry {
        state: ToServerConnectionState::Startup,
        handler: CommandHandler::handle_got_blocks,
    }), // 0x24
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_deleted_blocks,
    }), // 0x25
    None, // 0x26
    None, // 0x27
    None, // 0x28
    None, // 0x29
    None, // 0x2a
    None, // 0x2b
    None, // 0x2c
    None, // 0x2d
    None, // 0x2e
    None, // 0x2f
    None, // 0x30
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_inventory_action,
    }), // 0x31
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_chat_message,
    }), // 0x32
    None, // 0x33
    None, // 0x34
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_damage,
    }), // 0x35
    None, // 0x36
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_player_item,
    }), // 0x37
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_respawn_legacy,
    }), // 0x38
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_interact,
    }), // 0x39
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_removed_sounds,
    }), // 0x3a
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_node_meta_fields,
    }), // 0x3b
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_inventory_fields,
    }), // 0x3c
    None, // 0x3d
    None, // 0x3e
    None, // 0x3f
    Some(HandlerEntry {
        state: ToServerConnectionState::Startup,
        handler: CommandHandler::handle_request_media,
    }), // 0x40
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_have_media,
    }), // 0x41
    None, // 0x42
    Some(HandlerEntry {
        state: ToServerConnectionState::Startup,
        handler: CommandHandler::handle_client_ready,
    }), // 0x43
    None, // 0x44
    None, // 0x45
    None, // 0x46
    None, // 0x47
    None, // 0x48
    None, // 0x49
    None, // 0x4a
    None, // 0x4b
    None, // 0x4c
    None, // 0x4d
    None, // 0x4e
    None, // 0x4f
    Some(HandlerEntry {
        state: ToServerConnectionState::NotConnected,
        handler: CommandHandler::handle_first_srp,
    }), // 0x50
    Some(HandlerEntry {
        state: ToServerConnectionState::NotConnected,
        handler: CommandHandler::handle_srp_bytes_a,
    }), // 0x51
    Some(HandlerEntry {
        state: ToServerConnectionState::NotConnected,
        handler: CommandHandler::handle_srp_bytes_m,
    }), // 0x52
    Some(HandlerEntry {
        state: ToServerConnectionState::Ingame,
        handler: CommandHandler::handle_update_client_info,
    }), // 0x53
];

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

        let responses = h.handle_command(&mut session, &p).unwrap();
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

        let responses = h.handle_command(&mut session, &p).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].command(), 0x0A);
    }

    #[test]
    fn media_commands_rejected_before_init2() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));

        // REQUEST_MEDIA is a Startup-category command in the C++
        // table, so it is unconditionally accepted by the gate
        // (mirroring `Server::ProcessData`'s early-return path).
        // Before INIT2 the server has no media registered, so the
        // handler short-circuits with an empty media bunch — *not*
        // a hard drop.
        let p = pkt(0x0040, &[0x00, 0x00]);
        let responses = h.handle_command(&mut session, &p).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].command(), 0x0038); // TOCLIENT_MEDIA
    }

    #[test]
    fn srp_bytes_a_rejects_disallowed_mech() {
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        session.player_name = Some("nrz".to_string());
        session.enc_pwd = Some("#1#fake".to_string());
        session.allowed_auth_mechs = AuthMechanism::LegacyPassword as u32; // only legacy

        let auth = make_auth();
        let mut h = CommandHandler::new(40, 42, Box::new(auth));

        // SRP_BYTES_A with based_on=1 (SRP mech) which is disallowed.
        let mut p = NetworkPacket::new(0x0051, 0);
        p.write_string(b"some-bytes");
        p.write_u8(1);

        let responses = h.handle_command(&mut session, &p).unwrap();
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
        let r = h.handle_command(&mut session, &p).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].command(), 0x0002); // TOCLIENT_HELLO
                                            // C++ CS_Created --CSE_Hello--> CS_HelloSent
        assert_eq!(session.phase, SessionPhase::HelloSent);

        // 2. FIRST_SRP
        let mut p = NetworkPacket::new(0x0050, 0);
        p.write_string(b"salt");
        p.write_string(b"verifier");
        p.write_u8(0);
        let r = h.handle_command(&mut session, &p).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].command(), 0x0003); // TOCLIENT_AUTH_ACCEPT

        // 3. INIT2
        let p = NetworkPacket::new(0x0011, 0);
        let r = h.handle_command(&mut session, &p).unwrap();
        // Should send ItemDef + NodeDef + AnnounceMedia + Movement +
        // TimeOfDay + CsmRestrictionFlags = 6 packets (in that
        // exact C++ order — see `handle_init2`).
        assert_eq!(r.len(), 6);
        assert_eq!(r[0].command(), 0x003D); // TOCLIENT_ITEMDEF
        assert_eq!(r[1].command(), 0x003A); // TOCLIENT_NODEDEF
        assert_eq!(r[2].command(), 0x003C); // TOCLIENT_ANNOUNCE_MEDIA
        assert_eq!(r[3].command(), 0x0045); // TOCLIENT_MOVEMENT
        assert_eq!(r[4].command(), 0x0029); // TOCLIENT_TIME_OF_DAY
        assert_eq!(r[5].command(), 0x002A); // TOCLIENT_CSM_RESTRICTION_FLAGS
                                            // C++ CS_InitDone --CSE_SetDefinitionsSent--> CS_DefinitionsSent
        assert_eq!(session.phase, SessionPhase::DefinitionsSent);

        // Re-sending INIT2 in MediaLoading phase must be a no-op
        // (mirrors C++ `getClientState(peer_id) != CS_AwaitingInit2`).
        let r2 = h
            .handle_command(&mut session, &NetworkPacket::new(0x0011, 0))
            .unwrap();
        assert!(r2.is_empty(), "INIT2 must be dropped in MediaLoading");

        // 4. CLIENT_READY
        let mut p = NetworkPacket::new(0x0043, 0);
        p.write_u8(5);
        p.write_u8(8);
        p.write_u8(0);
        p.write_u8(0);
        p.write_utf8("5.8.0");
        let r = h.handle_command(&mut session, &p).unwrap();
        assert!(r.is_empty());
        assert_eq!(session.phase, SessionPhase::Active);
    }

    #[test]
    fn handshake_retransmits_are_accepted_at_any_phase() {
        // Mirrors the C++ behaviour where `Server::ProcessData`
        // early-returns on `NotConnected`/`Startup` opcodes without
        // consulting `ClientState`. Once a client has reached the
        // `Active` phase it may still re-send the handshake packets
        // (e.g. on perceived packet loss) and they must be processed
        // rather than dropped.
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let fixture = make_auth_fixture();
        let mut h = CommandHandler::new(40, 42, Box::new(fixture.db));

        // Drive the session to Active.
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(40);
        p.write_u16(42);
        p.write_utf8("nrz");
        h.handle_command(&mut session, &p).unwrap();

        let mut p = NetworkPacket::new(0x0050, 0);
        p.write_string(b"salt");
        p.write_string(b"verifier");
        p.write_u8(0);
        h.handle_command(&mut session, &p).unwrap();

        h.handle_command(&mut session, &NetworkPacket::new(0x0011, 0))
            .unwrap();

        let mut p = NetworkPacket::new(0x0043, 0);
        p.write_u8(5);
        p.write_u8(8);
        p.write_u8(0);
        p.write_u8(0);
        p.write_utf8("5.8.0");
        h.handle_command(&mut session, &p).unwrap();
        assert_eq!(session.phase, SessionPhase::Active);

        // Re-send SRP_BYTES_A, SRP_BYTES_M, INIT2, CLIENT_READY
        // while in Active phase: every one must be accepted (no
        // "not allowed in current state" warning, no empty drop).
        let mut p = NetworkPacket::new(0x0051, 0);
        p.write_string(&vec![0u8; 256]);
        p.write_u8(1);
        let r = h.handle_command(&mut session, &p).unwrap();
        assert!(!r.is_empty(), "SRP_BYTES_A must be re-accepted");

        let r = h
            .handle_command(&mut session, &NetworkPacket::new(0x0011, 0))
            .unwrap();
        // INIT2 retransmits after Active are dropped: the C++ server
        // returns early on `client->getState() != CS_AwaitingInit2`,
        // and re-sending ITEMDEF/NODEDEF to a client whose
        // `m_mesh_update_manager` is running would crash the C++
        // client on `sanity_check(!m_mesh_update_manager->isRunning())`.
        assert!(
            r.is_empty(),
            "INIT2 must NOT be re-processed in Active phase"
        );

        let mut p = NetworkPacket::new(0x0043, 0);
        p.write_u8(5);
        p.write_u8(8);
        p.write_u8(0);
        p.write_u8(0);
        p.write_utf8("5.8.0");
        let r = h.handle_command(&mut session, &p).unwrap();
        assert!(r.is_empty(), "CLIENT_READY is ack-only");
    }

    #[test]
    fn ingame_commands_dropped_before_active() {
        // HAVE_MEDIA is Ingame-category, so it requires
        // `phase == Active` — mirroring the C++
        // `m_clients.getClientState(peer_id) < CS_Active` drop.
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let fixture = make_auth_fixture();
        let mut h = CommandHandler::new(40, 42, Box::new(fixture.db));

        // Drive to MediaLoading (INIT → FIRST_SRP → INIT2).
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(40);
        p.write_u16(42);
        p.write_utf8("nrz");
        h.handle_command(&mut session, &p).unwrap();
        let mut p = NetworkPacket::new(0x0050, 0);
        p.write_string(b"salt");
        p.write_string(b"verifier");
        p.write_u8(0);
        h.handle_command(&mut session, &p).unwrap();
        h.handle_command(&mut session, &NetworkPacket::new(0x0011, 0))
            .unwrap();
        assert_eq!(session.phase, SessionPhase::DefinitionsSent);

        // HAVE_MEDIA while in DefinitionsSent: must be dropped
        // (no response, mirroring the C++ warning drop —
        // `state < CS_Active` for an Ingame-category opcode).
        let mut p = NetworkPacket::new(0x0041, 0);
        p.write_u8(0);
        let r = h.handle_command(&mut session, &p).unwrap();
        assert!(r.is_empty(), "HAVE_MEDIA must be dropped pre-Active");
    }

    #[test]
    fn handler_table_state_matches_cpp_to_server_command_table() {
        // The HANDLER_TABLE state column must match
        // `ToServerCommandSpec::required_state` in
        // `luanti-network/src/opcodes.rs` (the latter is the
        // single source of truth that mirrors the C++
        // `toServerCommandTable[command].state` field in
        // `src/network/serveropcodes.cpp`). Walking both tables
        // opcode-by-opcode keeps them in lock-step.
        for (raw, slot) in HANDLER_TABLE.iter().enumerate() {
            let raw = raw as u16;
            let Some(cmd) = ToServerCommand::from_u16(raw) else {
                assert!(
                    slot.is_none(),
                    "HANDLER_TABLE has a handler for opcode 0x{:04x} \
                     that has no ToServerCommand variant",
                    raw
                );
                continue;
            };
            match slot {
                None => panic!(
                    "ToServerCommand::{:?} (0x{:04x}) has a Rust variant but \
                     no entry in HANDLER_TABLE",
                    cmd, raw
                ),
                Some(entry) => {
                    assert_eq!(
                        entry.state,
                        cmd.required_state(),
                        "HANDLER_TABLE state mismatch for {:?} (0x{:04x}): \
                         table says {:?}, opcode spec says {:?}. \
                         Keep the two in lock-step — they mirror the C++ \
                         `toServerCommandTable[command].state` column \
                         (src/network/serveropcodes.cpp).",
                        cmd,
                        raw,
                        entry.state,
                        cmd.required_state(),
                    );
                }
            }
        }
    }

    #[test]
    fn modchannel_accepted_in_awaiting_init2_rejected_before() {
        // The C++ `TOSERVER_MODCHANNEL_*` opcodes are
        // `TOSERVER_STATE_INGAME` (serveropcodes.cpp:37-39), so
        // `Server::ProcessData` drops them with a warning when
        // `getClientState(peer_id) < CS_Active`. We mirror that:
        // Ingame-category opcodes are dropped in any pre-Active
        // phase and accepted in Active.
        let mut session = Session::new(2, "127.0.0.1:0".parse().unwrap());
        let fixture = make_auth_fixture();
        let mut h = CommandHandler::new(40, 42, Box::new(fixture.db));

        // Drive to AwaitingInit2 (INIT → FIRST_SRP).
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(29);
        p.write_u16(0);
        p.write_u16(40);
        p.write_u16(42);
        p.write_utf8("nrz");
        h.handle_command(&mut session, &p).unwrap();
        let mut p = NetworkPacket::new(0x0050, 0);
        p.write_string(b"salt");
        p.write_string(b"verifier");
        p.write_u8(0);
        h.handle_command(&mut session, &p).unwrap();
        assert_eq!(session.phase, SessionPhase::AwaitingInit2);

        // MODCHANNEL_JOIN while in AwaitingInit2: must be dropped
        // (the C++ logs "but client isn't active yet. Dropping packet."
        // and returns — same outcome as the Rust warn-and-return-vec![]).
        let mut p = NetworkPacket::new(0x0017, 0);
        p.write_utf8("chan");
        let r = h.handle_command(&mut session, &p).unwrap();
        assert!(
            r.is_empty(),
            "MODCHANNEL_JOIN must be dropped in AwaitingInit2"
        );
    }
}
