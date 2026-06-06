// Session management for peer connections

use log::info;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::protocol::*;

/// Represents a connection session with a peer
#[derive(Debug)]
pub struct Session {
    pub peer_id: u16,
    pub address: SocketAddr,
    pub connected: bool,
    pub last_activity: Instant,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub next_outgoing_seqnum: u16,
    pub next_incoming_seqnum: u16,
    pub pending_acks: Vec<u16>,
    pub protocol_version: Option<u16>,
    pub player_name: Option<String>,
    /// Encrypted password (`#1#...` SRP format or base64 legacy), populated
    /// after TOSERVER_INIT is processed.
    pub enc_pwd: Option<String>,
    /// Chosen auth mechanism for the current authentication step.
    pub chosen_mech: u32,
    /// Whether we should create the player in the database on successful
    /// authentication (used when a `default_password` matches a fresh account).
    pub create_player_on_auth_success: bool,
    /// Bitmask of auth mechanisms allowed by the server for this session.
    pub allowed_auth_mechs: u32,
    /// Progress of the client through the connection handshake.
    ///
    /// The single source of truth for the session lifecycle. The
    /// phase space mirrors the C++ `ClientState` enum
    /// (see [`src/server/clientiface.h`](../../../../src/server/clientiface.h))
    /// line-for-line, with all ten sub-states (`Created`,
    /// `HelloSent`, `AwaitingInit2`, `InitDone`, `DefinitionsSent`,
    /// `Active`, `SudoMode`, plus the terminal `Invalid`,
    /// `Disconnecting`, `Denied`).
    ///
    /// It is used as the gating condition for `Startup`- and
    /// `Ingame`-category opcodes — mirroring the C++
    /// `getClient(peer_id, CS_InitDone)` and
    /// `m_clients.getClientState(peer_id) >= CS_Active` checks in
    /// [`Server::ProcessData`](../../../../src/server.cpp).
    ///
    /// ```text
    /// Created → HelloSent → AwaitingInit2 → InitDone → DefinitionsSent
    ///                                                            ↓
    ///                                                        Active ↔ SudoMode
    /// ```
    ///
    /// The progression is mostly monotonic: it never goes
    /// backwards through the handshake. The terminal
    /// `Disconnecting`/`Denied` states can be entered from
    /// various points. A re-sent handshake (e.g. the client
    /// retransmitting `INIT2` after a perceived packet loss) does
    /// *not* move the phase back; the handler simply runs again.
    pub phase: SessionPhase,
    /// `true` if this session was just created by the call that
    /// returned it. The next packet-processing turn is expected to
    /// inform the client of its assigned peer id via CONTROLTYPE_SET_PEER_ID
    /// and clear this flag.
    pub newly_created: bool,
}

/// Tracks the progress of a client through the connection handshake.
///
/// The discriminants and names match the C++ `ClientState` enum
/// (see `enum ClientState` in [`src/server/clientiface.h`](../../../../src/server/clientiface.h))
/// line-for-line so the Rust port can mirror the C++ `ProcessData`
/// state-machine filtering exactly. The progression is mostly
/// monotonic — once a client has reached `Active` it does not go
/// back to `Init`/`MediaLoading` — with the exception of the
/// terminal `Disconnecting`/`Denied`/`SudoMode` states that can be
/// entered from various points.
///
/// ```text
/// Created → HelloSent → AwaitingInit2 → InitDone → DefinitionsSent
///                                                          ↓
///                                                       Active ↔ SudoMode
/// ```
///
/// The C++ dispatch logic in `Server::ProcessData`
/// (see [`src/server.cpp`](../../../../src/server.cpp)) gates
/// incoming packets on the coarse `ToServerConnectionState`
/// category — `NotConnected` / `Startup` / `Ingame` — but the
/// per-handler state predicates are checked against the
/// fine-grained `ClientState`:
/// - `NotConnected` opcodes are accepted in **any** state (they
///   run before the state-machine gates).
/// - `Startup` opcodes are accepted from `InitDone` onwards (the
///   C++ explicitly calls `getClient(peer_id, CS_InitDone)`,
///   which asserts the state has reached `InitDone`).
/// - `Ingame` opcodes are accepted from `Active` onwards (the
///   `state < CS_Active` drop in `ProcessData`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SessionPhase {
    /// Sentinel for an unused slot. C++ `CS_Invalid`.
    Invalid = 0,
    /// Peer is being torn down. C++ `CS_Disconnecting`.
    Disconnecting = 1,
    /// Access was denied. C++ `CS_Denied`.
    Denied = 2,
    /// Session created, `TOSERVER_INIT` not yet received.
    /// C++ `CS_Created`.
    Created = 3,
    /// `TOSERVER_INIT` processed, `TOCLIENT_HELLO` sent.
    /// C++ `CS_HelloSent`.
    HelloSent = 4,
    /// Auth negotiation done, waiting for `TOSERVER_INIT2`.
    /// C++ `CS_AwaitingInit2`.
    AwaitingInit2 = 5,
    /// `TOSERVER_INIT2` processed, init-data not yet fully sent.
    /// C++ `CS_InitDone`.
    InitDone = 6,
    /// ItemDef/NodeDef/AnnounceMedia sent, client may request media.
    /// C++ `CS_DefinitionsSent`.
    DefinitionsSent = 7,
    /// `TOSERVER_CLIENT_READY` received, fully in-game.
    /// C++ `CS_Active`.
    Active = 8,
    /// Sudo mode (elevated privileges for /grant-style commands).
    /// C++ `CS_SudoMode`.
    SudoMode = 9,
}

impl SessionPhase {
    /// `true` if the session has reached the "media can be
    /// requested" stage — i.e. the C++ `CS_InitDone` floor that
    /// `Startup`-category opcodes require.
    ///
    /// Mirrors `getClient(peer_id, CS_InitDone)` in
    /// `Server::ProcessData`.
    #[inline]
    pub fn has_reached_init_done(self) -> bool {
        self >= SessionPhase::InitDone
    }

    /// `true` if the session is in `Active` (or `SudoMode`, which
    /// the C++ also counts as `>= CS_Active`).
    ///
    /// Mirrors `m_clients.getClientState(peer_id) >= CS_Active` in
    /// `Server::ProcessData`.
    #[inline]
    pub fn is_active(self) -> bool {
        self >= SessionPhase::Active
    }

    /// Coarse progress bucket used by the tests and by code that
    /// doesn't need to distinguish the C++ sub-states. Returns:
    /// - `Init` for `Created`/`HelloSent`/`AwaitingInit2`
    /// - `MediaLoading` for `InitDone`/`DefinitionsSent`
    /// - `Active` for `Active`/`SudoMode`
    pub fn coarse(self) -> CoarsePhase {
        match self {
            SessionPhase::Created | SessionPhase::HelloSent | SessionPhase::AwaitingInit2 => {
                CoarsePhase::Init
            }
            SessionPhase::InitDone | SessionPhase::DefinitionsSent => CoarsePhase::MediaLoading,
            SessionPhase::Active | SessionPhase::SudoMode => CoarsePhase::Active,
            SessionPhase::Invalid | SessionPhase::Disconnecting | SessionPhase::Denied => {
                CoarsePhase::Invalid
            }
        }
    }
}

/// Coarse-grained view of [`SessionPhase`] used by code that does
/// not need the full C++ `ClientState` granularity (tests, log
/// messages, dispatching on "have we reached media loading yet").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoarsePhase {
    /// Session is pre-`InitDone` (any of the `Created`/
    /// `HelloSent`/`AwaitingInit2` sub-states, plus the terminal
    /// `Invalid`/`Disconnecting`/`Denied` bucket).
    Invalid,
    /// `Init` per the original 3-phase model: covers
    /// `CS_Created`/`CS_HelloSent`/`CS_AwaitingInit2`.
    Init,
    /// `MediaLoading` per the original 3-phase model: covers
    /// `CS_InitDone`/`CS_DefinitionsSent`.
    MediaLoading,
    /// `Active` per the original 3-phase model: covers
    /// `CS_Active`/`CS_SudoMode`.
    Active,
}

impl Session {
    pub fn new(peer_id: u16, address: SocketAddr) -> Self {
        Session {
            peer_id,
            address,
            connected: true,
            last_activity: Instant::now(),
            packets_received: 0,
            packets_sent: 0,
            next_outgoing_seqnum: SEQNUM_INITIAL,
            next_incoming_seqnum: SEQNUM_INITIAL,
            pending_acks: Vec::new(),
            protocol_version: None,
            player_name: None,
            enc_pwd: None,
            chosen_mech: 0,
            create_player_on_auth_success: false,
            allowed_auth_mechs: 0,
            phase: SessionPhase::Created,
            newly_created: true,
        }
    }

    /// Returns whether the session was just created by the most recent
    /// call to `SessionManager::get_or_create_session` and clears the
    /// flag.
    pub fn take_newly_created(&mut self) -> bool {
        let n = self.newly_created;
        self.newly_created = false;
        n
    }

    pub fn on_packet_received(&mut self) {
        self.last_activity = Instant::now();
        self.packets_received += 1;
    }

    pub fn on_packet_sent(&mut self) {
        self.packets_sent += 1;
    }

    pub fn handle_ack(&mut self, seqnum: u16) {
        if let Some(pos) = self.pending_acks.iter().position(|&s| s == seqnum) {
            self.pending_acks.remove(pos);
        }
    }

    pub fn set_peer_id(&mut self, new_peer_id: u16) {
        self.peer_id = new_peer_id;
    }

    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub fn get_next_outgoing_seqnum(&mut self) -> u16 {
        let seqnum = self.next_outgoing_seqnum;
        self.next_outgoing_seqnum = if self.next_outgoing_seqnum == SEQNUM_MAX {
            0
        } else {
            self.next_outgoing_seqnum + 1
        };
        seqnum
    }
}

/// Manages all active sessions
pub struct SessionManager {
    sessions: HashMap<u16, Session>,
    address_to_peer_id: HashMap<SocketAddr, u16>,
    next_peer_id: u16,
    timeout: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
            address_to_peer_id: HashMap::new(),
            next_peer_id: PEER_ID_SERVER + 1, // Start after server's reserved ID
            timeout: Duration::from_secs(30),
        }
    }

    pub fn get_or_create_session(&mut self, peer_id: u16, address: SocketAddr) -> &mut Session {
        // If this is a new connection (peer_id == 0), assign a new ID
        if peer_id == PEER_ID_INEXISTENT {
            // Check if we already have a session for this address
            if let Some(&existing_peer_id) = self.address_to_peer_id.get(&address) {
                info!(
                    "Reusing existing session {} for {}",
                    existing_peer_id, address
                );
                return self.sessions.get_mut(&existing_peer_id).unwrap();
            }

            let new_peer_id = self.allocate_peer_id();
            info!("Creating new session {} for {}", new_peer_id, address);

            let session = Session::new(new_peer_id, address);
            self.sessions.insert(new_peer_id, session);
            self.address_to_peer_id.insert(address, new_peer_id);

            return self.sessions.get_mut(&new_peer_id).unwrap();
        }

        // Otherwise, get or create session with the given peer_id
        self.sessions.entry(peer_id).or_insert_with(|| {
            info!("Creating session {} for {}", peer_id, address);
            self.address_to_peer_id.insert(address, peer_id);
            Session::new(peer_id, address)
        })
    }

    pub fn get_session(&self, peer_id: u16) -> Option<&Session> {
        self.sessions.get(&peer_id)
    }

    pub fn get_session_mut(&mut self, peer_id: u16) -> Option<&mut Session> {
        self.sessions.get_mut(&peer_id)
    }

    pub fn remove_session(&mut self, peer_id: u16) {
        if let Some(session) = self.sessions.remove(&peer_id) {
            self.address_to_peer_id.remove(&session.address);
            info!("Removed session {} ({})", peer_id, session.address);
        }
    }

    pub fn cleanup_timed_out_sessions(&mut self) {
        let timed_out: Vec<u16> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_timed_out(self.timeout))
            .map(|(&peer_id, _)| peer_id)
            .collect();

        for peer_id in timed_out {
            self.remove_session(peer_id);
        }
    }

    fn allocate_peer_id(&mut self) -> u16 {
        loop {
            let peer_id = self.next_peer_id;
            self.next_peer_id = if self.next_peer_id == SEQNUM_MAX {
                PEER_ID_SERVER + 1
            } else {
                self.next_peer_id + 1
            };

            if !self.sessions.contains_key(&peer_id) {
                return peer_id;
            }
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
