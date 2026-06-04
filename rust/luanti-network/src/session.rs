// Session management for peer connections

use log::info;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::opcodes::ToServerConnectionState;
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
    pub connection_state: ToServerConnectionState,
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
    /// Whether the client has completed `TOSERVER_INIT2` and is now in
    /// the media-loading phase. While `false`, media-related commands
    /// (REQUEST_MEDIA, HAVE_MEDIA, GOTBLOCKS) are rejected.
    pub media_loading: bool,
    /// Set to `true` when the client sends `TOSERVER_CLIENT_READY`.
    /// After this, the client is fully connected.
    pub client_ready: bool,
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
            connection_state: ToServerConnectionState::NotConnected,
            protocol_version: None,
            player_name: None,
            enc_pwd: None,
            chosen_mech: 0,
            create_player_on_auth_success: false,
            allowed_auth_mechs: 0,
            media_loading: false,
            client_ready: false,
        }
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
