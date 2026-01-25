// Command handler for processing protocol commands
// This layer sits on top of the session layer and processes application-level commands

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::net::SocketAddr;

use luanti_auth_db::AuthDatabase;
use luanti_network::{
    create_access_denied, create_auth_accept_response, create_chat_message_response,
    create_hello_response, AccessDeniedCode, AuthMechanism, Session, ToServerCommand,
    ToServerConnectionState,
};

/// Represents a parsed network packet with command information
#[derive(Debug)]
pub struct CommandPacket {
    pub peer_id: u16,
    pub command: u16,
    pub data: Vec<u8>,
}

impl CommandPacket {
    /// Parse a command packet from raw data (after session layer processing)
    pub fn parse(data: &[u8], peer_id: u16) -> Result<Self> {
        if data.len() < 2 {
            return Err(anyhow!("Command packet too short"));
        }

        let command = u16::from_be_bytes([data[0], data[1]]);
        let payload = data[2..].to_vec();

        Ok(CommandPacket {
            peer_id,
            command,
            data: payload,
        })
    }

    /// Get the command as ToServerCommand if valid
    pub fn as_to_server_command(&self) -> Option<ToServerCommand> {
        ToServerCommand::from_u16(self.command)
    }
}

/// Command handler that processes application-level protocol commands
pub struct CommandHandler {
    // Protocol version negotiation
    pub min_protocol_version: u16,
    pub max_protocol_version: u16,

    // Authentication database
    auth_db: Box<dyn AuthDatabase>,
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
        }
    }

    /// Process a command packet from a client
    pub fn handle_command(
        &mut self,
        session: &mut Session,
        packet: &CommandPacket,
        peer_addr: SocketAddr,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(cmd) = packet.as_to_server_command() {
            debug!("Processing command {} from {}", cmd, peer_addr);

            // Check if session state allows this command
            if !self.check_command_state(session, cmd) {
                warn!(
                    "Command {} not allowed in current state from {}",
                    cmd, peer_addr
                );
                return Ok(None);
            }

            // Dispatch to appropriate handler
            match cmd {
                ToServerCommand::Init => self.handle_init(session, packet, peer_addr),
                ToServerCommand::Init2 => self.handle_init2(session, packet, peer_addr),
                ToServerCommand::PlayerPos => self.handle_player_pos(session, packet),
                ToServerCommand::ChatMessage => self.handle_chat_message(session, packet),
                ToServerCommand::ClientReady => self.handle_client_ready(session, packet),
                _ => {
                    info!("Handler not implemented for {}", cmd);
                    Ok(None)
                }
            }
        } else {
            warn!(
                "Unknown command 0x{:04x} from {}",
                packet.command, peer_addr
            );
            Ok(None)
        }
    }

    /// Check if command is allowed in current session state
    fn check_command_state(&self, session: &Session, cmd: ToServerCommand) -> bool {
        let required_state = cmd.required_state();
        let current_state = &session.connection_state;

        match required_state {
            ToServerConnectionState::NotConnected => {
                matches!(current_state, ToServerConnectionState::NotConnected)
            }
            ToServerConnectionState::Startup => {
                matches!(
                    current_state,
                    ToServerConnectionState::Startup | ToServerConnectionState::NotConnected
                )
            }
            ToServerConnectionState::Ingame => {
                matches!(current_state, ToServerConnectionState::Ingame)
            }
        }
    }

    /// Handle TOSERVER_INIT command
    fn handle_init(
        &mut self,
        session: &mut Session,
        packet: &CommandPacket,
        peer_addr: SocketAddr,
    ) -> Result<Option<Vec<u8>>> {
        if packet.data.len() < 7 {
            return Err(anyhow!("INIT packet too short"));
        }

        let client_ser_ver = packet.data[0];
        let _compression = u16::from_be_bytes([packet.data[1], packet.data[2]]);
        let min_proto = u16::from_be_bytes([packet.data[3], packet.data[4]]);
        let max_proto = u16::from_be_bytes([packet.data[5], packet.data[6]]);

        // Parse player name (length-prefixed string)
        let mut offset = 7;
        if packet.data.len() < offset + 2 {
            return Err(anyhow!("INIT packet missing player name length"));
        }

        let name_len = u16::from_be_bytes([packet.data[offset], packet.data[offset + 1]]) as usize;
        offset += 2;

        if packet.data.len() < offset + name_len {
            return Err(anyhow!("INIT packet name too short"));
        }

        let player_name =
            String::from_utf8_lossy(&packet.data[offset..offset + name_len]).to_string();

        info!(
            "Client {} INIT: ser_ver={}, proto={}-{}, name='{}'",
            peer_addr, client_ser_ver, min_proto, max_proto, player_name
        );

        // Negotiate serialization version (use minimum of client and server)
        const SER_FMT_VER_HIGHEST_WRITE: u8 = 29;
        let negotiated_ser_ver = std::cmp::min(client_ser_ver, SER_FMT_VER_HIGHEST_WRITE);

        // Negotiate protocol version
        let negotiated_proto = std::cmp::min(max_proto, self.max_protocol_version);
        if negotiated_proto < self.min_protocol_version || negotiated_proto < min_proto {
            warn!("Protocol version mismatch with {}", peer_addr);
            return Ok(Some(create_access_denied(
                AccessDeniedCode::WrongVersion,
                "Protocol version mismatch",
            )));
        }

        // Determine authentication mechanism based on database lookup
        let auth_mechs = self.determine_auth_mechanism(&player_name)?;

        debug!("Auth mechanisms for {}: 0x{:08x}", player_name, auth_mechs);

        session.protocol_version = Some(negotiated_proto);
        session.player_name = Some(player_name);
        session.connection_state = ToServerConnectionState::Startup;

        debug!(
            "Negotiated with {}: ser_ver={}, proto={}",
            peer_addr, negotiated_ser_ver, negotiated_proto
        );
        // Send TOCLIENT_HELLO
        Ok(Some(create_hello_response(
            negotiated_ser_ver,
            negotiated_proto,
            auth_mechs,
        )))
    }

    /// Handle TOSERVER_INIT2 command
    fn handle_init2(
        &mut self,
        session: &mut Session,
        _packet: &CommandPacket,
        peer_addr: SocketAddr,
    ) -> Result<Option<Vec<u8>>> {
        info!("Client {} completed initialization", peer_addr);
        session.connection_state = ToServerConnectionState::Ingame;

        // Send AUTH_ACCEPT
        Ok(Some(create_auth_accept_response()))
    }

    /// Handle TOSERVER_PLAYERPOS command
    fn handle_player_pos(
        &mut self,
        session: &mut Session,
        packet: &CommandPacket,
    ) -> Result<Option<Vec<u8>>> {
        if packet.data.len() < 34 {
            return Err(anyhow!("PLAYERPOS packet too short"));
        }

        // Parse position, speed, pitch, yaw, etc.
        // For now just acknowledge receipt
        debug!("Received PLAYERPOS from peer {}", session.peer_id);
        Ok(None)
    }

    /// Handle TOSERVER_CHAT_MESSAGE command
    fn handle_chat_message(
        &mut self,
        session: &mut Session,
        packet: &CommandPacket,
    ) -> Result<Option<Vec<u8>>> {
        if packet.data.len() < 2 {
            return Err(anyhow!("CHAT_MESSAGE packet too short"));
        }

        let msg_len = u16::from_be_bytes([packet.data[0], packet.data[1]]) as usize;
        if packet.data.len() < 2 + msg_len * 2 {
            return Err(anyhow!("CHAT_MESSAGE truncated"));
        }

        // Parse wide string (UTF-16)
        let mut wchars = Vec::new();
        for i in 0..msg_len {
            let offset = 2 + i * 2;
            wchars.push(u16::from_be_bytes([
                packet.data[offset],
                packet.data[offset + 1],
            ]));
        }

        let message = String::from_utf16_lossy(&wchars);
        info!(
            "Chat message from {} ({}): {}",
            session.player_name.as_deref().unwrap_or("unknown"),
            session.peer_id,
            message
        );

        // Echo back as server message (for demonstration)
        Ok(Some(create_chat_message_response(&format!(
            "<{}> {}",
            session.player_name.as_deref().unwrap_or("Player"),
            message
        ))))
    }

    /// Handle TOSERVER_CLIENT_READY command
    fn handle_client_ready(
        &mut self,
        session: &mut Session,
        packet: &CommandPacket,
    ) -> Result<Option<Vec<u8>>> {
        if packet.data.len() < 6 {
            return Err(anyhow!("CLIENT_READY packet too short"));
        }

        let major = packet.data[0];
        let minor = packet.data[1];
        let patch = packet.data[2];

        info!(
            "Client {} ready: version {}.{}.{}",
            session.peer_id, major, minor, patch
        );

        Ok(None)
    }

    /// Determine authentication mechanism for a player
    ///
    /// Returns the bitmask of supported authentication mechanisms based on:
    /// - Whether the player exists in the database
    /// - The format of their stored password
    fn determine_auth_mechanism(&mut self, player_name: &str) -> Result<u32> {
        // Try to get auth entry from database
        match self.auth_db.get_auth(player_name) {
            Ok(auth_entry) => {
                // User exists - check password format
                let enc_pwd = &auth_entry.password;

                // Check if it's SRP format (component1#component2#component3#component4)
                let pwd_components: Vec<&str> = enc_pwd.split('#').collect();
                if pwd_components.len() == 4 {
                    // Check if it's SRP (mech code "1")
                    if pwd_components[1] == "1" {
                        info!("Player {} has SRP password", player_name);
                        return Ok(AuthMechanism::Srp as u32);
                    } else {
                        warn!(
                            "Player {} has unknown password mechanism: {}",
                            player_name, pwd_components[1]
                        );
                        return Err(anyhow!("Invalid password mechanism"));
                    }
                } else if Self::is_valid_base64(enc_pwd) {
                    // Legacy base64 password
                    info!("Player {} has legacy password", player_name);
                    return Ok(AuthMechanism::LegacyPassword as u32);
                } else {
                    warn!("Player {} has invalid password format", player_name);
                    return Err(anyhow!("Invalid password format"));
                }
            }
            Err(_) => {
                // User doesn't exist - allow first login with SRP
                info!("Player {} not found, allowing first SRP", player_name);
                Ok(AuthMechanism::FirstSrp as u32)
            }
        }
    }

    /// Check if a string is valid base64
    fn is_valid_base64(s: &str) -> bool {
        // Simple check: base64 uses only [A-Za-z0-9+/=]
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && !s.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_packet_parse() {
        let data = vec![0x00, 0x02, 0xAA, 0xBB]; // Command 0x0002 with data
        let packet = CommandPacket::parse(&data, 123).unwrap();

        assert_eq!(packet.command, 0x0002);
        assert_eq!(packet.peer_id, 123);
        assert_eq!(packet.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_to_server_command_parsing() {
        let data = vec![0x00, 0x02]; // TOSERVER_INIT
        let packet = CommandPacket::parse(&data, 1).unwrap();
        assert_eq!(packet.as_to_server_command(), Some(ToServerCommand::Init));
    }
}
