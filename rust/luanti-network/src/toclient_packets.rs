//! TOCLIENT packet creation functions
//!
//! This module provides functions to create protocol packets sent from the server to clients.
//! These are pure functions that don't depend on session state and can be reused across
//! different server implementations.

use crate::opcodes::{AccessDeniedCode, AuthMechanism, ToClientCommand};

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
    let mut response = Vec::new();
    response.extend_from_slice(&(ToClientCommand::Hello as u16).to_be_bytes());
    response.push(serialization_version); // negotiated serialization version
    response.extend_from_slice(&0u16.to_be_bytes()); // compression (unused)
    response.extend_from_slice(&protocol_version.to_be_bytes());
    response.extend_from_slice(&auth_mechs.to_be_bytes());
    // Empty username (u16 length + string)
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

/// Create TOCLIENT_AUTH_ACCEPT response
///
/// This packet is sent when the client's authentication is accepted, allowing them
/// to enter the game.
pub fn create_auth_accept_response() -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&(ToClientCommand::AuthAccept as u16).to_be_bytes());
    // v3f unused position
    response.extend_from_slice(&[0u8; 12]);
    // u64 map seed
    response.extend_from_slice(&12345u64.to_be_bytes());
    // f32 send interval (converted to f1000)
    response.extend_from_slice(&100u16.to_be_bytes()); // 0.1 second
                                                       // u32 auth methods for sudo
    response.extend_from_slice(&(AuthMechanism::None as u32).to_be_bytes());
    response
}

/// Create TOCLIENT_ACCESS_DENIED response
///
/// This packet denies access to a client with a specific reason code and message.
///
/// # Arguments
/// * `code` - The denial reason code
/// * `message` - Human-readable message explaining the denial
pub fn create_access_denied(code: AccessDeniedCode, message: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&(ToClientCommand::AccessDenied as u16).to_be_bytes());
    response.push(code as u8);
    // Custom reason string
    response.extend_from_slice(&(message.len() as u16).to_be_bytes());
    response.extend_from_slice(message.as_bytes());
    response.push(0); // no reconnect
    response
}

/// Create TOCLIENT_CHAT_MESSAGE response
///
/// This packet sends a chat message to the client. The message is encoded in UTF-16
/// as per the protocol specification.
///
/// # Arguments
/// * `message` - The message text to send
pub fn create_chat_message_response(message: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&(ToClientCommand::ChatMessage as u16).to_be_bytes());
    response.push(1); // version
    response.push(0); // message type (normal)

    // Sender name (empty for server)
    response.extend_from_slice(&0u16.to_be_bytes());

    // Convert message to UTF-16
    let wchars: Vec<u16> = message.encode_utf16().collect();
    response.extend_from_slice(&(wchars.len() as u16).to_be_bytes());
    for wchar in wchars {
        response.extend_from_slice(&wchar.to_be_bytes());
    }

    response
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
        let packet = create_auth_accept_response();
        assert_eq!(
            packet[0..2],
            (ToClientCommand::AuthAccept as u16).to_be_bytes()
        );
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
