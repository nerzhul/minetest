//! Luanti Network Protocol Library
//!
//! This library implements the Minetest Protocol (MTP) for Luanti (formerly Minetest).
//! It provides a session layer with reliable ordered transmission and packet creation
//! utilities.

pub mod auth;
pub mod base64_util;
pub mod network_packet;
pub mod opcodes;
pub mod packet;
pub mod protocol;
pub mod session;
pub mod srp;
pub mod toclient_packets;
pub mod wire;

// Re-export commonly used types
pub use opcodes::{
    AccessDeniedCode, AuthMechanism, ToClientCommand, ToServerCommand, ToServerConnectionState,
};
pub use network_packet::{NetworkPacket, PacketError, PacketResult};
pub use protocol::*;
pub use session::{Session, SessionManager, SessionPhase};
pub use srp::SrpVerifier;
pub use toclient_packets::*;
