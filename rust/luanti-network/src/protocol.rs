// Protocol definitions based on Luanti's MTP (Minetest Protocol)

use anyhow::{anyhow, Result};

// Constant that differentiates the protocol from random data and other protocols
pub const PROTOCOL_ID: u32 = 0x4f457403;

// Protocol version constants
pub const LATEST_PROTOCOL_VERSION: u16 = 43;
pub const SERVER_PROTOCOL_VERSION_MIN: u16 = 37;
pub const CLIENT_PROTOCOL_VERSION_MIN: u16 = 37;

pub const BASE_HEADER_SIZE: usize = 7;
pub const CHANNEL_COUNT: usize = 3;

pub const ORIGINAL_HEADER_SIZE: usize = 1;
pub const RELIABLE_HEADER_SIZE: usize = 3;
pub const SEQNUM_INITIAL: u16 = 65500;
pub const SEQNUM_MAX: u16 = 65535;

// Peer IDs
pub const PEER_ID_INEXISTENT: u16 = 0;
pub const PEER_ID_SERVER: u16 = 1;

/// Base header present in all packets
/// [0..4] u32 protocol_id
/// [4..6] u16 sender_peer_id (session_t)
/// [6] u8 channel
#[derive(Debug, Clone)]
pub struct BaseHeader {
    pub protocol_id: u32,
    pub sender_peer_id: u16,
    pub channel: u8,
}

impl BaseHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < BASE_HEADER_SIZE {
            return Err(anyhow!("Data too short for base header"));
        }

        let protocol_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let sender_peer_id = u16::from_be_bytes([data[4], data[5]]);
        let channel = data[6];

        Ok(BaseHeader {
            protocol_id,
            sender_peer_id,
            channel,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BASE_HEADER_SIZE);
        bytes.extend_from_slice(&self.protocol_id.to_be_bytes());
        bytes.extend_from_slice(&self.sender_peer_id.to_be_bytes());
        bytes.push(self.channel);
        bytes
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Control = 0,
    Original = 1,
    Split = 2,
    Reliable = 3,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PacketType::Control),
            1 => Some(PacketType::Original),
            2 => Some(PacketType::Split),
            3 => Some(PacketType::Reliable),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlType {
    Ack = 0,
    SetPeerId = 1,
    Ping = 2,
    Disco = 3,
}

impl ControlType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ControlType::Ack),
            1 => Some(ControlType::SetPeerId),
            2 => Some(ControlType::Ping),
            3 => Some(ControlType::Disco),
            _ => None,
        }
    }
}

/// Check if a sequence number is higher than another, accounting for wrapping
pub fn seqnum_higher(totest: u16, base: u16) -> bool {
    if totest > base {
        if (totest - base) > (SEQNUM_MAX / 2) {
            return false;
        }
        return true;
    }

    if (base - totest) > (SEQNUM_MAX / 2) {
        return true;
    }

    false
}

/// Check if a sequence number is within a window
pub fn seqnum_in_window(seqnum: u16, next: u16, window_size: u16) -> bool {
    let window_start = next;
    // Use u32 for computation to avoid overflow
    let window_end = ((next as u32 + window_size as u32) % 65536) as u16;

    if window_start < window_end {
        return seqnum >= window_start && seqnum < window_end;
    }

    seqnum < window_end || seqnum >= window_start
}
