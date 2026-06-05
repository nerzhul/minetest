//! MTP frame construction helpers.
//!
//! The Luanti wire format adds a small envelope around a payload:
//!
//! ```text
//! [0..4]   u32  protocol_id (PROTOCOL_ID, big-endian)
//! [4..6]   u16  sender_peer_id  (always PEER_ID_SERVER for outbound)
//! [6]      u8   channel
//! [7]      u8   packet_type  (Control / Original / Split / Reliable)
//! [8..]    type-specific payload
//! ```
//!
//! `Original` packets carry the command + its payload directly. `Reliable`
//! packets carry a u16 sequence number followed by the same command +
//! payload. `Control` packets carry a u8 control subtype followed by
//! type-specific data.
//!
//! These helpers build complete datagrams ready to be sent on the UDP
//! socket.

use luanti_network::{
    BaseHeader, ControlType, PacketType, BASE_HEADER_SIZE, PEER_ID_SERVER, PROTOCOL_ID,
};

/// Build the 7-byte MTP base header.
pub fn build_base_header(sender_peer_id: u16, channel: u8) -> [u8; BASE_HEADER_SIZE] {
    let mut header = [0u8; BASE_HEADER_SIZE];
    header[0..4].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    header[4..6].copy_from_slice(&sender_peer_id.to_be_bytes());
    header[6] = channel;
    header
}

pub fn parse_base_header(data: &[u8]) -> Option<BaseHeader> {
    if data.len() < BASE_HEADER_SIZE {
        return None;
    }
    Some(BaseHeader::parse(data).ok()?)
}

/// Wrap a command + payload in an `Original` MTP datagram on channel 0.
pub fn wrap_original(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 1 + payload.len());
    out.extend_from_slice(&build_base_header(PEER_ID_SERVER, 0));
    out.push(PacketType::Original as u8);
    out.extend_from_slice(payload);
    out
}

/// Wrap a command + payload in a `Reliable` MTP datagram on channel 0.
pub fn wrap_reliable(seqnum: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 3 + payload.len());
    out.extend_from_slice(&build_base_header(PEER_ID_SERVER, 0));
    out.push(PacketType::Reliable as u8);
    out.extend_from_slice(&seqnum.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build a `CONTROLTYPE_ACK` control datagram, used to ACK a peer's
/// reliable packet.
pub fn build_control_ack(seqnum: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 3);
    out.extend_from_slice(&build_base_header(PEER_ID_SERVER, 0));
    out.push(PacketType::Control as u8);
    out.push(ControlType::Ack as u8);
    out.extend_from_slice(&seqnum.to_be_bytes());
    out
}

/// Build a `CONTROLTYPE_SET_PEER_ID` control datagram. Sent to a
/// freshly-arrived peer to inform it of the id we just assigned to it.
pub fn build_set_peer_id(peer_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + 4);
    out.extend_from_slice(&build_base_header(PEER_ID_SERVER, 0));
    out.push(PacketType::Control as u8);
    out.push(ControlType::SetPeerId as u8);
    out.extend_from_slice(&peer_id.to_be_bytes());
    out
}

/// Format up to `max` bytes of `data` as a lowercase hex string. Useful
/// for log lines that need to identify a malformed packet.
pub fn hex_preview(data: &[u8], max: usize) -> String {
    let n = data.len().min(max);
    let mut s = String::with_capacity(n * 2 + 8);
    for b in &data[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    if data.len() > n {
        s.push_str(&format!("…(+{}B)", data.len() - n));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_header_layout() {
        let h = build_base_header(0x1234, 2);
        assert_eq!(&h[0..4], &PROTOCOL_ID.to_be_bytes());
        assert_eq!(h[4..6], 0x1234u16.to_be_bytes());
        assert_eq!(h[6], 2);
    }

    #[test]
    fn wrap_original_layout() {
        let p = wrap_original(&[0xAA, 0xBB]);
        assert_eq!(p[0..4], PROTOCOL_ID.to_be_bytes());
        assert_eq!(p[4..6], PEER_ID_SERVER.to_be_bytes());
        assert_eq!(p[6], 0);
        assert_eq!(p[7], PacketType::Original as u8);
        assert_eq!(&p[8..], &[0xAA, 0xBB]);
    }

    #[test]
    fn wrap_reliable_layout() {
        let p = wrap_reliable(0x00FF, &[0x01, 0x02]);
        assert_eq!(p[0..4], PROTOCOL_ID.to_be_bytes());
        assert_eq!(p[4..6], PEER_ID_SERVER.to_be_bytes());
        assert_eq!(p[6], 0);
        assert_eq!(p[7], PacketType::Reliable as u8);
        assert_eq!(p[8..10], 0x00FFu16.to_be_bytes());
        assert_eq!(&p[10..], &[0x01, 0x02]);
    }

    #[test]
    fn control_ack_layout() {
        let p = build_control_ack(0x0042);
        assert_eq!(p[7], PacketType::Control as u8);
        assert_eq!(p[8], ControlType::Ack as u8);
        assert_eq!(p[9..11], 0x0042u16.to_be_bytes());
    }

    #[test]
    fn set_peer_id_layout() {
        let p = build_set_peer_id(0xABCD);
        assert_eq!(p[7], PacketType::Control as u8);
        assert_eq!(p[8], ControlType::SetPeerId as u8);
        assert_eq!(p[9..11], 0xABCDu16.to_be_bytes());
    }

    #[test]
    fn hex_preview_truncates() {
        let s = hex_preview(&[0xde, 0xad, 0xbe, 0xef], 2);
        assert_eq!(s, "dead…(+2B)");
    }
}
