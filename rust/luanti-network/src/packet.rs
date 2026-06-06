// Packet structures and utilities

use std::collections::HashMap;

use crate::protocol::*;

/// Represents a buffered packet with metadata
#[derive(Debug, Clone)]
pub struct BufferedPacket {
    pub data: Vec<u8>,
    pub seqnum: Option<u16>,
    pub resend_count: u32,
}

impl BufferedPacket {
    pub fn new(data: Vec<u8>) -> Self {
        BufferedPacket {
            data,
            seqnum: None,
            resend_count: 0,
        }
    }

    pub fn get_seqnum(&self) -> Option<u16> {
        self.seqnum
    }

    pub fn set_sender_peer_id(&mut self, id: u16) {
        if self.data.len() >= 6 {
            let bytes = id.to_be_bytes();
            self.data[4] = bytes[0];
            self.data[5] = bytes[1];
        }
    }
}

/// Handles split packet reassembly
#[derive(Debug)]
pub struct IncomingSplitPacket {
    pub chunk_count: u16,
    pub chunks: HashMap<u16, Vec<u8>>,
    pub reliable: bool,
}

impl IncomingSplitPacket {
    pub fn new(chunk_count: u16, reliable: bool) -> Self {
        IncomingSplitPacket {
            chunk_count,
            chunks: HashMap::new(),
            reliable,
        }
    }

    pub fn insert(&mut self, chunk_num: u16, data: Vec<u8>) -> bool {
        if chunk_num >= self.chunk_count {
            return false;
        }
        self.chunks.insert(chunk_num, data);
        self.is_complete()
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.len() == self.chunk_count as usize
    }

    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut result = Vec::new();
        for i in 0..self.chunk_count {
            if let Some(chunk) = self.chunks.get(&i) {
                result.extend_from_slice(chunk);
            } else {
                return None;
            }
        }

        Some(result)
    }
}

/// Create a base packet with header
pub fn make_packet(protocol_id: u32, sender_peer_id: u16, channel: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(BASE_HEADER_SIZE + data.len());
    packet.extend_from_slice(&protocol_id.to_be_bytes());
    packet.extend_from_slice(&sender_peer_id.to_be_bytes());
    packet.push(channel);
    packet.extend_from_slice(data);
    packet
}

/// Create a reliable packet wrapper
pub fn make_reliable_packet(data: &[u8], seqnum: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(RELIABLE_HEADER_SIZE + data.len());
    packet.push(PacketType::Reliable as u8);
    packet.extend_from_slice(&seqnum.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Split data into chunks for split packets
pub fn make_auto_split_packet(
    data: &[u8],
    chunksize_max: usize,
    split_seqnum: &mut u16,
) -> Vec<Vec<u8>> {
    if data.len() <= chunksize_max {
        // No need to split, return as original packet
        let mut packet = vec![PacketType::Original as u8];
        packet.extend_from_slice(data);
        return vec![packet];
    }

    // Calculate number of chunks needed
    let chunk_count = ((data.len() + chunksize_max - 1) / chunksize_max) as u16;
    let seqnum = *split_seqnum;
    *split_seqnum = if *split_seqnum == SEQNUM_MAX {
        0
    } else {
        *split_seqnum + 1
    };

    let mut packets = Vec::new();

    for chunk_num in 0..chunk_count {
        let start = (chunk_num as usize) * chunksize_max;
        let end = std::cmp::min(start + chunksize_max, data.len());
        let chunk_data = &data[start..end];

        let mut packet = Vec::with_capacity(7 + chunk_data.len());
        packet.push(PacketType::Split as u8);
        packet.extend_from_slice(&seqnum.to_be_bytes());
        packet.extend_from_slice(&chunk_count.to_be_bytes());
        packet.extend_from_slice(&chunk_num.to_be_bytes());
        packet.extend_from_slice(chunk_data);

        packets.push(packet);
    }

    packets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_packet() {
        let data = b"Hello, World!";
        let packet = make_packet(PROTOCOL_ID, 123, 0, data);

        assert_eq!(packet.len(), BASE_HEADER_SIZE + data.len());
        assert_eq!(&packet[0..4], &PROTOCOL_ID.to_be_bytes());
        assert_eq!(&packet[4..6], &123u16.to_be_bytes());
        assert_eq!(packet[6], 0);
        assert_eq!(&packet[7..], data);
    }

    #[test]
    fn test_split_packet() {
        let mut split_seqnum = 0;
        let data = vec![0u8; 1000];
        let packets = make_auto_split_packet(&data, 400, &mut split_seqnum);

        assert_eq!(packets.len(), 3);
        assert_eq!(split_seqnum, 1);
    }

    #[test]
    fn test_incoming_split_packet() {
        let mut incoming = IncomingSplitPacket::new(3, false);

        assert!(!incoming.is_complete());

        incoming.insert(0, vec![1, 2, 3]);
        assert!(!incoming.is_complete());

        incoming.insert(1, vec![4, 5, 6]);
        assert!(!incoming.is_complete());

        incoming.insert(2, vec![7, 8, 9]);
        assert!(incoming.is_complete());

        let reassembled = incoming.reassemble().unwrap();
        assert_eq!(reassembled, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
