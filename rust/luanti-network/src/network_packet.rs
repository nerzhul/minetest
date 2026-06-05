//! `NetworkPacket` — direct port of the C++ `NetworkPacket` class from
//! `src/network/networkpacket.{h,cpp}`.
//!
//! A `NetworkPacket` carries a Luanti command opcode plus a payload
//! buffer. It exposes sequential `read_*` / `write_*` helpers that
//! maintain a single cursor (`read_pos` in the C++ code,
//! `m_read_offset`), so the wire format is described in one place and
//! is impossible to desync from the actual byte stream.
//!
//! This is the canonical type used by both the server's command
//! handler and the C++ client/server. Layout on the wire is:
//!
//! ```text
//! [0..2]  u16  command (big-endian)
//! [2..]   std::string / primitive payloads (u16-length-prefixed strings)
//! ```

use thiserror::Error;

const STRING_MAX_LEN: usize = 0xFFFF;
const LONG_STRING_MAX_LEN: usize = 0xFFFF_FFFF;

/// Errors that can occur while reading a [`NetworkPacket`].
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("reading outside packet (offset: {offset}, packet size: {size}, needed {needed})")]
    OutOfBounds {
        offset: usize,
        size: usize,
        needed: usize,
    },

    #[error("string too long: {got} bytes, max {max}")]
    StringTooLong { got: usize, max: usize },

    #[error("string is not valid UTF-8")]
    InvalidUtf8,

    #[error("wstring is not valid UTF-16")]
    InvalidUtf16,

    #[error("packet is too short to contain a command ({size} bytes)")]
    PacketTooShort { size: usize },
}

pub type PacketResult<T> = Result<T, PacketError>;

/// Luanti network packet, mirrors the C++ `NetworkPacket` class.
#[derive(Debug, Clone)]
pub struct NetworkPacket {
    command: u16,
    data: Vec<u8>,
    read_pos: usize,
    peer_id: u16,
}

impl Default for NetworkPacket {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl NetworkPacket {
    // --- Constructors ----------------------------------------------------

    /// Build an empty packet carrying the given command. The peer id
    /// defaults to 0 and can be set later via [`Self::set_peer_id`].
    pub fn new(command: u16, preallocate: usize) -> Self {
        Self {
            command,
            data: Vec::with_capacity(preallocate),
            read_pos: 0,
            peer_id: 0,
        }
    }

    /// Same as [`Self::new`] but also stores the peer id this packet is
    /// being sent to / was received from.
    pub fn with_peer_id(command: u16, preallocate: usize, peer_id: u16) -> Self {
        let mut p = Self::new(command, preallocate);
        p.peer_id = peer_id;
        p
    }

    /// Decode a raw on-the-wire buffer into a `NetworkPacket`.
    ///
    /// The first two bytes are the command, the rest is the payload.
    /// The internal read cursor is left at 0, so callers can use
    /// `read_*` methods to walk the payload.
    pub fn from_raw(data: &[u8], peer_id: u16) -> PacketResult<Self> {
        if data.len() < 2 {
            return Err(PacketError::PacketTooShort { size: data.len() });
        }
        let command = u16::from_be_bytes([data[0], data[1]]);
        let mut p = Self::with_peer_id(command, data.len().saturating_sub(2), peer_id);
        if data.len() > 2 {
            p.data.extend_from_slice(&data[2..]);
        }
        Ok(p)
    }

    // --- Getters ----------------------------------------------------------

    pub fn command(&self) -> u16 {
        self.command
    }

    pub fn set_command(&mut self, command: u16) {
        self.command = command;
    }

    pub fn peer_id(&self) -> u16 {
        self.peer_id
    }

    pub fn set_peer_id(&mut self, peer_id: u16) {
        self.peer_id = peer_id;
    }

    /// Number of payload bytes (excluding the 2-byte command header).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Number of unread payload bytes remaining.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.read_pos)
    }

    pub fn read_pos(&self) -> usize {
        self.read_pos
    }

    pub fn set_read_pos(&mut self, pos: usize) {
        self.read_pos = pos.min(self.data.len());
    }

    /// Borrow the underlying payload buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Borrow the unread tail of the payload.
    pub fn rest(&self) -> &[u8] {
        &self.data[self.read_pos..]
    }

    /// Reset all state. After this, the packet has command 0, peer_id 0,
    /// no payload, and the cursor at 0.
    pub fn clear(&mut self) {
        self.command = 0;
        self.data.clear();
        self.read_pos = 0;
        self.peer_id = 0;
    }

    /// Encode the packet back to the on-the-wire representation
    /// (`command || payload`).
    pub fn into_raw_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&self.command.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Append raw bytes to the payload, advancing the write cursor
    /// (which is the same as the read cursor in the C++ class).
    pub fn put_raw(&mut self, src: &[u8]) {
        self.data.extend_from_slice(src);
    }

    // --- Read helpers -----------------------------------------------------

    fn check_read(&self, needed: usize) -> PacketResult<()> {
        let avail = self.remaining();
        if avail < needed {
            return Err(PacketError::OutOfBounds {
                offset: self.read_pos,
                size: self.data.len(),
                needed,
            });
        }
        Ok(())
    }

    /// Skip `count` bytes ahead in the payload.
    pub fn skip(&mut self, count: usize) -> PacketResult<()> {
        self.check_read(count)?;
        self.read_pos += count;
        Ok(())
    }

    pub fn read_u8(&mut self) -> PacketResult<u8> {
        self.check_read(1)?;
        let v = self.data[self.read_pos];
        self.read_pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> PacketResult<u16> {
        self.check_read(2)?;
        let v = u16::from_be_bytes([self.data[self.read_pos], self.data[self.read_pos + 1]]);
        self.read_pos += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> PacketResult<u32> {
        self.check_read(4)?;
        let v = u32::from_be_bytes([
            self.data[self.read_pos],
            self.data[self.read_pos + 1],
            self.data[self.read_pos + 2],
            self.data[self.read_pos + 3],
        ]);
        self.read_pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> PacketResult<u64> {
        self.check_read(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.read_pos..self.read_pos + 8]);
        self.read_pos += 8;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_i16(&mut self) -> PacketResult<i16> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_i32(&mut self) -> PacketResult<i32> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_f32(&mut self) -> PacketResult<f32> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    /// Read a `std::string` (u16 length + raw bytes).
    pub fn read_string(&mut self) -> PacketResult<Vec<u8>> {
        let len = self.read_u16()? as usize;
        self.check_read(len)?;
        let v = self.data[self.read_pos..self.read_pos + len].to_vec();
        self.read_pos += len;
        Ok(v)
    }

    /// Read a `std::string` and decode as UTF-8.
    pub fn read_utf8(&mut self) -> PacketResult<String> {
        let bytes = self.read_string()?;
        String::from_utf8(bytes).map_err(|_| PacketError::InvalidUtf8)
    }

    /// Read a long string (u32 length + bytes) used for media data.
    pub fn read_long_string(&mut self) -> PacketResult<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.check_read(len)?;
        let v = self.data[self.read_pos..self.read_pos + len].to_vec();
        self.read_pos += len;
        Ok(v)
    }

    /// Read a `wstring` (u16 length + UTF-16 code units).
    pub fn read_wstring(&mut self) -> PacketResult<String> {
        let len = self.read_u16()? as usize;
        self.check_read(len * 2)?;
        let mut chars = Vec::with_capacity(len);
        for i in 0..len {
            let off = self.read_pos + i * 2;
            let cu = u16::from_be_bytes([self.data[off], self.data[off + 1]]);
            chars.push(cu);
        }
        self.read_pos += len * 2;
        String::from_utf16(&chars).map_err(|_| PacketError::InvalidUtf16)
    }

    pub fn read_v2s16(&mut self) -> PacketResult<(i16, i16)> {
        Ok((self.read_i16()?, self.read_i16()?))
    }

    pub fn read_v2f32(&mut self) -> PacketResult<(f32, f32)> {
        Ok((self.read_f32()?, self.read_f32()?))
    }

    pub fn read_v3s16(&mut self) -> PacketResult<(i16, i16, i16)> {
        Ok((self.read_i16()?, self.read_i16()?, self.read_i16()?))
    }

    pub fn read_v3s32(&mut self) -> PacketResult<(i32, i32, i32)> {
        Ok((self.read_i32()?, self.read_i32()?, self.read_i32()?))
    }

    pub fn read_v3f(&mut self) -> PacketResult<(f32, f32, f32)> {
        Ok((self.read_f32()?, self.read_f32()?, self.read_f32()?))
    }

    // --- Write helpers ----------------------------------------------------

    pub fn write_u8(&mut self, v: u8) {
        self.data.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_i16(&mut self, v: i16) {
        self.write_u16(v as u16);
    }

    pub fn write_i32(&mut self, v: i32) {
        self.write_u32(v as u32);
    }

    pub fn write_f32(&mut self, v: f32) {
        self.write_u32(v.to_bits());
    }

    /// Write a `std::string` (u16 length + raw bytes).
    pub fn write_string(&mut self, s: &[u8]) {
        debug_assert!(s.len() <= STRING_MAX_LEN, "string too long for u16 length");
        self.write_u16(s.len() as u16);
        self.data.extend_from_slice(s);
    }

    /// Write a UTF-8 `&str` as a `std::string`.
    pub fn write_utf8(&mut self, s: &str) {
        self.write_string(s.as_bytes());
    }

    /// Write a `wstring` (u16 length + UTF-16 code units).
    pub fn write_wstring(&mut self, s: &str) {
        let chars: Vec<u16> = s.encode_utf16().collect();
        debug_assert!(chars.len() <= STRING_MAX_LEN, "wstring too long for u16 length");
        self.write_u16(chars.len() as u16);
        for c in chars {
            self.write_u16(c);
        }
    }

    /// Write a long string (u32 length + bytes) used for media data.
    pub fn write_long_string(&mut self, s: &[u8]) {
        debug_assert!(
            s.len() <= LONG_STRING_MAX_LEN,
            "long string too long for u32 length"
        );
        self.write_u32(s.len() as u32);
        self.data.extend_from_slice(s);
    }

    pub fn write_v2f32(&mut self, x: f32, y: f32) {
        self.write_f32(x);
        self.write_f32(y);
    }

    pub fn write_v3f(&mut self, x: f32, y: f32, z: f32) {
        self.write_f32(x);
        self.write_f32(y);
        self.write_f32(z);
    }

    pub fn write_v3s16(&mut self, x: i16, y: i16, z: i16) {
        self.write_i16(x);
        self.write_i16(y);
        self.write_i16(z);
    }

    pub fn write_v3s32(&mut self, x: i32, y: i32, z: i32) {
        self.write_i32(x);
        self.write_i32(y);
        self.write_i32(z);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8_u16_u32_u64() {
        let mut p = NetworkPacket::new(0x0002, 0);
        p.write_u8(0x42);
        p.write_u16(0xCAFE);
        p.write_u32(0xDEAD_BEEF);
        p.write_u64(0x0102_0304_0506_0708);
        p.set_read_pos(0);
        assert_eq!(p.read_u8().unwrap(), 0x42);
        assert_eq!(p.read_u16().unwrap(), 0xCAFE);
        assert_eq!(p.read_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(p.read_u64().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn roundtrip_string_and_wstring() {
        let mut p = NetworkPacket::new(0, 0);
        p.write_utf8("héllo");
        p.write_wstring("wörld");
        p.set_read_pos(0);
        assert_eq!(p.read_utf8().unwrap(), "héllo");
        assert_eq!(p.read_wstring().unwrap(), "wörld");
    }

    #[test]
    fn from_raw_recovers_command() {
        let raw = [0x00u8, 0x02, 0x01, 0x02, 0x03];
        let p = NetworkPacket::from_raw(&raw, 7).unwrap();
        assert_eq!(p.command(), 0x0002);
        assert_eq!(p.peer_id(), 7);
        assert_eq!(p.as_slice(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn from_raw_rejects_short_input() {
        let raw = [0x00u8];
        assert!(NetworkPacket::from_raw(&raw, 0).is_err());
    }

    #[test]
    fn into_raw_bytes_roundtrips() {
        let mut p = NetworkPacket::new(0x0043, 0);
        p.write_u16(0x1234);
        p.write_utf8("hi");
        let bytes = p.into_raw_bytes();
        assert_eq!(bytes, vec![0x00, 0x43, 0x12, 0x34, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn read_oob_errors() {
        let mut p = NetworkPacket::new(0, 0);
        p.write_u8(1);
        p.set_read_pos(0);
        assert!(p.read_u16().is_err());
    }
}
