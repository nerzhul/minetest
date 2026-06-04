//! Wire-format (de)serialization for the Luanti MTP protocol
//!
//! Luanti's on-wire integers are big-endian and strings are encoded as a
//! `u16` length followed by the raw bytes (no terminator). This module
//! provides type-safe reader and writer types that wrap a `&[u8]` slice
//! or a `Vec<u8>` and panic / return errors on malformed input.
//!
//! Most Luanti commands also accept strings in the wider `wstring` form
//! (UTF-16, `u16` length + chars). Those helpers are also provided.

use std::io::Cursor;

/// Errors returned by the wire-format readers.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("unexpected end of input: needed {needed} bytes, only {available} available")]
    UnexpectedEof { needed: usize, available: usize },

    #[error("string is not valid UTF-8")]
    InvalidUtf8,

    #[error("payload too long: {got} bytes, max {max}")]
    PayloadTooLong { got: usize, max: usize },
}

pub type WireResult<T> = Result<T, WireError>;

/// Reader over a `&[u8]`.
#[derive(Debug, Clone)]
pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the unread portion of the buffer.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn ensure(&self, n: usize) -> WireResult<()> {
        let avail = self.remaining();
        if avail < n {
            return Err(WireError::UnexpectedEof {
                needed: n,
                available: avail,
            });
        }
        Ok(())
    }

    pub fn read_u8(&mut self) -> WireResult<u8> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> WireResult<u16> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> WireResult<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> WireResult<u64> {
        self.ensure(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_i16(&mut self) -> WireResult<i16> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_i32(&mut self) -> WireResult<i32> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_f32(&mut self) -> WireResult<f32> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    pub fn read_f1000(&mut self) -> WireResult<f32> {
        Ok(self.read_u16()? as f32 / 1000.0)
    }

    /// Read a `std::string` (u16 length + bytes).
    pub fn read_string(&mut self) -> WireResult<Vec<u8>> {
        let len = self.read_u16()? as usize;
        self.ensure(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// Read a long string (u32 length + bytes), used for media data.
    pub fn read_long_string(&mut self) -> WireResult<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.ensure(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// Read raw bytes of the given length (no length prefix).
    pub fn read_raw(&mut self, len: usize) -> WireResult<Vec<u8>> {
        self.ensure(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// Read a `std::string` and decode as UTF-8.
    pub fn read_utf8(&mut self) -> WireResult<String> {
        let bytes = self.read_string()?;
        String::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8)
    }

    /// Read a `wstring` (u16 length + UTF-16 code units).
    pub fn read_wstring(&mut self) -> WireResult<String> {
        let len = self.read_u16()? as usize;
        self.ensure(len * 2)?;
        let mut chars = Vec::with_capacity(len);
        for i in 0..len {
            let off = self.pos + i * 2;
            let cu = u16::from_be_bytes([self.data[off], self.data[off + 1]]);
            chars.push(cu);
        }
        self.pos += len * 2;
        String::from_utf16(&chars).map_err(|_| WireError::InvalidUtf8)
    }

    /// Read a v3s32 (12 bytes, three i32s).
    pub fn read_v3s32(&mut self) -> WireResult<(i32, i32, i32)> {
        Ok((self.read_i32()?, self.read_i32()?, self.read_i32()?))
    }

    /// Read a v3f (12 bytes, three f32s).
    pub fn read_v3f(&mut self) -> WireResult<(f32, f32, f32)> {
        Ok((self.read_f32()?, self.read_f32()?, self.read_f32()?))
    }

    /// Read a v2s16 (4 bytes, two i16s).
    pub fn read_v2s16(&mut self) -> WireResult<(i16, i16)> {
        Ok((self.read_i16()?, self.read_i16()?))
    }

    /// Read a v2f32 (8 bytes, two f32s).
    pub fn read_v2f32(&mut self) -> WireResult<(f32, f32)> {
        Ok((self.read_f32()?, self.read_f32()?))
    }
}

/// Writer that appends to a `Vec<u8>`.
#[derive(Debug)]
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
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

    /// Write `seconds * 1000` as a `u16` (f1000 encoding used in some
    /// fields such as `TOCLIENT_AUTH_ACCEPT`).
    pub fn write_f1000(&mut self, seconds: f32) {
        self.write_u16((seconds * 1000.0).round() as u16);
    }

    /// Write a Luanti `std::string` (u16 length + bytes).
    pub fn write_string(&mut self, s: &[u8]) {
        self.write_u16(s.len() as u16);
        self.buf.extend_from_slice(s);
    }

    /// Write raw bytes without any length prefix.
    pub fn write_string_raw(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
    }

    /// Write a 32-bit length followed by raw bytes (used for media file data).
    pub fn write_long_string(&mut self, s: &[u8]) {
        self.write_u32(s.len() as u32);
        self.write_string_raw(s);
    }

    /// Write a `std::string` from a Rust `&str` (UTF-8 bytes).
    pub fn write_utf8(&mut self, s: &str) {
        self.write_string(s.as_bytes());
    }

    /// Write a `wstring` (u16 length + UTF-16 code units).
    pub fn write_wstring(&mut self, s: &str) {
        let chars: Vec<u16> = s.encode_utf16().collect();
        self.write_u16(chars.len() as u16);
        for c in chars {
            self.write_u16(c);
        }
    }

    pub fn write_v3s32(&mut self, x: i32, y: i32, z: i32) {
        self.write_i32(x);
        self.write_i32(y);
        self.write_i32(z);
    }

    pub fn write_v3f(&mut self, x: f32, y: f32, z: f32) {
        self.write_f32(x);
        self.write_f32(y);
        self.write_f32(z);
    }

    pub fn write_v2s16(&mut self, x: i16, y: i16) {
        self.write_i16(x);
        self.write_i16(y);
    }

    pub fn write_v2f32(&mut self, x: f32, y: f32) {
        self.write_f32(x);
        self.write_f32(y);
    }
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

// --- Cursor-based convenience (for use on owned Vec<u8> buffers) -----------

/// Read a `u16` from the front of `data` and return both the value and
/// the remaining data. Returns `None` if the input is too short.
pub fn read_u16_at(data: &[u8], offset: usize) -> Option<(u16, usize)> {
    if data.len() < offset + 2 {
        return None;
    }
    let v = u16::from_be_bytes([data[offset], data[offset + 1]]);
    Some((v, offset + 2))
}

/// Decode a Luanti `std::string` (u16 length + bytes) from a `Cursor`.
/// Returns `None` if the cursor doesn't hold a full string.
pub fn try_read_string(cursor: &mut Cursor<&[u8]>) -> Option<Vec<u8>> {
    use std::io::Read;
    let pos = cursor.position() as usize;
    let slice = cursor.get_ref();
    if slice.len() < pos + 2 {
        return None;
    }
    let len = u16::from_be_bytes([slice[pos], slice[pos + 1]]) as usize;
    if slice.len() < pos + 2 + len {
        return None;
    }
    let value = slice[pos + 2..pos + 2 + len].to_vec();
    cursor.set_position((pos + 2 + len) as u64);
    let _ = cursor.read(&mut []); // touch
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u8_u16_u32_u64() {
        let bytes = [0x01u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0x04];
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_u16().unwrap(), 0x0002);
        assert_eq!(r.read_u32().unwrap(), 0x0000_0003);
        assert_eq!(r.read_u64().unwrap(), 0x0000_0000_0000_0004);
        assert!(r.is_empty());
    }

    #[test]
    fn read_truncated_u16_errors() {
        let bytes = [0x00u8];
        let mut r = WireReader::new(&bytes);
        let err = r.read_u16().unwrap_err();
        matches!(err, WireError::UnexpectedEof { .. });
    }

    #[test]
    fn read_string_roundtrip() {
        let mut w = WireWriter::new();
        w.write_string(b"hello");
        let mut r = WireReader::new(w.as_slice());
        assert_eq!(r.read_string().unwrap(), b"hello");
        assert!(r.is_empty());
    }

    #[test]
    fn read_wstring_roundtrip() {
        let mut w = WireWriter::new();
        w.write_wstring("héllo");
        let mut r = WireReader::new(w.as_slice());
        assert_eq!(r.read_wstring().unwrap(), "héllo");
        assert!(r.is_empty());
    }

    #[test]
    fn read_string_truncated() {
        // length says 5 but only 3 bytes follow
        let bytes = [0x00u8, 0x05, b'a', b'b', b'c'];
        let mut r = WireReader::new(&bytes);
        let err = r.read_string().unwrap_err();
        matches!(err, WireError::UnexpectedEof { .. });
    }

    #[test]
    fn writer_helpers() {
        let mut w = WireWriter::new();
        w.write_u8(0x42);
        w.write_u16(0x1234);
        w.write_u32(0xDEAD_BEEF);
        w.write_u64(0x0102_0304_0506_0708);
        w.write_f32(1.5);
        w.write_f1000(0.1);
        w.write_v3f(1.0, 2.0, 3.0);
        w.write_string(b"hi");
        w.write_wstring("yo");
        assert_eq!(
            w.as_slice(),
            &[
                0x42, //
                0x12, 0x34, //
                0xDE, 0xAD, 0xBE, 0xEF, //
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
                0x3F, 0xC0, 0x00, 0x00, // 1.5f
                0x00, 0x64, // f1000(0.1) = 100
                0x3F, 0x80, 0x00, 0x00, // 1.0
                0x40, 0x00, 0x00, 0x00, // 2.0
                0x40, 0x40, 0x00, 0x00, // 3.0
                0x00, 0x02, b'h', b'i', //
                0x00, 0x02, 0x00, b'y', 0x00, b'o', // "yo" in UTF-16 BE
            ][..]
        );
    }

    #[test]
    fn read_v3f_and_back() {
        let mut w = WireWriter::new();
        w.write_v3f(1.5, -2.25, 3.125);
        let mut r = WireReader::new(w.as_slice());
        let (x, y, z) = r.read_v3f().unwrap();
        assert_eq!(x, 1.5);
        assert_eq!(y, -2.25);
        assert_eq!(z, 3.125);
    }

    #[test]
    fn read_invalid_utf8_errors() {
        let mut w = WireWriter::new();
        w.write_string(&[0xFF, 0xFE, 0xFD]);
        let mut r = WireReader::new(w.as_slice());
        let err = r.read_utf8().unwrap_err();
        matches!(err, WireError::InvalidUtf8);
    }

    #[test]
    fn read_u16_at_works() {
        let data = [0xAAu8, 0xBB, 0xCC];
        let (v, new_pos) = read_u16_at(&data, 0).unwrap();
        assert_eq!(v, 0xAABB);
        assert_eq!(new_pos, 2);
        assert!(read_u16_at(&data, 2).is_none());
    }
}
