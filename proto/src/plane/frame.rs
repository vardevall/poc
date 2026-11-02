//! Socket demultiplexing and data frames (vv-03 §2, §3).

use crate::error::{CryptoError, ParseError};
use crate::handshake::message::TYPE_DATA;
use crate::keys::crypto::{self, TAG_LEN};

/// Header size of a data frame: type, reserved, receiver index and counter (vv-03 §3.1).
pub const FRAME_HEADER: usize = 16;
/// Per-frame overhead: header and tag.
pub const FRAME_OVERHEAD: usize = FRAME_HEADER + TAG_LEN;
/// The default interface MTU (vv-03 §3.4).
pub const DEFAULT_MTU: usize = 1280;
/// Plaintext padding granularity (vv-03 §3.2).
pub const PADDING_BLOCK: usize = 16;

/// How a datagram on the shared socket is handled (vv-03 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// STUN or TURN control.
    StunTurn,
    /// A handshake fragment.
    HandshakeFragment,
    /// A cookie reply.
    CookieReply,
    /// A data frame.
    DataFrame,
    /// An unfragmented message 1 or 2; valid only from a switch.
    SwitchHandshake,
    /// TURN ChannelData.
    TurnChannelData,
    /// Not for this node.
    Drop,
}

/// Classifies a datagram received on the UDP socket by its first byte (vv-03 §2.1).
pub fn classify(first_byte: u8, from_turn_server_with_allocation: bool) -> Class {
    match first_byte {
        0..=3 => Class::StunTurn,
        4..=7 => Class::HandshakeFragment,
        8 => Class::CookieReply,
        9 => Class::DataFrame,
        64..=79 if from_turn_server_with_allocation => Class::TurnChannelData,
        10..=255 => Class::Drop,
    }
}

/// Classifies a datagram delivered by a switch (vv-04 §6): messages 10 and 11 are valid there.
pub fn classify_forwarded(first_byte: u8) -> Class {
    match first_byte {
        10 | 11 => Class::SwitchHandshake,
        b => classify(b, false),
    }
}

/// The addressing fields of a data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The receiver's index for the session.
    pub receiver_index: u32,
    /// The per-direction counter, also the nonce.
    pub counter: u64,
}

/// Parses the header of a type 9 frame without decrypting.
pub fn parse_header(frame: &[u8]) -> Result<FrameHeader, ParseError> {
    if frame.len() < FRAME_OVERHEAD {
        return Err(ParseError::Length);
    }
    if frame[0] != TYPE_DATA {
        return Err(ParseError::Type);
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(&frame[8..16]);
    Ok(FrameHeader {
        receiver_index: u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]),
        counter: u64::from_le_bytes(c),
    })
}

/// Encrypts `plaintext` into a data frame (vv-03 §3.1).
pub fn seal(key: &[u8; 32], receiver_index: u32, counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_OVERHEAD + plaintext.len());
    f.extend_from_slice(&[TYPE_DATA, 0, 0, 0]);
    f.extend_from_slice(&receiver_index.to_le_bytes());
    f.extend_from_slice(&counter.to_le_bytes());
    f.extend_from_slice(&crypto::aead_seal(key, counter, &[], plaintext));
    f
}

/// Decrypts the payload of a frame, parsing its header first.
pub fn open(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let header = parse_header(frame).map_err(|_| CryptoError::Authentication)?;
    open_parsed(key, &header, frame)
}

/// Decrypts the payload of `frame`, whose header [`parse_header`] returned as `header`.
pub fn open_parsed(
    key: &[u8; 32],
    header: &FrameHeader,
    frame: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let body = frame
        .get(FRAME_HEADER..)
        .ok_or(CryptoError::Authentication)?;
    crypto::aead_open(key, header.counter, &[], body)
}

/// Pads an IP packet with zeros to a multiple of 16 bytes, never beyond `mtu` (vv-03 §3.2).
pub fn pad(packet: &[u8], mtu: usize) -> Vec<u8> {
    let target = packet
        .len()
        .next_multiple_of(PADDING_BLOCK)
        .min(mtu)
        .max(packet.len());
    let mut v = Vec::with_capacity(target);
    v.extend_from_slice(packet);
    v.resize(target, 0);
    v
}

/// Strips padding using the packet's length field and returns the packet (vv-03 §3.2): the
/// payload length of IPv6, or the total length of IPv4, which the exit carries.
pub fn unpad(plaintext: &[u8]) -> Result<&[u8], ParseError> {
    let total = match plaintext.first().map(|b| b >> 4) {
        Some(6) if plaintext.len() >= 40 => {
            40 + usize::from(u16::from_be_bytes([plaintext[4], plaintext[5]]))
        }
        Some(4) if plaintext.len() >= 20 => {
            let total = usize::from(u16::from_be_bytes([plaintext[2], plaintext[3]]));
            if total < 20 {
                return Err(ParseError::Field);
            }
            total
        }
        _ => return Err(ParseError::Field),
    };
    if total > plaintext.len() {
        return Err(ParseError::Length);
    }
    Ok(&plaintext[..total])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_outside_the_handled_classes_are_dropped() {
        for b in 10..=255u8 {
            let turn = classify(b, true);
            let plain = classify(b, false);
            if (64..=79).contains(&b) {
                assert_eq!(turn, Class::TurnChannelData);
            } else {
                assert_eq!(turn, Class::Drop, "{b}");
            }
            assert_eq!(plain, Class::Drop, "{b}");
        }
    }

    #[test]
    fn padding_rules() {
        assert_eq!(pad(&[1; 58], 1280).len(), 64);
        assert_eq!(pad(&[1; 64], 1280).len(), 64);
        assert_eq!(pad(&[1; 1410], 1420).len(), 1420);
        assert_eq!(pad(&[1; 1280], 1280).len(), 1280);
        assert_eq!(pad(&[], 1280).len(), 0);
    }

    #[test]
    fn unpad_rejects_malformed() {
        assert!(unpad(&[0u8; 39]).is_err());
        let mut p = [0u8; 48];
        p[0] = 0x60;
        p[5] = 9;
        assert!(unpad(&p).is_err());
        p[5] = 8;
        assert_eq!(unpad(&p).unwrap().len(), 48);
        p[0] = 0x40;
        assert!(unpad(&p).is_err());
    }

    #[test]
    fn an_ipv4_packet_unpads_to_its_total_length() {
        let mut p = [0u8; 48];
        p[0] = 0x45;
        p[3] = 28;
        p[12..16].copy_from_slice(&[198, 18, 0, 7]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let packet = unpad(&p).unwrap();
        assert_eq!(packet.len(), 28);
        p[3] = 49;
        assert!(unpad(&p).is_err());
        p[3] = 19;
        assert!(unpad(&p).is_err());
    }
}
