//! Handshake wire formats: messages, fragments and cookie replies (vv-02 §3, §5).

use crate::error::ParseError;
use crate::keys::crypto::{self, TAG_LEN, XNONCE_LEN};

/// Length of mac1 and mac2.
pub const MAC_LEN: usize = 16;
/// Fragment type byte of message 1, fragment 0 (vv-02 §5.1).
pub const TYPE_MSG1_FRAG0: u8 = 4;
/// Fragment type byte of message 1, fragment 1.
pub const TYPE_MSG1_FRAG1: u8 = 5;
/// Fragment type byte of message 2, fragment 0.
pub const TYPE_MSG2_FRAG0: u8 = 6;
/// Fragment type byte of message 2, fragment 1.
pub const TYPE_MSG2_FRAG1: u8 = 7;
/// Type byte of a cookie reply (vv-02 §3.4).
pub const TYPE_COOKIE: u8 = 8;
/// Type byte of a data frame (vv-03 §3.1).
pub const TYPE_DATA: u8 = 9;
/// Type byte of an unfragmented message 1 (vv-02 §1).
pub const TYPE_MSG1: u8 = 10;
/// Type byte of an unfragmented message 2 (vv-02 §1).
pub const TYPE_MSG2: u8 = 11;

/// Message bytes carried by fragment 0 (vv-02 §5.1).
pub const FRAGMENT_DATA: usize = 1160;
/// Largest fragment (vv-02 §5.1).
pub const MAX_FRAGMENT: usize = 1200;
/// Fragment header: type, reserved and sender index.
pub const FRAGMENT_HEADER: usize = 8;
/// Size of a cookie reply (vv-02 §3.4).
pub const COOKIE_REPLY_LEN: usize = 80;
/// Smallest message 1: sender index, Noise message with empty payload, mac1.
pub const MIN_MESSAGE1: usize = 4 + crate::handshake::noise::NOISE1_OVERHEAD + MAC_LEN;
/// Smallest message 2.
pub const MIN_MESSAGE2: usize = 8 + crate::handshake::noise::NOISE2_OVERHEAD + MAC_LEN;
/// Largest message of either kind that fits two fragments.
pub const MAX_MESSAGE: usize = 2 * FRAGMENT_DATA;

/// Which handshake message a fragment belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageNumber {
    /// Message 1.
    One,
    /// Message 2.
    Two,
}

/// Message 1 bytes: `sender_index ‖ noise1 ‖ mac1` (vv-02 §3.1).
pub fn build_message1(sender_index: u32, noise1: &[u8], mac1_key: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + noise1.len() + MAC_LEN);
    m.extend_from_slice(&sender_index.to_le_bytes());
    m.extend_from_slice(noise1);
    let mac1: [u8; MAC_LEN] = crypto::mac(mac1_key, &[&m]);
    m.extend_from_slice(&mac1);
    m
}

/// Message 2 bytes: `sender_index ‖ receiver_index ‖ noise2 ‖ mac1` (vv-02 §3.2).
pub fn build_message2(
    sender_index: u32,
    receiver_index: u32,
    noise2: &[u8],
    mac1_key: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + noise2.len() + MAC_LEN);
    m.extend_from_slice(&sender_index.to_le_bytes());
    m.extend_from_slice(&receiver_index.to_le_bytes());
    m.extend_from_slice(noise2);
    let mac1: [u8; MAC_LEN] = crypto::mac(mac1_key, &[&m]);
    m.extend_from_slice(&mac1);
    m
}

/// Checks the trailing mac1 of a whole message or of a fragment's first part (vv-02 §4.1).
pub fn verify_mac1(bytes_with_mac1_last: &[u8], mac1_key: &[u8; 32]) -> bool {
    let Some(split) = bytes_with_mac1_last.len().checked_sub(MAC_LEN) else {
        return false;
    };
    let (body, mac) = bytes_with_mac1_last.split_at(split);
    let expect: [u8; MAC_LEN] = crypto::mac(mac1_key, &[body]);
    crypto::ct_eq(&expect, mac)
}

/// The parts of a message 1.
#[derive(Debug, Clone, Copy)]
pub struct Message1<'a> {
    /// The initiator's index.
    pub sender_index: u32,
    /// The Noise message.
    pub noise1: &'a [u8],
}

/// The parts of a message 2.
#[derive(Debug, Clone, Copy)]
pub struct Message2<'a> {
    /// The responder's index.
    pub sender_index: u32,
    /// The index of message 1's sender.
    pub receiver_index: u32,
    /// The Noise message.
    pub noise2: &'a [u8],
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Splits a message 1; does not check mac1.
pub fn parse_message1(msg: &[u8]) -> Result<Message1<'_>, ParseError> {
    if !(MIN_MESSAGE1..=MAX_MESSAGE).contains(&msg.len()) {
        return Err(ParseError::Length);
    }
    Ok(Message1 {
        sender_index: le32(msg),
        noise1: &msg[4..msg.len() - MAC_LEN],
    })
}

/// Splits a message 2; does not check mac1.
pub fn parse_message2(msg: &[u8]) -> Result<Message2<'_>, ParseError> {
    if !(MIN_MESSAGE2..=MAX_MESSAGE).contains(&msg.len()) {
        return Err(ParseError::Length);
    }
    Ok(Message2 {
        sender_index: le32(msg),
        receiver_index: le32(&msg[4..]),
        noise2: &msg[8..msg.len() - MAC_LEN],
    })
}

/// Splits `message` into its two fragments (vv-02 §5.1), with mac2 from `cookie` if present.
pub fn fragment_message(
    message: &[u8],
    message_number: MessageNumber,
    sender_index: u32,
    mac1_key: &[u8; 32],
    cookie: Option<&[u8; 32]>,
) -> Result<[Vec<u8>; 2], ParseError> {
    if message.len() <= FRAGMENT_DATA || message.len() > MAX_MESSAGE {
        return Err(ParseError::Length);
    }
    let first_type = match message_number {
        MessageNumber::One => TYPE_MSG1_FRAG0,
        MessageNumber::Two => TYPE_MSG2_FRAG0,
    };
    let (a, b) = message.split_at(FRAGMENT_DATA);
    Ok([
        build_fragment(first_type, sender_index, a, mac1_key, cookie),
        build_fragment(first_type + 1, sender_index, b, mac1_key, cookie),
    ])
}

fn build_fragment(
    msg_type: u8,
    sender_index: u32,
    data: &[u8],
    mac1_key: &[u8; 32],
    cookie: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAGMENT_HEADER + data.len() + 2 * MAC_LEN);
    f.extend_from_slice(&[msg_type, 0, 0, 0]);
    f.extend_from_slice(&sender_index.to_le_bytes());
    f.extend_from_slice(data);
    let mac1: [u8; MAC_LEN] = crypto::mac(mac1_key, &[&f]);
    f.extend_from_slice(&mac1);
    let mac2: [u8; MAC_LEN] = match cookie {
        Some(c) => crypto::mac(c, &[&f]),
        None => [0; MAC_LEN],
    };
    f.extend_from_slice(&mac2);
    f
}

/// A parsed handshake fragment.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    /// Message 1 or 2.
    pub message_number: MessageNumber,
    /// 0 or 1.
    pub index: u8,
    /// The message's sender index.
    pub sender_index: u32,
    /// Message bytes carried.
    pub data: &'a [u8],
    /// Bytes before mac1, for mac1 verification.
    pub signed: &'a [u8],
    /// The fragment's mac1.
    pub mac1: [u8; MAC_LEN],
    /// Bytes before mac2, which cover mac1.
    pub signed_with_mac1: &'a [u8],
    /// The fragment's mac2.
    pub mac2: [u8; MAC_LEN],
}

/// Parses a type 4–7 fragment; checks length bounds but no MAC (vv-02 §5.1).
pub fn parse_fragment(buf: &[u8]) -> Result<Fragment<'_>, ParseError> {
    if buf.len() < FRAGMENT_HEADER + 1 + 2 * MAC_LEN || buf.len() > MAX_FRAGMENT {
        return Err(ParseError::Length);
    }
    let (message_number, index) = match buf[0] {
        TYPE_MSG1_FRAG0 => (MessageNumber::One, 0),
        TYPE_MSG1_FRAG1 => (MessageNumber::One, 1),
        TYPE_MSG2_FRAG0 => (MessageNumber::Two, 0),
        TYPE_MSG2_FRAG1 => (MessageNumber::Two, 1),
        _ => return Err(ParseError::Type),
    };
    let data_end = buf.len() - 2 * MAC_LEN;
    let data = &buf[FRAGMENT_HEADER..data_end];
    if (index == 0 && data.len() != FRAGMENT_DATA) || data.len() > FRAGMENT_DATA {
        return Err(ParseError::Length);
    }
    let mut mac1 = [0u8; MAC_LEN];
    mac1.copy_from_slice(&buf[data_end..data_end + MAC_LEN]);
    let mut mac2 = [0u8; MAC_LEN];
    mac2.copy_from_slice(&buf[data_end + MAC_LEN..]);
    Ok(Fragment {
        message_number,
        index,
        sender_index: le32(&buf[4..]),
        data,
        signed: &buf[..data_end],
        mac1,
        signed_with_mac1: &buf[..data_end + MAC_LEN],
        mac2,
    })
}

impl Fragment<'_> {
    /// Verifies mac1 against the key of the receiving node (vv-02 §4.1).
    pub fn mac1_valid(&self, mac1_key: &[u8; 32]) -> bool {
        let expect: [u8; MAC_LEN] = crypto::mac(mac1_key, &[self.signed]);
        crypto::ct_eq(&expect, &self.mac1)
    }

    /// Verifies mac2 against `cookie` (vv-02 §4.2).
    pub fn mac2_valid(&self, cookie: &[u8; 32]) -> bool {
        let expect: [u8; MAC_LEN] = crypto::mac(cookie, &[self.signed_with_mac1]);
        crypto::ct_eq(&expect, &self.mac2)
    }
}

/// Builds a cookie reply (vv-02 §3.4); `trigger_mac1` is the answered fragment's mac1.
pub fn build_cookie_reply(
    receiver_index: u32,
    nonce: &[u8; XNONCE_LEN],
    cookie_key: &[u8; 32],
    cookie: &[u8; 32],
    trigger_mac1: &[u8; MAC_LEN],
) -> [u8; COOKIE_REPLY_LEN] {
    let mut out = [0u8; COOKIE_REPLY_LEN];
    out[0] = TYPE_COOKIE;
    out[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    out[8..32].copy_from_slice(nonce);
    let sealed = crypto::xaead_seal(cookie_key, nonce, trigger_mac1, cookie);
    debug_assert_eq!(sealed.len(), 32 + TAG_LEN);
    out[32..].copy_from_slice(&sealed);
    out
}

/// The receiver index and parts of a cookie reply.
#[derive(Debug, Clone, Copy)]
pub struct CookieReply<'a> {
    /// The `sender_index` of the answered fragments.
    pub receiver_index: u32,
    /// The XAEAD nonce.
    pub nonce: [u8; XNONCE_LEN],
    /// The encrypted cookie with its tag.
    pub sealed: &'a [u8],
}

/// Parses a cookie reply.
pub fn parse_cookie_reply(buf: &[u8]) -> Result<CookieReply<'_>, ParseError> {
    if buf.len() != COOKIE_REPLY_LEN {
        return Err(ParseError::Length);
    }
    if buf[0] != TYPE_COOKIE {
        return Err(ParseError::Type);
    }
    let mut nonce = [0u8; XNONCE_LEN];
    nonce.copy_from_slice(&buf[8..32]);
    Ok(CookieReply {
        receiver_index: le32(&buf[4..]),
        nonce,
        sealed: &buf[32..],
    })
}

impl CookieReply<'_> {
    /// Opens the cookie with the mac1 of a fragment that was sent (vv-02 §4.2).
    pub fn open(&self, cookie_key: &[u8; 32], fragment_mac1: &[u8; MAC_LEN]) -> Option<[u8; 32]> {
        crypto::xaead_open(cookie_key, &self.nonce, fragment_mac1, self.sealed)
            .ok()
            .and_then(|v| v.try_into().ok())
    }
}
