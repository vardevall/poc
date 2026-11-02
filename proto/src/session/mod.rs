//! One transport session: keys, counters and expiry (vv-02 §6, vv-03 §3).

pub mod replay;

use std::time::Duration;

use zeroize::Zeroizing;

use crate::handshake::SessionKeys;
use crate::ip::exit::ExitOffer;
use crate::plane::frame;
use crate::session::replay::{REJECT_AFTER_MESSAGES, ReplayWindow};
use crate::time::Instant;

/// `REKEY_AFTER_MESSAGES` (vv-02 §6.4).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// `REKEY_AFTER_TIME` (vv-02 §6.4).
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// `REJECT_AFTER_TIME` (vv-02 §6.4).
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// `REKEY_ATTEMPT_TIME` (vv-02 §6.4).
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Base of `REKEY_TIMEOUT` (vv-02 §6.4).
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound of the per-attempt jitter, in milliseconds (vv-02 §6.4).
pub const REKEY_JITTER_MAX_MS: u64 = 333;
/// Default `KEEPALIVE_TIMEOUT` (vv-02 §6.4).
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// An established session with one peer.
pub struct Session {
    pub(crate) local_index: u32,
    pub(crate) remote_index: u32,
    pub(crate) initiator: bool,
    pub(crate) created: Instant,
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_counter: u64,
    pub(crate) window: ReplayWindow,
    /// The exit offer of the handshake that made the session.
    pub(crate) offer: Option<ExitOffer>,
}

impl Session {
    pub(crate) fn new(
        keys: &SessionKeys,
        initiator: bool,
        local_index: u32,
        remote_index: u32,
        now: Instant,
    ) -> Self {
        let (send_key, recv_key) = if initiator {
            (keys.frame_i2r(), keys.frame_r2i())
        } else {
            (keys.frame_r2i(), keys.frame_i2r())
        };
        Session {
            local_index,
            remote_index,
            initiator,
            created: now,
            send_key,
            recv_key,
            send_counter: 0,
            window: ReplayWindow::new(),
            offer: None,
        }
    }

    /// Whether this node initiated the handshake.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    pub(crate) fn expired(&self, now: Instant) -> bool {
        now >= self.created + REJECT_AFTER_TIME
    }

    pub(crate) fn expires_at(&self) -> Instant {
        self.created + REJECT_AFTER_TIME
    }

    pub(crate) fn can_send(&self, now: Instant) -> bool {
        !self.expired(now) && self.send_counter < REJECT_AFTER_MESSAGES
    }

    pub(crate) fn send_counter(&self) -> u64 {
        self.send_counter
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> (u64, Vec<u8>) {
        let counter = self.send_counter;
        let frame = frame::seal(&self.send_key, self.remote_index, counter, plaintext);
        self.send_counter += 1;
        (counter, frame)
    }

    pub(crate) fn open(
        &self,
        header: &frame::FrameHeader,
        frame: &[u8],
    ) -> Result<Vec<u8>, crate::error::CryptoError> {
        frame::open_parsed(&self.recv_key, header, frame)
    }

    /// Opens a frame this session sealed.
    #[cfg(feature = "sim")]
    pub(crate) fn open_sent(&self, header: &frame::FrameHeader, frame: &[u8]) -> Option<Vec<u8>> {
        (header.receiver_index == self.remote_index)
            .then(|| frame::open_parsed(&self.send_key, header, frame).ok())
            .flatten()
    }
}
