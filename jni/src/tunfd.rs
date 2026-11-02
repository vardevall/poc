//! The file descriptor of the `VpnService` interface: one `read` is one packet and one `write`
//! is one packet. Packets are read and written here, not in Kotlin.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::unix::AsyncFd;
use vardevall_tun::embed::Networks;

/// Most packets handed to the engine in one call.
const BATCH: usize = 32;
/// Room for the largest packet the kernel gives in one read.
const PACKET_MAX: usize = 65_535;

/// A tunnel descriptor, non-blocking.
pub struct TunFd {
    fd: OwnedFd,
}

impl TunFd {
    /// Takes ownership of `fd` and makes it non-blocking.
    pub fn new(fd: OwnedFd) -> io::Result<TunFd> {
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is the open descriptor `fd` owns for the duration of both calls.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        // SAFETY: as above.
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TunFd { fd })
    }

    /// Writes one packet; a full queue or a closed interface loses it, as a full link would.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: the descriptor is open while `self` lives and `packet` is readable for its length.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the descriptor is open while `self` lives and `buf` is writable for its length.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    /// The name of the interface the descriptor is the end of, such as `tun0`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn interface_name(&self) -> Option<String> {
        const TUNGETIFF: u32 = 0x8004_54d2;
        let mut request = [0u8; 40];
        // SAFETY: `TUNGETIFF` fills a `struct ifreq` of 40 bytes, which `request` has room for.
        let r = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                TUNGETIFF as _,
                request.as_mut_ptr().cast::<libc::c_void>(),
            )
        };
        if r < 0 {
            return None;
        }
        let name = &request[..libc::IFNAMSIZ];
        let end = name.iter().position(|&b| b == 0)?;
        String::from_utf8(name[..end].to_vec()).ok()
    }

    /// The name of the interface the descriptor is the end of; only a tunnel of Linux has one.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn interface_name(&self) -> Option<String> {
        None
    }
}

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// The descriptor packets are written to; replaced when the interface is built again.
#[derive(Default)]
pub struct TunSlot(Mutex<Option<Arc<TunFd>>>);

impl TunSlot {
    /// Makes `tun` the interface and returns the one it replaced.
    pub fn replace(&self, tun: Arc<TunFd>) -> Option<Arc<TunFd>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(tun)
    }

    /// Writes the packets of the engine, in order; they are lost while there is no interface.
    pub fn write(&self, packets: &[&[u8]]) {
        let Some(tun) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        for packet in packets {
            let _ = tun.write_packet(packet);
        }
    }
}

struct Registered(Arc<TunFd>);

impl AsRawFd for Registered {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Reads packets from `tun` and hands them to `networks`, a batch at a time, until the interface
/// is closed or fails.
pub async fn read_loop(tun: Arc<TunFd>, networks: Arc<Networks>) -> io::Result<()> {
    // SAFETY: `Registered` keeps the descriptor open, at the same number, for as long as the
    // `AsyncFd` holds it.
    let ready = unsafe { AsyncFd::register(Registered(tun))? };
    let mut scratch = vec![0u8; PACKET_MAX];
    loop {
        let mut guard = ready.readable().await?;
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(BATCH);
        while batch.len() < BATCH {
            match guard.try_io(|fd| fd.get_ref().0.read_packet(&mut scratch)) {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => batch.push(scratch[..n].to_vec()),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => break,
            }
        }
        networks.packets_in(batch.iter().map(Vec::as_slice));
    }
}
