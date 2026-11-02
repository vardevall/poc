//! The tunnel device: `utun` on macOS, `/dev/net/tun` on Linux.
//!
//! This is the only module of the crate that uses `unsafe`; every block is a direct system call
//! on a descriptor this module owns.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A layer-3 tunnel device carrying IPv6 and IPv4 packets, told apart by the first nibble
///.
pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    /// The interface name, such as `utun4` or `home`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IP packet into `buf`, blocking; returns its length.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        read_packet(&self.fd, buf)
    }

    /// Writes one IP packet.
    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        write_packet(&self.fd, packet)
    }
}

/// The address family of the packet, from its version nibble.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn family(packet: &[u8]) -> libc::c_int {
    if packet.first().is_some_and(|b| b >> 4 == 4) {
        libc::AF_INET
    } else {
        libc::AF_INET6
    }
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use super::*;

    const HEADER: usize = 4;

    pub(super) fn create(_hint: &str) -> io::Result<Tun> {
        // SAFETY: plain socket(2); the result is checked and wrapped in an OwnedFd below.
        let raw = cvt(unsafe {
            libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
        })?;
        // SAFETY: `raw` is a freshly created descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: ctl_info is plain old data for which all-zero is a valid value.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let name = b"com.apple.net.utun_control";
        for (d, s) in info.ctl_name.iter_mut().zip(name) {
            *d = *s as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO reads and writes one ctl_info, which `info` is.
        cvt(unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) })?;

        // SAFETY: sockaddr_ctl is plain old data for which all-zero is a valid value.
        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0;
        // SAFETY: `addr` is a valid sockaddr_ctl of the stated length.
        cvt(unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        })?;

        let mut ifname = [0u8; 64];
        let mut len = ifname.len() as libc::socklen_t;
        // SAFETY: the option writes at most `len` bytes into `ifname` and updates `len`.
        cvt(unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname.as_mut_ptr().cast(),
                &mut len,
            )
        })?;
        let end = ifname.iter().position(|b| *b == 0).unwrap_or(ifname.len());
        let name = String::from_utf8_lossy(&ifname[..end]).into_owned();
        Ok(Tun { fd, name })
    }

    pub(super) fn read_packet(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        let mut tmp = vec![0u8; buf.len() + HEADER];
        loop {
            // SAFETY: reads at most `tmp.len()` bytes into `tmp`.
            let n = unsafe { libc::read(fd.as_raw_fd(), tmp.as_mut_ptr().cast(), tmp.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            if n <= HEADER {
                continue;
            }
            buf[..n - HEADER].copy_from_slice(&tmp[HEADER..n]);
            return Ok(n - HEADER);
        }
    }

    pub(super) fn write_packet(fd: &OwnedFd, packet: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(packet.len() + HEADER);
        out.extend_from_slice(&(family(packet) as u32).to_be_bytes());
        out.extend_from_slice(packet);
        // SAFETY: writes `out.len()` bytes from `out`.
        cvt(unsafe { libc::write(fd.as_raw_fd(), out.as_ptr().cast(), out.len()) } as libc::c_int)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [u8; libc::IFNAMSIZ],
        flags: libc::c_short,
        pad: [u8; 22],
    }

    pub(super) fn create(hint: &str) -> io::Result<Tun> {
        let path = b"/dev/net/tun\0";
        // SAFETY: `path` is NUL-terminated; the result is checked and wrapped in an OwnedFd.
        let raw = cvt(unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) })?;
        // SAFETY: `raw` is a freshly opened descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            pad: [0; 22],
        };
        let bytes = hint.as_bytes();
        let n = bytes.len().min(libc::IFNAMSIZ - 1);
        req.name[..n].copy_from_slice(&bytes[..n]);
        // SAFETY: TUNSETIFF reads one ifreq, which `req` is, and writes the final name into it.
        cvt(unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req) })?;
        let end = req
            .name
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(req.name.len());
        let name = String::from_utf8_lossy(&req.name[..end]).into_owned();
        Ok(Tun { fd, name })
    }

    pub(super) fn read_packet(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: reads at most `buf.len()` bytes into `buf`.
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }

    pub(super) fn write_packet(fd: &OwnedFd, packet: &[u8]) -> io::Result<()> {
        // SAFETY: writes `packet.len()` bytes from `packet`.
        cvt(
            unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) }
                as libc::c_int,
        )?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod sys {
    use super::*;

    pub(super) fn create(_hint: &str) -> io::Result<Tun> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no tunnel device on this platform",
        ))
    }
    pub(super) fn read_packet(_: &OwnedFd, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub(super) fn write_packet(_: &OwnedFd, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

use sys::{read_packet, write_packet};

impl Tun {
    /// Creates a tunnel device. Linux uses `name_hint` as the interface name; macOS numbers it.
    pub fn create(name_hint: &str) -> io::Result<Tun> {
        sys::create(name_hint)
    }
}

#[cfg(test)]
mod tests {
    use super::family;

    #[test]
    fn the_first_nibble_tells_the_family() {
        assert_eq!(family(&[0x45, 0, 0]), libc::AF_INET);
        assert_eq!(family(&[0x60, 0, 0]), libc::AF_INET6);
        assert_eq!(family(&[]), libc::AF_INET6);
    }
}
