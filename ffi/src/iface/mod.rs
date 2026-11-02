//! Lookup of the network interface that holds an address.

use std::ffi::CStr;
use std::net::Ipv6Addr;
use std::ptr;

/// The name of the interface that has `addr` assigned.
pub fn holding(addr: Ipv6Addr) -> Option<String> {
    let mut list: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `list` is a valid out-pointer; the list is freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list returned by `getifaddrs`.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null and points to a sockaddr.
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET6 {
            continue;
        }
        // SAFETY: the family is AF_INET6, so the address is a `sockaddr_in6`.
        let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        if Ipv6Addr::from(sin6.sin6_addr.s6_addr) == addr {
            // SAFETY: `ifa_name` is a NUL-terminated string.
            found = Some(
                unsafe { CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned(),
            );
            break;
        }
    }
    // SAFETY: `list` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(list) };
    found
}
