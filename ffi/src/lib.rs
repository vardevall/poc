//! C interface of the vardevall engine for the Apple apps (`include/vardevall.h`).

#![warn(missing_docs)]

mod abi;
mod host;
mod iface;

#[cfg(test)]
mod header;
