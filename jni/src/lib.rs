//! JNI interface of the vardevall engine for the Android app.
//!
//! `android/app/src/main/kotlin/dev/vardevall/Native.kt` is the authoritative interface, as
//! `apple/include/vardevall.h` is for the Apple apps; the functions of [`native`] mirror the header
//! over `vardevall-tun`'s embedding API, with the same JSON documents and events. The packets
//! of the `VpnService` interface are read and written here.

#![warn(missing_docs)]

mod bridge;
mod engine;
mod native;
mod resolvers;
mod tunfd;

#[cfg(test)]
mod pipeline;
#[cfg(test)]
mod symbols;
