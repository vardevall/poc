//! Operating-system randomness for the core.

use rand_core::UnwrapErr;

pub use getrandom::SysRng;

/// The system generator as the core takes it: it panics if the system cannot provide
/// randomness, as continuing would weaken the keys.
pub type OsRng = UnwrapErr<SysRng>;

/// A generator backed by the operating system.
pub fn os_rng() -> OsRng {
    UnwrapErr(SysRng)
}
