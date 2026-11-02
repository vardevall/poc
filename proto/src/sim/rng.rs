//! A seeded, deterministic RNG for simulations.

/// SplitMix64. Marked cryptographic so `Node` accepts it; it is not, and exists only so that a
/// simulation repeats exactly for a given seed.
#[derive(Debug, Clone)]
pub struct SimRng(u64);

impl SimRng {
    /// A generator whose output is fixed by `seed`.
    pub const fn new(seed: u64) -> Self {
        SimRng(seed)
    }

    /// An independent generator derived from this one.
    pub fn fork(&mut self) -> SimRng {
        SimRng(self.next())
    }

    /// A value in `0..n`; `n` must not be zero.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl rand_core::TryRng for SimRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok((self.next() >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SimRng {}
