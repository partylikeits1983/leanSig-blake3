use std::fmt::Debug;

use rand::{CryptoRng, RngExt};

use crate::MESSAGE_LENGTH;
use crate::serialization::Serializable;

/// Hashes messages into encoding chunks.
pub trait MessageHash {
    type Parameter: Clone + Serializable;
    type Randomness: Serializable;
    type Error: Debug;

    /// Number of output chunks.
    const DIMENSION: usize;

    /// Output alphabet size. Must fit in `u8`.
    const BASE: usize;

    /// Samples encoding randomness.
    fn rand<R: RngExt + CryptoRng>(rng: &mut R) -> Self::Randomness;

    /// Returns `DIMENSION` chunks in `0..BASE`.
    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, Self::Error>;
}

pub mod blake3;
