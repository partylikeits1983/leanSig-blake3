use rand::{CryptoRng, RngExt};
use std::fmt::Debug;

use crate::MESSAGE_LENGTH;
use crate::serialization::Serializable;

/// Maps messages to fixed-length, pairwise-incomparable codewords.
pub trait IncomparableEncoding {
    type Parameter: Serializable;
    type Randomness: Serializable;
    type Error: Debug;

    /// Number of codeword entries.
    const DIMENSION: usize;

    /// Maximum encoding attempts.
    const MAX_TRIES: usize;

    /// Codeword alphabet size. Entries lie in `0..BASE` and fit in `u8`.
    const BASE: usize;

    /// Samples encoding randomness.
    fn rand<R: RngExt + CryptoRng>(rng: &mut R) -> Self::Randomness;

    /// Encodes a message, or returns an error when the code constraint is not met.
    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub mod target_sum;
