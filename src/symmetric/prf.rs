use rand::{CryptoRng, RngExt};

use crate::serialization::Serializable;

use crate::MESSAGE_LENGTH;

/// Pseudorandom functions used by the signer.
pub trait Pseudorandom {
    type Key: Send + Sync + Serializable;
    type Domain;
    type Randomness;

    /// Samples a PRF key.
    fn key_gen<R: RngExt + CryptoRng>(rng: &mut R) -> Self::Key;

    /// Derives a hash-chain start.
    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain;

    /// Derives deterministic encoding randomness.
    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness;
}

pub mod blake3;
