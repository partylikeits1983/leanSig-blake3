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

    /// Derives four independent hash-chain starts for SIMD-friendly callers.
    fn get_domain_elements_4(key: &Self::Key, epochs: [u32; 4], index: u64) -> [Self::Domain; 4] {
        epochs.map(|epoch| Self::get_domain_element(key, epoch, index))
    }

    /// Derives deterministic encoding randomness.
    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness;
}

pub mod blake3;
