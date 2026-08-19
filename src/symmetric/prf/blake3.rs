//! BLAKE3-based pseudorandom functions used by LeanSig.

use super::Pseudorandom;
use crate::{HASH_LENGTH, MESSAGE_LENGTH, symmetric::tweak_hash::blake3_simd::keyed_hash_4};

const CHAIN_START_TAG: &[u8] = b"leansig-v1/prf-chain-start";
const SIGNING_RANDOMNESS_TAG: &[u8] = b"leansig-v1/prf-signing-randomness";

/// Keyed BLAKE3 PRF for one-time-secret generation and deterministic signing randomness.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Prf;

impl Pseudorandom for Blake3Prf {
    type Key = [u8; HASH_LENGTH];
    type Domain = [u8; HASH_LENGTH];
    type Randomness = [u8; HASH_LENGTH];

    fn key_gen<R: rand::RngExt + rand::CryptoRng>(rng: &mut R) -> Self::Key {
        rng.random()
    }

    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(CHAIN_START_TAG);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&index.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn get_domain_elements_4(key: &Self::Key, epochs: [u32; 4], index: u64) -> [Self::Domain; 4] {
        const INPUT_LEN: usize = CHAIN_START_TAG.len() + size_of::<u32>() + size_of::<u64>();
        let inputs: [[u8; INPUT_LEN]; 4] = core::array::from_fn(|lane| {
            let mut input = [0; INPUT_LEN];
            let epoch_start = CHAIN_START_TAG.len();
            let index_start = epoch_start + size_of::<u32>();
            input[..epoch_start].copy_from_slice(CHAIN_START_TAG);
            input[epoch_start..index_start].copy_from_slice(&epochs[lane].to_le_bytes());
            input[index_start..].copy_from_slice(&index.to_le_bytes());
            input
        });
        keyed_hash_4(key, &inputs)
    }

    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(SIGNING_RANDOMNESS_TAG);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(message);
        hasher.update(&counter.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_deterministic_and_separated() {
        let key = [7u8; HASH_LENGTH];
        let message = [9u8; MESSAGE_LENGTH];

        let chain = Blake3Prf::get_domain_element(&key, 3, 4);
        assert_eq!(
            chain,
            [
                32, 218, 144, 129, 118, 17, 106, 65, 19, 162, 247, 228, 198, 2, 64, 89, 134, 144,
                192, 54, 27, 162, 204, 206, 143, 110, 102, 104, 126, 89, 128, 233,
            ]
        );
        assert_eq!(chain, Blake3Prf::get_domain_element(&key, 3, 4));
        assert_ne!(chain, Blake3Prf::get_domain_element(&key, 3, 5));

        let rho = Blake3Prf::get_randomness(&key, 3, &message, 4);
        assert_eq!(
            rho,
            [
                237, 23, 122, 244, 23, 242, 56, 163, 59, 240, 132, 71, 68, 254, 73, 116, 94, 104,
                5, 163, 225, 79, 141, 216, 247, 123, 225, 189, 36, 136, 85, 51,
            ]
        );
        assert_eq!(rho, Blake3Prf::get_randomness(&key, 3, &message, 4));
        assert_ne!(rho, Blake3Prf::get_randomness(&key, 3, &message, 5));
        assert_ne!(chain, rho);
    }

    #[test]
    fn batched_domains_match_scalar() {
        let key = [17u8; HASH_LENGTH];
        let epochs = [0, 1, 123_456, u32::MAX];

        for index in [0, 1, u64::from(u32::MAX), u64::MAX] {
            let batched = Blake3Prf::get_domain_elements_4(&key, epochs, index);
            let scalar = epochs.map(|epoch| Blake3Prf::get_domain_element(&key, epoch, index));
            assert_eq!(batched, scalar);
        }
    }
}
