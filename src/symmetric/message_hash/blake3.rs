//! BLAKE3 XOF message hashing into uniformly distributed encoding chunks.

use std::convert::Infallible;

use super::MessageHash;
use crate::{HASH_LENGTH, MESSAGE_LENGTH};

const MESSAGE_HASH_CONTEXT: &str = "leansig 2026-08-17 message hash v1";

/// A BLAKE3 message hash with `DIMENSION` independent uniform chunks in `0..BASE`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3MessageHash<const DIMENSION: usize, const BASE: usize>;

impl<const DIMENSION: usize, const BASE: usize> MessageHash for Blake3MessageHash<DIMENSION, BASE> {
    type Parameter = [u8; HASH_LENGTH];
    type Randomness = [u8; HASH_LENGTH];
    type Error = Infallible;

    const DIMENSION: usize = DIMENSION;
    const BASE: usize = BASE;

    fn rand<R: rand::RngExt>(rng: &mut R) -> Self::Randomness {
        rng.random()
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, Self::Error> {
        const {
            assert!(BASE >= 2, "BLAKE3 message hash base must be at least 2");
            assert!(BASE <= 256, "BLAKE3 message hash base must fit in u8");
            assert!(
                DIMENSION >= 1,
                "BLAKE3 message hash dimension must be non-zero"
            );
        }

        let mut hasher = blake3::Hasher::new_derive_key(MESSAGE_HASH_CONTEXT);
        hasher.update(parameter);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(randomness);
        hasher.update(message);
        let mut reader = hasher.finalize_xof();

        // Rejection sampling avoids modulo bias for non-power-of-two bases.
        let acceptance_limit = 256 - (256 % BASE);
        let mut chunks = Vec::with_capacity(DIMENSION);
        let mut block = [0u8; 64];
        while chunks.len() < DIMENSION {
            reader.fill(&mut block);
            for byte in block {
                if usize::from(byte) < acceptance_limit {
                    chunks.push((usize::from(byte) % BASE) as u8);
                    if chunks.len() == DIMENSION {
                        break;
                    }
                }
            }
        }

        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_deterministic_bounded_and_domain_separated() {
        type Hash = Blake3MessageHash<257, 7>;
        let parameter = [1u8; HASH_LENGTH];
        let randomness = [2u8; HASH_LENGTH];
        let message = [3u8; MESSAGE_LENGTH];

        let a = Hash::apply(&parameter, 4, &randomness, &message).unwrap();
        assert_eq!(&a[..16], &[5, 4, 4, 6, 5, 0, 3, 4, 4, 6, 4, 0, 5, 1, 2, 5]);
        let b = Hash::apply(&parameter, 4, &randomness, &message).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 257);
        assert!(a.iter().all(|chunk| *chunk < 7));
        assert_ne!(
            a,
            Hash::apply(&parameter, 5, &randomness, &message).unwrap()
        );
    }
}
