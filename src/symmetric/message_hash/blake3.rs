//! BLAKE3 XOF message hashing into uniformly distributed encoding chunks.

use std::{convert::Infallible, sync::LazyLock};

use super::MessageHash;
use crate::{HASH_LENGTH, MESSAGE_LENGTH};

const MESSAGE_HASH_CONTEXT: &str = "leansig 2026-08-17 message hash v1";
static MESSAGE_HASHER: LazyLock<blake3::Hasher> =
    LazyLock::new(|| blake3::Hasher::new_derive_key(MESSAGE_HASH_CONTEXT));

/// A BLAKE3 message hash with `DIMENSION` independent uniform chunks in `0..BASE`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3MessageHash<const DIMENSION: usize, const BASE: usize>;

impl<const DIMENSION: usize, const BASE: usize> MessageHash for Blake3MessageHash<DIMENSION, BASE> {
    type Parameter = [u8; HASH_LENGTH];
    type Randomness = [u8; HASH_LENGTH];
    type Error = Infallible;

    const DIMENSION: usize = DIMENSION;
    const BASE: usize = BASE;

    fn rand<R: rand::RngExt + rand::CryptoRng>(rng: &mut R) -> Self::Randomness {
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

        // Deriving a BLAKE3 context hashes the context string. Clone the immutable
        // initialized state so hot-path calls only process the actual transcript.
        let mut hasher = (*MESSAGE_HASHER).clone();
        hasher.update(parameter);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(randomness);
        hasher.update(message);
        let mut reader = hasher.finalize_xof();

        let mut chunks = Vec::with_capacity(DIMENSION);
        let mut block = [0u8; 64];

        if BASE.is_power_of_two() {
            // Consume every XOF bit for power-of-two alphabets. Disjoint groups of
            // uniform bits are independent uniform chunks and require no rejection.
            let bits_per_chunk = BASE.ilog2() as usize;
            let mask = (BASE - 1) as u16;
            let mut reservoir = 0u16;
            let mut available_bits = 0usize;
            while chunks.len() < DIMENSION {
                reader.fill(&mut block);
                for byte in block {
                    reservoir |= u16::from(byte) << available_bits;
                    available_bits += 8;
                    while available_bits >= bits_per_chunk {
                        chunks.push((reservoir & mask) as u8);
                        if chunks.len() == DIMENSION {
                            break;
                        }
                        reservoir >>= bits_per_chunk;
                        available_bits -= bits_per_chunk;
                    }
                    if chunks.len() == DIMENSION {
                        break;
                    }
                }
            }
        } else {
            // Rejection sampling avoids modulo bias for other bases.
            let acceptance_limit = 256 - (256 % BASE);
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

    #[test]
    fn power_of_two_base_uses_uniform_bit_chunks() {
        type Hash = Blake3MessageHash<257, 2>;
        let chunks = Hash::apply(
            &[1u8; HASH_LENGTH],
            4,
            &[2u8; HASH_LENGTH],
            &[3u8; MESSAGE_LENGTH],
        )
        .unwrap();
        assert_eq!(chunks.len(), 257);
        assert!(chunks.iter().all(|chunk| *chunk <= 1));
        assert!(chunks.contains(&0));
        assert!(chunks.contains(&1));
    }
}
