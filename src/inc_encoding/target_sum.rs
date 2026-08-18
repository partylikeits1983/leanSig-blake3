use super::IncomparableEncoding;
use crate::{MESSAGE_LENGTH, symmetric::message_hash::MessageHash};
use std::fmt::Debug;
use thiserror::Error;

/// Target-sum encoding errors.
#[derive(Debug, Error)]
pub enum TargetSumError<E> {
    /// The chunks do not sum to `TARGET_SUM`.
    #[error("Target sum mismatch: expected {expected}, but got {actual}.")]
    Mismatch { expected: usize, actual: usize },

    /// Message hashing failed.
    #[error("Hash error: {0:?}")]
    HashError(E),
}

/// Accepts message-hash outputs whose entries sum to `TARGET_SUM`.
///
/// A target near `MH::DIMENSION * (MH::BASE - 1) / 2` gives the highest
/// acceptance rate.
#[derive(Clone)]
pub struct TargetSumEncoding<MH: MessageHash, const TARGET_SUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const TARGET_SUM: usize> IncomparableEncoding
    for TargetSumEncoding<MH, TARGET_SUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    type Error = TargetSumError<MH::Error>;

    const DIMENSION: usize = MH::DIMENSION;

    /// Limit for deterministic randomness retries during signing.
    const MAX_TRIES: usize = 100_000;

    const BASE: usize = MH::BASE;

    fn rand<R: rand::RngExt + rand::CryptoRng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        const {
            // Chain indexes, positions, and codeword entries are encoded as u8.
            assert!(
                MH::BASE <= 1 << 8,
                "Target Sum Encoding: Base must be at most 2^8"
            );
            assert!(
                MH::DIMENSION <= 1 << 8,
                "Target Sum Encoding: Dimension must be at most 2^8"
            );

            assert!(
                MH::BASE >= 2,
                "Target Sum Encoding: Base must be at least 2"
            );

            assert!(
                TARGET_SUM <= MH::DIMENSION * (MH::BASE - 1),
                "Target Sum Encoding: TARGET_SUM must be at most DIMENSION * (BASE - 1)"
            );
        }

        let chunks =
            MH::apply(parameter, epoch, randomness, message).map_err(TargetSumError::HashError)?;
        let sum: u32 = chunks.iter().map(|&x| x as u32).sum();
        if sum as usize == TARGET_SUM {
            Ok(chunks)
        } else {
            Err(TargetSumError::Mismatch {
                expected: TARGET_SUM,
                actual: sum as usize,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::message_hash::blake3::Blake3MessageHash;
    use proptest::prelude::*;
    use rand::RngExt;

    const TEST_TARGET_SUM: usize = 192;
    type TestMessageHash = Blake3MessageHash<128, 4>;
    type TestTargetSumEncoding = TargetSumEncoding<TestMessageHash, TEST_TARGET_SUM>;

    #[test]
    fn test_successful_encoding_fixed_message() {
        let mut rng = rand::rng();
        let parameter = rng.random();
        let message: [u8; 32] = rng.random();
        let epoch = 0u32;

        for _ in 0..1_000 {
            let randomness = TestTargetSumEncoding::rand(&mut rng);

            if let Ok(chunks) =
                TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch)
            {
                assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);

                for &chunk in &chunks {
                    assert!((chunk as usize) < TestTargetSumEncoding::BASE);
                }

                let sum: usize = chunks.iter().map(|&x| x as usize).sum();
                assert_eq!(sum, TEST_TARGET_SUM);

                let result2 =
                    TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
                assert_eq!(chunks, result2.unwrap());

                return;
            }
        }

        panic!("failed to find successful encoding after 1000 attempts");
    }

    #[test]
    fn test_successful_encoding_random_inputs() {
        let mut rng = rand::rng();
        let epoch = 0u32;

        for _ in 0..1_000 {
            let parameter = rng.random();
            let message: [u8; 32] = rng.random();
            let randomness = TestTargetSumEncoding::rand(&mut rng);

            if let Ok(chunks) =
                TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch)
            {
                assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);

                for &chunk in &chunks {
                    assert!((chunk as usize) < TestTargetSumEncoding::BASE);
                }

                let sum: usize = chunks.iter().map(|&x| x as usize).sum();
                assert_eq!(sum, TEST_TARGET_SUM);

                let result2 =
                    TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
                assert_eq!(chunks, result2.unwrap());

                return;
            }
        }

        panic!("failed to find successful encoding after 1000 attempts");
    }

    proptest! {
        #[test]
        fn proptest_encoding_determinism_and_error_reporting(
            message in prop::array::uniform32(any::<u8>()),
            randomness in prop::array::uniform32(any::<u8>()),
            parameter in prop::array::uniform32(any::<u8>()),
            epoch in any::<u32>()
        ) {
            let hash_chunks = TestMessageHash::apply(&parameter, epoch, &randomness, &message).unwrap();
            let hash_sum: usize = hash_chunks.iter().map(|&x| x as usize).sum();

            let result1 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
            let result2 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);

            match (&result1, &result2) {
                (Ok(c1), Ok(c2)) => prop_assert_eq!(c1, c2),
                (Err(TargetSumError::Mismatch { expected: e1, actual: a1 }),
                 Err(TargetSumError::Mismatch { expected: e2, actual: a2 })) => {
                    prop_assert_eq!(e1, e2);
                    prop_assert_eq!(a1, a2);
                }
                _ => prop_assert!(false, "determinism violated"),
            }

            match result1 {
                Err(TargetSumError::Mismatch { expected, actual }) => {
                    prop_assert_eq!(expected, TEST_TARGET_SUM);
                    prop_assert_eq!(actual, hash_sum);
                }
                Ok(chunks) => {
                    prop_assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);
                    for &chunk in &chunks {
                        prop_assert!((chunk as usize) < TestTargetSumEncoding::BASE);
                    }
                    let sum: usize = chunks.iter().map(|&x| x as usize).sum();
                    prop_assert_eq!(sum, TEST_TARGET_SUM);
                }
                Err(TargetSumError::HashError(error)) => match error {},
            }
        }
    }
}
