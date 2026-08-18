use std::ops::Range;

use crate::MESSAGE_LENGTH;
use crate::serialization::Serializable;
use rand::{CryptoRng, RngExt};
use thiserror::Error;

/// Signing errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    /// The epoch is outside the key's activation interval.
    #[error("Epoch {epoch} is outside this secret key's activation interval.")]
    EpochOutsideActivation { epoch: u32 },

    /// The key has not prepared this epoch.
    #[error("Epoch {epoch} is not in this secret key's prepared interval.")]
    EpochNotPrepared { epoch: u32 },

    /// The key has already signed in this epoch.
    #[error("Epoch {epoch} has already been signed with this secret key.")]
    EpochAlreadyUsed { epoch: u32 },

    /// No valid codeword was found within the attempt limit.
    #[error("Failed to encode message after {attempts} attempts.")]
    EncodingAttemptsExceeded { attempts: usize },
}

/// State needed to maintain the sliding window of prepared Merkle subtrees.
pub trait SignatureSchemeSecretKey {
    /// Epochs covered by the key.
    fn get_activation_interval(&self) -> Range<u64>;

    /// Epochs covered by the two bottom trees currently in memory.
    fn get_prepared_interval(&self) -> Range<u64>;

    /// Drops the oldest bottom tree and prepares the next one, if it is active.
    fn advance_preparation(&mut self);
}

/// Stateful hash-based signature scheme.
///
/// A key may sign once per epoch. See <https://eprint.iacr.org/2025/055.pdf>.
pub trait SignatureScheme {
    /// Serializable public key.
    type PublicKey: Serializable;

    /// Serializable stateful secret key.
    type SecretKey: SignatureSchemeSecretKey + Serializable;

    /// Serializable signature.
    type Signature: Serializable;

    /// Maximum number of epochs. Must be a power of two.
    const LIFETIME: u64;

    /// Generates a key active for the requested epoch range.
    fn key_gen<R: RngExt + CryptoRng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Signs once at `epoch` and records the epoch in `sk`.
    ///
    /// Persist the updated key before releasing the signature. Restoring older key
    /// state can bypass epoch-reuse protection.
    fn sign(
        sk: &mut Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError>;

    /// Verifies a signature for `message` at `epoch`.
    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool;

    /// Derives the public key from a secret key.
    fn get_public_key(sk: &Self::SecretKey) -> Self::PublicKey;
}

pub mod generalized_xmss;

#[cfg(test)]
mod test_templates {
    use rand::RngExt;

    use super::*;

    /// Runs a sign/verify round trip for a scheme.
    pub fn test_signature_scheme_correctness<T: SignatureScheme>(
        epoch: u32,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) {
        // Use u64 for the end check so a 2^32 lifetime does not wrap.
        assert!(
            activation_epoch as u32 <= epoch
                && (epoch as u64) < (activation_epoch + num_active_epochs) as u64,
            "Did not even try signing, epoch {:?} outside of activation interval {:?},{:?}",
            epoch,
            activation_epoch,
            num_active_epochs
        );

        let mut rng = rand::rng();

        let (pk, mut sk) = T::key_gen(&mut rng, activation_epoch, num_active_epochs);

        let mut iterations = 0;
        while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
            sk.advance_preparation();
            iterations += 1;
        }
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Did not even try signing, failed to advance key preparation to desired epoch {:?}.",
            epoch
        );

        let message = rng.random();
        let signature = T::sign(&mut sk, epoch, &message);

        assert!(
            signature.is_ok(),
            "Signing failed: {:?}. Epoch was {:?}",
            signature.err(),
            epoch
        );

        let signature = signature.unwrap();
        let is_valid = T::verify(&pk, epoch, &message, &signature);
        assert!(
            is_valid,
            "Signature verification failed. . Epoch was {:?}",
            epoch
        );
    }
}
