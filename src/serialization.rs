//! A unified serialization implementation

use serde::{Serialize, de::DeserializeOwned};
use ssz::{Decode, DecodeError, Encode};

/// A supertrait combining all serialization capabilities needed for leanSig types.
pub trait Serializable: Serialize + DeserializeOwned + Encode + Decode + Sized {
    /// Converts this object to a canonical byte representation.
    ///
    /// # Canonical Format
    ///
    /// - BLAKE3 values are encoded as fixed 32-byte byte vectors.
    /// - Integer metadata is encoded in little-endian order by SSZ.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the canonical byte representation of this object.
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    /// Parses an object from its canonical byte representation.
    ///
    /// # Canonical Format
    ///
    /// The input bytes must follow the same canonical format as `to_bytes()`:
    /// - BLAKE3 values as fixed 32-byte byte vectors.
    /// - Composite structures following SSZ layout rules.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The canonical binary data to parse
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` if the bytes represent a valid object
    /// - `Err(DecodeError)` if the bytes are malformed or invalid
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_ssz_bytes(bytes)
    }
}

impl Serializable for [u8; 32] {}
