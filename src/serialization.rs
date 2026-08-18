//! A unified serialization implementation

use serde::{Serialize, de::DeserializeOwned};
use ssz::{Decode, DecodeError, Encode};

/// Canonical SSZ and serde support for LeanSig values.
pub trait Serializable: Serialize + DeserializeOwned + Encode + Decode + Sized {
    /// Encodes this value as SSZ.
    fn to_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    /// Decodes an SSZ value.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_ssz_bytes(bytes)
    }
}

impl Serializable for [u8; 32] {}
