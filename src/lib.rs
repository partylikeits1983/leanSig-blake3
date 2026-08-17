/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

/// Size in bytes of BLAKE3 digests, public salts, PRF keys, and signing randomness.
pub const HASH_LENGTH: usize = 32;

pub mod inc_encoding;
pub mod serialization;
pub mod signature;
pub mod symmetric;
