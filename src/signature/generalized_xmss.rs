use std::marker::PhantomData;

use rand::{CryptoRng, RngExt};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    MESSAGE_LENGTH,
    inc_encoding::IncomparableEncoding,
    serialization::Serializable,
    signature::SignatureSchemeSecretKey,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{TweakableHash, chain},
        tweak_hash_tree::{HashSubTree, HashTreeOpening, combined_path, hash_tree_verify},
    },
};

use super::{SignatureScheme, SigningError};

use ssz::{Decode, DecodeError, Encode};

/// Generalized XMSS over a PRF, incomparable encoding, and tweakable hash.
///
/// `LOG_LIFETIME` must be even and no greater than 32.
pub struct GeneralizedXMSSSignatureScheme<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    _prf: std::marker::PhantomData<PRF>,
    _ie: std::marker::PhantomData<IE>,
    _th: std::marker::PhantomData<TH>,
}

/// Merkle path, encoding randomness, and Winternitz chain values.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

impl<IE: IncomparableEncoding, TH: TweakableHash> GeneralizedXMSSSignature<IE, TH> {
    pub const fn path(&self) -> &HashTreeOpening<TH> {
        &self.path
    }

    pub const fn rho(&self) -> &IE::Randomness {
        &self.rho
    }

    pub const fn hashes(&self) -> &Vec<TH::Domain> {
        &self.hashes
    }
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Encode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        let offset_size = 4;
        let rho_size = self.rho.ssz_bytes_len();
        let path_size = self.path.ssz_bytes_len();
        let hashes_size = self.hashes.ssz_bytes_len();

        offset_size + rho_size + offset_size + path_size + hashes_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let rho_size = self.rho.ssz_bytes_len();
        let fixed_size = 4 + rho_size + 4;

        let offset_path = fixed_size;
        let offset_hashes = offset_path + self.path.ssz_bytes_len();

        buf.extend_from_slice(&(offset_path as u32).to_le_bytes());
        self.rho.ssz_append(buf);
        buf.extend_from_slice(&(offset_hashes as u32).to_le_bytes());
        self.path.ssz_append(buf);
        self.hashes.ssz_append(buf);
    }
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Decode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let rho_size = if <IE::Randomness as Encode>::is_ssz_fixed_len() {
            <IE::Randomness as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "IE::Randomness must be fixed length".into(),
            ));
        };

        let min_size = 4 + rho_size + 4;
        if bytes.len() < min_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_size,
            });
        }

        let offset_path = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 4,
            }
        })?) as usize;

        let rho = IE::Randomness::from_ssz_bytes(&bytes[4..4 + rho_size])?;
        let offset_hashes =
            u32::from_le_bytes(bytes[4 + rho_size..8 + rho_size].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: 8 + rho_size,
                }
            })?) as usize;

        let expected_offset_path = 4 + rho_size + 4;
        if offset_path != expected_offset_path {
            return Err(DecodeError::InvalidByteLength {
                len: offset_path,
                expected: expected_offset_path,
            });
        }

        if offset_path > offset_hashes || offset_hashes > bytes.len() {
            return Err(DecodeError::BytesInvalid(format!(
                "Invalid variable offsets: path={} hashes={} len={}",
                offset_path,
                offset_hashes,
                bytes.len()
            )));
        }

        let path = HashTreeOpening::<TH>::from_ssz_bytes(&bytes[offset_path..offset_hashes])?;
        let hashes = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset_hashes..])?;

        Ok(Self { path, rho, hashes })
    }
}

/// Merkle root and public tweakable-hash parameter.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

impl<TH: TweakableHash> GeneralizedXMSSPublicKey<TH> {
    pub const fn root(&self) -> &TH::Domain {
        &self.root
    }

    pub const fn parameter(&self) -> &TH::Parameter {
        &self.parameter
    }
}

/// PRF key, prepared Merkle subtrees, and consumed-epoch state.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSecretKey<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    prf_key: PRF::Key,
    parameter: TH::Parameter,
    activation_epoch: u64,
    num_active_epochs: u64,
    top_tree: HashSubTree<TH>,
    left_bottom_tree_index: u64,
    left_bottom_tree: HashSubTree<TH>,
    right_bottom_tree: HashSubTree<TH>,
    /// Sorted epochs consumed inside the current prepared window.
    used_epochs: Vec<u32>,
    _encoding_type: PhantomData<IE>,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Encode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();
        let activation_epoch_size = 8; // u64
        let num_active_epochs_size = 8; // u64

        let offset_size = 4;
        let top_tree_size = self.top_tree.ssz_bytes_len();

        let left_bottom_tree_index_size = 8; // u64
        let left_bottom_tree_size = self.left_bottom_tree.ssz_bytes_len();
        let right_bottom_tree_size = self.right_bottom_tree.ssz_bytes_len();
        let used_epochs_size = self.used_epochs.ssz_bytes_len();

        prf_key_size
            + parameter_size
            + activation_epoch_size
            + num_active_epochs_size
            + offset_size // top_tree offset
            + left_bottom_tree_index_size
            + offset_size // left_bottom_tree offset
            + offset_size // right_bottom_tree offset
            + offset_size // used_epochs offset
            + top_tree_size
            + left_bottom_tree_size
            + right_bottom_tree_size
            + used_epochs_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();
        let fixed_size = prf_key_size + parameter_size + 8 + 8 + 4 + 8 + 4 + 4 + 4;

        let offset_top_tree = fixed_size;
        let offset_left_bottom = offset_top_tree + self.top_tree.ssz_bytes_len();
        let offset_right_bottom = offset_left_bottom + self.left_bottom_tree.ssz_bytes_len();
        let offset_used_epochs = offset_right_bottom + self.right_bottom_tree.ssz_bytes_len();

        self.prf_key.ssz_append(buf);
        self.parameter.ssz_append(buf);
        buf.extend_from_slice(&self.activation_epoch.to_le_bytes());
        buf.extend_from_slice(&self.num_active_epochs.to_le_bytes());
        buf.extend_from_slice(&(offset_top_tree as u32).to_le_bytes());
        buf.extend_from_slice(&self.left_bottom_tree_index.to_le_bytes());
        buf.extend_from_slice(&(offset_left_bottom as u32).to_le_bytes());
        buf.extend_from_slice(&(offset_right_bottom as u32).to_le_bytes());
        buf.extend_from_slice(&(offset_used_epochs as u32).to_le_bytes());
        self.top_tree.ssz_append(buf);
        self.left_bottom_tree.ssz_append(buf);
        self.right_bottom_tree.ssz_append(buf);
        self.used_epochs.ssz_append(buf);
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Decode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    #[allow(clippy::too_many_lines)]
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let prf_key_size = if <PRF::Key as Encode>::is_ssz_fixed_len() {
            <PRF::Key as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "PRF::Key must be fixed length".into(),
            ));
        };

        let parameter_size = if <TH::Parameter as Encode>::is_ssz_fixed_len() {
            <TH::Parameter as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "TH::Parameter must be fixed length".into(),
            ));
        };

        let min_fixed_size = prf_key_size + parameter_size + 24 + 16;
        if bytes.len() < min_fixed_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_fixed_size,
            });
        }

        let mut pos = 0;
        let prf_key = PRF::Key::from_ssz_bytes(&bytes[pos..pos + prf_key_size])?;
        pos += prf_key_size;
        let parameter = TH::Parameter::from_ssz_bytes(&bytes[pos..pos + parameter_size])?;
        pos += parameter_size;
        let activation_epoch =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        let num_active_epochs =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        let offset_top_tree = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: pos + 4,
            }
        })?) as usize;
        pos += 4;

        let left_bottom_tree_index =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        let offset_left_bottom =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 4,
                }
            })?) as usize;
        pos += 4;

        let offset_right_bottom =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 4,
                }
            })?) as usize;
        pos += 4;

        let offset_used_epochs =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 4,
                }
            })?) as usize;
        pos += 4;

        if pos != offset_top_tree {
            return Err(DecodeError::InvalidByteLength {
                len: pos,
                expected: offset_top_tree,
            });
        }

        if offset_top_tree > offset_left_bottom
            || offset_left_bottom > offset_right_bottom
            || offset_right_bottom > offset_used_epochs
            || offset_used_epochs > bytes.len()
        {
            return Err(DecodeError::BytesInvalid(format!(
                "Invalid variable offsets: top={} left={} right={} used={} len={}",
                offset_top_tree,
                offset_left_bottom,
                offset_right_bottom,
                offset_used_epochs,
                bytes.len()
            )));
        }

        let top_tree =
            HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_top_tree..offset_left_bottom])?;
        let left_bottom_tree =
            HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_left_bottom..offset_right_bottom])?;
        let right_bottom_tree =
            HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_right_bottom..offset_used_epochs])?;
        let used_epochs = Vec::<u32>::from_ssz_bytes(&bytes[offset_used_epochs..])?;

        let activation_end = activation_epoch
            .checked_add(num_active_epochs)
            .ok_or_else(|| {
                DecodeError::BytesInvalid("Secret-key activation interval overflows u64".into())
            })?;
        let leafs_per_bottom_tree = 1u64
            .checked_shl((LOG_LIFETIME / 2) as u32)
            .ok_or_else(|| DecodeError::BytesInvalid("Invalid LOG_LIFETIME".into()))?;
        let prepared_start = left_bottom_tree_index
            .checked_mul(leafs_per_bottom_tree)
            .ok_or_else(|| DecodeError::BytesInvalid("Prepared interval overflows u64".into()))?;
        let prepared_end = prepared_start
            .checked_add(2 * leafs_per_bottom_tree)
            .ok_or_else(|| DecodeError::BytesInvalid("Prepared interval overflows u64".into()))?;
        if prepared_start < activation_epoch || prepared_end > activation_end {
            return Err(DecodeError::BytesInvalid(
                "Prepared interval must be contained in the activation interval".into(),
            ));
        }
        if used_epochs.windows(2).any(|pair| pair[0] >= pair[1])
            || used_epochs.iter().any(|epoch| {
                let epoch = u64::from(*epoch);
                epoch < activation_epoch
                    || epoch >= activation_end
                    || epoch < prepared_start
                    || epoch >= prepared_end
            })
        {
            return Err(DecodeError::BytesInvalid(
                "Consumed epochs must be unique, sorted, active, and prepared".into(),
            ));
        }

        Ok(Self {
            prf_key,
            parameter,
            activation_epoch,
            num_active_epochs,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
            used_epochs,
            _encoding_type: PhantomData,
        })
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureSchemeSecretKey for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    fn get_activation_interval(&self) -> std::ops::Range<u64> {
        let start = self.activation_epoch;
        let end = start + self.num_active_epochs;
        start..end
    }

    fn get_prepared_interval(&self) -> std::ops::Range<u64> {
        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let start = self.left_bottom_tree_index * leafs_per_bottom_tree;
        let end = start + (2 * leafs_per_bottom_tree);
        start..end
    }

    fn advance_preparation(&mut self) {
        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let next_prepared_end_epoch =
            self.left_bottom_tree_index * leafs_per_bottom_tree + 3 * leafs_per_bottom_tree;
        if next_prepared_end_epoch > self.get_activation_interval().end {
            return;
        }

        let new_right_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &self.prf_key,
            self.left_bottom_tree_index + 2,
            &self.parameter,
        );

        self.left_bottom_tree =
            std::mem::replace(&mut self.right_bottom_tree, new_right_bottom_tree);
        self.left_bottom_tree_index += 1;
        let prepared_start = self.left_bottom_tree_index * leafs_per_bottom_tree;
        self.used_epochs
            .retain(|epoch| u64::from(*epoch) >= prepared_start);
    }
}

/// Expands an activation range to aligned bottom-tree boundaries.
///
/// Returns the inclusive start and exclusive end as bottom-tree indices.
fn expand_activation_time<const LOG_LIFETIME: usize>(
    desired_activation_epoch: usize,
    desired_num_active_epochs: usize,
) -> (usize, usize) {
    let lifetime = 1usize << LOG_LIFETIME;
    let c = 1usize << (LOG_LIFETIME / 2);
    let c_mask = !(c - 1);

    let desired_start = desired_activation_epoch;
    let desired_end = desired_activation_epoch + desired_num_active_epochs;

    let mut start = desired_start & c_mask;
    let mut end = (desired_end + c - 1) & c_mask;
    if end - start < 2 * c {
        end = start + 2 * c;
    }

    if end > lifetime {
        let duration = end - start;
        if duration > lifetime {
            start = 0;
            end = lifetime;
        } else {
            end = lifetime;
            start = (lifetime - duration) & c_mask;
        }
    }

    start >>= LOG_LIFETIME / 2;
    end >>= LOG_LIFETIME / 2;

    (start, end)
}

/// Rebuilds one bottom tree from PRF-derived chain starts.
fn bottom_tree_from_prf_key<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
>(
    prf_key: &PRF::Key,
    bottom_tree_index: u64,
    parameter: &TH::Parameter,
) -> HashSubTree<TH>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
    let num_chains = IE::DIMENSION;
    let chain_length = IE::BASE;

    let epoch_start = bottom_tree_index * leafs_per_bottom_tree;
    let epochs: Vec<u32> = (epoch_start..epoch_start + leafs_per_bottom_tree)
        .map(|e| e as u32)
        .collect();

    let chain_ends_hashes =
        TH::compute_tree_leaves::<PRF>(prf_key, parameter, &epochs, num_chains, chain_length);
    HashSubTree::new_bottom_tree(
        LOG_LIFETIME,
        bottom_tree_index as usize,
        parameter,
        chain_ends_hashes,
    )
}

impl<
    PRF: Pseudorandom,
    IE: IncomparableEncoding + Sync + Send,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    #[allow(clippy::too_many_lines)]
    fn key_gen<R: RngExt + CryptoRng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey) {
        const {
            assert!(
                IE::BASE >= 2,
                "Generalized XMSS: Encoding base (w) must be at least 2"
            );
            assert!(
                IE::DIMENSION >= 1,
                "Generalized XMSS: Encoding dimension (v) must be at least 1"
            );

            assert!(
                IE::BASE <= 1 << 8,
                "Generalized XMSS: Encoding base (w) must fit in u8 (<= 256)"
            );
            assert!(
                IE::DIMENSION <= 1 << 8,
                "Generalized XMSS: Encoding dimension (v) must fit in u8 (<= 256)"
            );

            assert!(
                LOG_LIFETIME.is_multiple_of(2),
                "Generalized XMSS: LOG_LIFETIME must be even (top-bottom tree split)"
            );

            assert!(
                LOG_LIFETIME >= 2,
                "Generalized XMSS: LOG_LIFETIME must be at least 2"
            );

            assert!(
                LOG_LIFETIME <= 32,
                "Generalized XMSS: LOG_LIFETIME must be at most 32 (epoch is u32)"
            );
        }

        // Validate in u64 so a 2^32 lifetime does not truncate on 32-bit targets.
        let requested_end = (activation_epoch as u64)
            .checked_add(num_active_epochs as u64)
            .expect("Key gen: activation interval overflowed u64");

        assert!(
            requested_end <= Self::LIFETIME,
            "Key gen: requested interval [{}..{}) exceeds LIFETIME {}",
            activation_epoch,
            requested_end,
            Self::LIFETIME
        );

        assert!(
            num_active_epochs > 0,
            "Key gen: num_active_epochs must be non-zero"
        );

        // The secret key keeps the top tree and two consecutive bottom trees.
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let (start_bottom_tree_index, end_bottom_tree_index) =
            expand_activation_time::<LOG_LIFETIME>(activation_epoch, num_active_epochs);
        let num_bottom_trees = end_bottom_tree_index - start_bottom_tree_index;
        assert!(num_bottom_trees >= 2);
        let activation_epoch = start_bottom_tree_index * leafs_per_bottom_tree;
        let num_active_epochs = num_bottom_trees * leafs_per_bottom_tree;

        let parameter = TH::rand_parameter(rng);
        let prf_key = PRF::key_gen(rng);
        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);

        let left_bottom_tree_index = start_bottom_tree_index as u64;
        let left_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &prf_key,
            left_bottom_tree_index,
            &parameter,
        );
        roots_of_bottom_trees.push(left_bottom_tree.root());

        let right_bottom_tree_index = (start_bottom_tree_index + 1) as u64;
        let right_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &prf_key,
            right_bottom_tree_index,
            &parameter,
        );
        roots_of_bottom_trees.push(right_bottom_tree.root());

        roots_of_bottom_trees.extend(
            (start_bottom_tree_index + 2..end_bottom_tree_index)
                .into_par_iter()
                .map(|bottom_tree_index| {
                    let bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
                        &prf_key,
                        bottom_tree_index as u64,
                        &parameter,
                    );
                    bottom_tree.root()
                })
                .collect::<Vec<_>>(),
        );
        let top_tree = HashSubTree::new_top_tree(
            rng,
            LOG_LIFETIME,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );

        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            parameter,
            activation_epoch: activation_epoch as u64,
            num_active_epochs: num_active_epochs as u64,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
            used_epochs: Vec::new(),
            _encoding_type: PhantomData,
        };
        let pk = Self::get_public_key(&sk);

        (pk, sk)
    }

    fn sign(
        sk: &mut Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        if !sk.get_activation_interval().contains(&(epoch as u64)) {
            return Err(SigningError::EpochOutsideActivation { epoch });
        }

        if !sk.get_prepared_interval().contains(&(epoch as u64)) {
            return Err(SigningError::EpochNotPrepared { epoch });
        }

        // Keep the invariant robust even if this key arrived through a serde format
        // that does not run the canonical SSZ decoder's structural validation.
        sk.used_epochs.sort_unstable();
        sk.used_epochs.dedup();
        let Err(used_epoch_position) = sk.used_epochs.binary_search(&epoch) else {
            return Err(SigningError::EpochAlreadyUsed { epoch });
        };

        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let boundary_between_bottom_trees =
            (sk.left_bottom_tree_index * leafs_per_bottom_tree + leafs_per_bottom_tree) as u32;
        let bottom_tree = if epoch < boundary_between_bottom_trees {
            &sk.left_bottom_tree
        } else {
            &sk.right_bottom_tree
        };
        let path = combined_path(&sk.top_tree, bottom_tree, epoch);

        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            let curr_rho = PRF::get_randomness(&sk.prf_key, epoch, message, attempts as u64).into();
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok();
                break;
            }

            attempts += 1;
        }

        if x.is_none() {
            return Err(SigningError::EncodingAttemptsExceeded {
                attempts: max_tries,
            });
        }

        let x = x.unwrap();
        let rho = rho.unwrap();
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );

        let hashes = (0..num_chains)
            .into_par_iter()
            .map(|chain_index| {
                let start = PRF::get_domain_element(&sk.prf_key, epoch, chain_index as u64).into();
                let steps = x[chain_index] as usize;
                chain::<TH>(&sk.parameter, epoch, chain_index as u8, 0, steps, &start)
            })
            .collect();

        // Record use before returning the signature.
        let signature = GeneralizedXMSSSignature { path, rho, hashes };
        sk.used_epochs.insert(used_epoch_position, epoch);
        Ok(signature)
    }

    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool {
        debug_assert!(
            (epoch as u64) < Self::LIFETIME,
            "Generalized XMSS - Verify: Epoch too large."
        );

        debug_assert!(
            sig.hashes.len() == IE::DIMENSION,
            "Generalized XMSS - Verify: Wrong number of hashes."
        );

        if (epoch as u64) >= Self::LIFETIME {
            return false;
        }
        if sig.hashes.len() != IE::DIMENSION {
            return false;
        }

        let Ok(x) = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch) else {
            return false;
        };

        let chain_length = IE::BASE;
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for (chain_index, xi) in x.iter().enumerate() {
            let steps = (chain_length - 1) as u8 - xi;
            let start_pos_in_chain = *xi;
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u8,
                start_pos_in_chain,
                steps as usize,
                start,
            );
            chain_ends.push(end);
        }

        hash_tree_verify(
            &pk.parameter,
            &pk.root,
            epoch,
            chain_ends.as_slice(),
            &sig.path,
        )
    }

    fn get_public_key(sk: &Self::SecretKey) -> Self::PublicKey {
        Self::PublicKey {
            root: sk.top_tree.root(),
            parameter: sk.parameter,
        }
    }
}

impl<TH: TweakableHash> Encode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Encode>::is_ssz_fixed_len() && <TH::Parameter as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Encode>::ssz_fixed_len() + <TH::Parameter as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.root.ssz_bytes_len() + self.parameter.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.root.ssz_append(buf);
        self.parameter.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Decode>::is_ssz_fixed_len() && <TH::Parameter as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Decode>::ssz_fixed_len() + <TH::Parameter as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected_len = <Self as Decode>::ssz_fixed_len();
        if bytes.len() != expected_len {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: expected_len,
            });
        }

        let root_len = <TH::Domain as Decode>::ssz_fixed_len();
        let (root_bytes, param_bytes) = bytes.split_at(root_len);

        let root = TH::Domain::from_ssz_bytes(root_bytes)?;
        let parameter = TH::Parameter::from_ssz_bytes(param_bytes)?;

        Ok(Self { root, parameter })
    }
}

impl<TH: TweakableHash> Serializable for GeneralizedXMSSPublicKey<TH> {}

impl<IE: IncomparableEncoding, TH: TweakableHash> Serializable
    for GeneralizedXMSSSignature<IE, TH>
{
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Serializable for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
}

/// Concrete generalized XMSS signature schemes using BLAKE3 end to end.
pub mod instantiations_blake3;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::test_templates::test_signature_scheme_correctness,
        symmetric::{
            message_hash::{MessageHash, blake3::Blake3MessageHash},
            prf::blake3::Blake3Prf,
            tweak_hash::blake3::Blake3TweakHash,
        },
    };

    use super::*;

    use proptest::prelude::*;

    use rand::{RngExt, SeedableRng, rng, rngs::StdRng};
    use ssz::{Decode, Encode};

    type TestTH = Blake3TweakHash<155>;

    #[test]
    pub fn test_target_sum_blake3() {
        // Note: do not use these parameters, they are just for testing
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_rejects_epoch_reuse() {
        // Note: do not use these parameters, they are just for testing
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rand::rng();
        let (_pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 29;

        assert!(matches!(
            Sig::sign(&mut sk, epoch, &message),
            Err(SigningError::EpochNotPrepared { epoch: rejected }) if rejected == epoch
        ));
        assert!(matches!(
            Sig::sign(&mut sk, Sig::LIFETIME as u32, &message),
            Err(SigningError::EpochOutsideActivation { epoch: rejected })
                if rejected == Sig::LIFETIME as u32
        ));

        // prepare key for epoch
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

        let signature = Sig::sign(&mut sk, epoch, &message).unwrap();
        assert!(matches!(
            Sig::sign(&mut sk, epoch, &message),
            Err(SigningError::EpochAlreadyUsed { epoch: reused }) if reused == epoch
        ));

        let encoded = sk.as_ssz_bytes();
        let mut restored = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&encoded).unwrap();
        assert!(matches!(
            Sig::sign(&mut restored, epoch, &message),
            Err(SigningError::EpochAlreadyUsed { epoch: reused }) if reused == epoch
        ));
        assert!(!signature.hashes.is_empty());

        // Moving beyond the old half-window compacts state that can no longer be used.
        sk.advance_preparation();
        sk.advance_preparation();
        assert!(!sk.used_epochs.contains(&epoch));
    }

    #[test]
    fn test_rejects_tampering() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<16>;
        type MH = Blake3MessageHash<16, 2>;
        type IE = TargetSumEncoding<MH, 8>;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, 6>;

        let mut rng = StdRng::seed_from_u64(7);
        let (pk, mut sk) = Sig::key_gen(&mut rng, 0, Sig::LIFETIME as usize);
        let epoch = 3;
        let message = [11u8; MESSAGE_LENGTH];
        let signature = Sig::sign(&mut sk, epoch, &message).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &signature));

        let mut wrong_message = message;
        wrong_message[0] ^= 1;
        assert!(!Sig::verify(&pk, epoch, &wrong_message, &signature));
        assert!(!Sig::verify(&pk, epoch + 1, &message, &signature));

        let mut wrong_rho = signature.clone();
        wrong_rho.rho[0] ^= 1;
        assert!(!Sig::verify(&pk, epoch, &message, &wrong_rho));

        let mut wrong_hash = signature.clone();
        wrong_hash.hashes[0][0] ^= 1;
        assert!(!Sig::verify(&pk, epoch, &message, &wrong_hash));

        let mut wrong_pk = pk;
        wrong_pk.parameter[0] ^= 1;
        assert!(!Sig::verify(&wrong_pk, epoch, &message, &signature));
    }

    #[test]
    pub fn test_large_base_blake3() {
        // Note: do not use these parameters, they are just for testing
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<32>;
        type MH = Blake3MessageHash<32, 256>;
        const TARGET_SUM: usize = 1 << 12;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_dimension_blake3() {
        // Note: do not use these parameters, they are just for testing
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<256>;
        type MH = Blake3MessageHash<256, 2>;
        const TARGET_SUM: usize = 128;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_base8_target_sum() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<64>;
        type MH = Blake3MessageHash<64, 8>;
        const TARGET_SUM: usize = MH::DIMENSION * (MH::BASE - 1) / 2; // 224
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_expand_activation_time() {
        const LOG_LIFETIME: usize = 4;

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 8);
        assert!((start == 0) && (end_excl == 2));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 4);
        assert!((start == 0) && (end_excl == 2));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 7);
        assert!((start == 0) && (end_excl == 2));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 3);
        assert!((start == 0) && (end_excl == 2));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(1, 8);
        assert!((start == 0) && (end_excl == 3));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(8, 5);
        assert!((start == 2) && (end_excl == 4));

        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(12, 2);
        assert!((start == 2) && (end_excl == 4));
    }

    #[test]
    fn test_ssz_encoding_structure() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        let encoded = public_key.as_ssz_bytes();
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[..32], root);
        let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(public_key.root, decoded.root);
        assert_eq!(public_key.parameter, decoded.parameter);

        let (pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        let signature = Sig::sign(&mut sk, epoch, &message).unwrap();
        let sig_encoded = signature.as_ssz_bytes();
        let rho_size = signature.rho.ssz_bytes_len();
        assert!(sig_encoded.len() >= 4 + rho_size + 4);
        let offset_path = u32::from_le_bytes(sig_encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(offset_path, 4 + rho_size + 4);
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));

        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        let sk_encoded = sk2.as_ssz_bytes();
        let prf_key_size = sk2.prf_key.ssz_bytes_len();
        let param_size = sk2.parameter.ssz_bytes_len();
        let fixed_part_size = prf_key_size + param_size + 8 + 8 + 4 + 8 + 4 + 4 + 4;
        assert!(sk_encoded.len() >= fixed_part_size);
        let activation_start = prf_key_size + param_size;
        let activation_epoch = u64::from_le_bytes(
            sk_encoded[activation_start..activation_start + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(activation_epoch, sk2.activation_epoch);
        let sk_decoded = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        let sk_reencoded = sk_decoded.as_ssz_bytes();
        assert_eq!(sk_encoded, sk_reencoded);
    }

    #[test]
    fn test_ssz_decoding_errors() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let encoded = vec![0u8; 63];
        let result = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 63,
                expected: 64
            })
        ));

        let encoded = vec![0u8; 8];
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 8,
                expected: 40
            })
        ));

        let mut encoded = vec![0u8; 128];
        encoded[0..4].copy_from_slice(&99u32.to_le_bytes());
        encoded[36..40].copy_from_slice(&78u32.to_le_bytes());
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 99,
                expected: 40
            })
        ));
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn test_ssz_panic_safety_malicious_offsets() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rand::rng();
        let dummy_prf_key = PRF::key_gen(&mut rng);
        let dummy_param = TH::rand_parameter(&mut rng);

        let prf_key_size = dummy_prf_key.ssz_bytes_len();
        let param_size = dummy_param.ssz_bytes_len();
        let u64_size = 8;
        let offset_size = 4;

        let fixed_part_len = prf_key_size
            + param_size
            + u64_size // activation_epoch
            + u64_size // num_active_epochs
            + offset_size // offset_top_tree
            + u64_size // left_bottom_tree_index
            + offset_size // offset_left_bottom
            + offset_size // offset_right_bottom
            + offset_size; // offset_used_epochs

        fn assert_bytes_invalid<T>(result: Result<T, DecodeError>, expected_msg_part: &str) {
            match result {
                Err(DecodeError::BytesInvalid(msg)) => {
                    assert!(
                        msg.contains(expected_msg_part),
                        "Error message '{}' did not contain expected part '{}'",
                        msg,
                        expected_msg_part
                    );
                }
                Err(e) => panic!("Wrong error type. Expected BytesInvalid, got {:?}", e),
                Ok(_) => panic!("Should have failed with BytesInvalid, but succeeded"),
            }
        }

        // Reversed signature offsets.
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();

            let sig_fixed_part_size = 4 + rho_size + 4;
            let mut encoded = vec![0u8; 200];
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4].copy_from_slice(&10u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "Invalid variable offsets");
        }

        // Out-of-bounds signature offset.
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();
            let sig_fixed_part_size = 4 + rho_size + 4;

            let mut encoded = vec![0u8; 100];
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4]
                .copy_from_slice(&200u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "len=100");
        }

        // Reversed secret-key offsets.
        {
            let mut encoded = vec![0u8; fixed_part_len + 100];
            let mut pos = 0;

            let mut prf_buf = Vec::new();
            dummy_prf_key.ssz_append(&mut prf_buf);
            encoded[pos..pos + prf_key_size].copy_from_slice(&prf_buf);
            pos += prf_key_size;

            let mut param_buf = Vec::new();
            dummy_param.ssz_append(&mut param_buf);
            encoded[pos..pos + param_size].copy_from_slice(&param_buf);
            pos += param_size;

            pos += 8;
            pos += 8;
            encoded[pos..pos + 4].copy_from_slice(&(fixed_part_len as u32).to_le_bytes());
            pos += 4;
            pos += 8;
            encoded[pos..pos + 4].copy_from_slice(&10u32.to_le_bytes());
            pos += 4;
            encoded[pos..pos + 4].copy_from_slice(&((fixed_part_len + 50) as u32).to_le_bytes());
            pos += 4;
            encoded[pos..pos + 4].copy_from_slice(&((fixed_part_len + 75) as u32).to_le_bytes());

            let result = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "Invalid variable offsets");
        }
    }

    #[test]
    fn test_ssz_determinism() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        let encoded1 = public_key.as_ssz_bytes();
        let encoded2 = public_key.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);
        let (_pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        let signature = Sig::sign(&mut sk, epoch, &message).unwrap();
        let sig_encoded1 = signature.as_ssz_bytes();
        let sig_encoded2 = signature.as_ssz_bytes();
        assert_eq!(sig_encoded1, sig_encoded2);
        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        let sk_encoded1 = sk2.as_ssz_bytes();
        let sk_encoded2 = sk2.as_ssz_bytes();
        assert_eq!(sk_encoded1, sk_encoded2);
    }

    #[test]
    fn test_ssz_signature_integration() {
        type PRF = Blake3Prf;
        type TH = Blake3TweakHash<155>;
        type MH = Blake3MessageHash<155, 2>;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        let (pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 7;
        let signature = Sig::sign(&mut sk, epoch, &message).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &signature));

        let pk_encoded = pk.as_ssz_bytes();
        let pk_decoded = GeneralizedXMSSPublicKey::<TH>::from_ssz_bytes(&pk_encoded).unwrap();
        assert!(Sig::verify(&pk_decoded, epoch, &message, &signature));

        let sig_encoded = signature.as_ssz_bytes();
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));
        assert!(Sig::verify(&pk_decoded, epoch, &message, &sig_decoded));

        let sk_encoded = sk.as_ssz_bytes();
        let mut sk_decoded =
            <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        assert!(matches!(
            Sig::sign(&mut sk_decoded, epoch, &message),
            Err(SigningError::EpochAlreadyUsed { epoch: reused }) if reused == epoch
        ));
        let sig2 = Sig::sign(&mut sk_decoded, epoch + 1, &message).unwrap();
        assert!(Sig::verify(&pk, epoch + 1, &message, &sig2));
    }

    proptest! {
        #[test]
        fn proptest_expand_activation_time_invariants(
            desired_start in 0usize..256,
            desired_duration in 1usize..256
        ) {
            const LOG_LIFETIME: usize = 8;
            const C: usize = 1 << (LOG_LIFETIME / 2);
            const LIFETIME: usize = 1 << LOG_LIFETIME;

            let desired_end = (desired_start + desired_duration).min(LIFETIME);

            let (start, end) = expand_activation_time::<LOG_LIFETIME>(desired_start, desired_duration);

            let actual_start = start * C;
            let actual_end = end * C;

            prop_assert!(actual_end - actual_start >= 2 * C);
            prop_assert!(actual_end <= LIFETIME);
            prop_assert!(actual_start <= desired_start);
            prop_assert!(actual_end >= desired_end);
            let (start2, end2) = expand_activation_time::<LOG_LIFETIME>(desired_start, desired_duration);
            prop_assert_eq!((start, end), (start2, end2));
        }

        #[test]
        fn proptest_ssz_public_key_roundtrip_and_determinism(
            root in prop::array::uniform32(any::<u8>()),
            parameter in prop::array::uniform32(any::<u8>())
        ) {
            let original = GeneralizedXMSSPublicKey::<TestTH> {
                root,
                parameter,
            };

            let encoded1 = original.as_ssz_bytes();
            let encoded2 = original.as_ssz_bytes();
            prop_assert_eq!(&encoded1, &encoded2);

            let expected_size = 64;
            prop_assert_eq!(encoded1.len(), expected_size);
            prop_assert_eq!(original.ssz_bytes_len(), expected_size);

            let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded1)
                .expect("valid SSZ bytes should decode");

            prop_assert_eq!(original.root, decoded.root);
            prop_assert_eq!(original.parameter, decoded.parameter);
        }
    }
}
