//! Domain-separated BLAKE3 hashing for Winternitz chains and Merkle trees.

use rayon::prelude::*;

use super::{TweakableHash, chain};
use crate::{HASH_LENGTH, symmetric::prf::Pseudorandom};

const CHAIN_HASH_CONTEXT: &str = "leansig 2026-08-17 chain hash v1";
const TREE_LEAF_CONTEXT: &str = "leansig 2026-08-17 tree leaf hash v1";
const TREE_NODE_CONTEXT: &str = "leansig 2026-08-17 tree node hash v1";

/// Addresses a hash invocation within a Winternitz chain or Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blake3Tweak {
    Tree {
        level: u8,
        position: u32,
    },
    Chain {
        epoch: u32,
        chain_index: u8,
        position: u8,
    },
}

/// BLAKE3 tweakable hash. `NUM_CHUNKS` binds the tree-leaf arity to an instantiation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3TweakHash<const NUM_CHUNKS: usize>;

impl<const NUM_CHUNKS: usize> TweakableHash for Blake3TweakHash<NUM_CHUNKS> {
    type Parameter = [u8; HASH_LENGTH];
    type Tweak = Blake3Tweak;
    type Domain = [u8; HASH_LENGTH];

    fn rand_parameter<R: rand::RngExt>(rng: &mut R) -> Self::Parameter {
        rng.random()
    }

    fn rand_domain<R: rand::RngExt>(rng: &mut R) -> Self::Domain {
        rng.random()
    }

    fn tree_tweak(level: u8, position: u32) -> Self::Tweak {
        Blake3Tweak::Tree { level, position }
    }

    fn chain_tweak(epoch: u32, chain_index: u8, position: u8) -> Self::Tweak {
        Blake3Tweak::Chain {
            epoch,
            chain_index,
            position,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        let (context, level, position) = match *tweak {
            Blake3Tweak::Chain {
                epoch,
                chain_index,
                position,
            } => {
                assert_eq!(message.len(), 1, "chain hashing requires one input");
                let mut hasher = blake3::Hasher::new_derive_key(CHAIN_HASH_CONTEXT);
                hasher.update(parameter);
                hasher.update(&epoch.to_le_bytes());
                hasher.update(&[chain_index, position]);
                hasher.update(&message[0]);
                return *hasher.finalize().as_bytes();
            }
            Blake3Tweak::Tree { level: 0, position } => (TREE_LEAF_CONTEXT, 0, position),
            Blake3Tweak::Tree { level, position } => {
                assert_eq!(
                    message.len(),
                    2,
                    "internal tree hashing requires two children"
                );
                (TREE_NODE_CONTEXT, level, position)
            }
        };

        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(parameter);
        hasher.update(&[level]);
        hasher.update(&position.to_le_bytes());
        hasher.update(&(message.len() as u32).to_le_bytes());
        for value in message {
            hasher.update(value);
        }
        *hasher.finalize().as_bytes()
    }

    fn compute_tree_leaves<PRF>(
        prf_key: &PRF::Key,
        parameter: &Self::Parameter,
        epochs: &[u32],
        num_chains: usize,
        chain_length: usize,
    ) -> Vec<Self::Domain>
    where
        PRF: Pseudorandom,
        PRF::Domain: Into<Self::Domain>,
    {
        assert_eq!(num_chains, NUM_CHUNKS);
        epochs
            .par_iter()
            .map(|epoch| {
                let chain_ends: Vec<_> = (0..num_chains)
                    .map(|chain_index| {
                        let start =
                            PRF::get_domain_element(prf_key, *epoch, chain_index as u64).into();
                        chain::<Self>(
                            parameter,
                            *epoch,
                            chain_index as u8,
                            0,
                            chain_length - 1,
                            &start,
                        )
                    })
                    .collect();
                Self::apply(parameter, &Self::tree_tweak(0, *epoch), &chain_ends)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Hash = Blake3TweakHash<3>;

    #[test]
    fn chain_leaf_and_node_domains_are_distinct() {
        let parameter = [1u8; HASH_LENGTH];
        let value = [2u8; HASH_LENGTH];
        let chain = Hash::apply(&parameter, &Hash::chain_tweak(0, 0, 1), &[value]);
        let leaf = Hash::apply(&parameter, &Hash::tree_tweak(0, 0), &[value; 3]);
        let node = Hash::apply(&parameter, &Hash::tree_tweak(1, 0), &[value; 2]);
        assert_eq!(
            chain,
            [
                219, 40, 57, 253, 160, 141, 22, 108, 64, 173, 2, 216, 86, 17, 150, 174, 167, 111,
                74, 196, 201, 129, 193, 97, 129, 233, 158, 41, 255, 39, 50, 217,
            ]
        );
        assert_eq!(
            leaf,
            [
                80, 192, 76, 19, 104, 99, 102, 42, 233, 244, 114, 174, 3, 196, 250, 244, 1, 87, 16,
                36, 247, 248, 247, 53, 201, 137, 6, 105, 103, 209, 149, 157,
            ]
        );
        assert_eq!(
            node,
            [
                14, 206, 168, 62, 24, 19, 170, 61, 111, 225, 113, 70, 81, 75, 20, 122, 238, 170,
                105, 68, 5, 139, 136, 239, 144, 175, 159, 61, 23, 76, 19, 32,
            ]
        );
        assert_ne!(chain, leaf);
        assert_ne!(chain, node);
        assert_ne!(leaf, node);
    }

    #[test]
    fn child_order_and_addresses_are_bound() {
        let parameter = [1u8; HASH_LENGTH];
        let left = [2u8; HASH_LENGTH];
        let right = [3u8; HASH_LENGTH];
        let a = Hash::apply(&parameter, &Hash::tree_tweak(1, 0), &[left, right]);
        let b = Hash::apply(&parameter, &Hash::tree_tweak(1, 0), &[right, left]);
        let c = Hash::apply(&parameter, &Hash::tree_tweak(1, 1), &[left, right]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
