use rand::{CryptoRng, RngExt};

use rayon::prelude::*;

use crate::serialization::Serializable;
use crate::symmetric::prf::Pseudorandom;

/// Addressed hash used by Winternitz chains and Merkle trees.
pub trait TweakableHash {
    /// Public hash parameter.
    type Parameter: Copy + Send + Sync + Serializable;

    /// Address type.
    type Tweak;

    /// Hash input and output type.
    type Domain: Copy + PartialEq + Send + Sync + Serializable;

    /// Samples the public hash parameter.
    fn rand_parameter<R: RngExt + CryptoRng>(rng: &mut R) -> Self::Parameter;

    /// Samples a domain element for tree padding and tests.
    fn rand_domain<R: RngExt>(rng: &mut R) -> Self::Domain;

    /// Returns a Merkle-tree address distinct from chain addresses.
    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak;

    /// Returns a chain address distinct from tree addresses.
    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak;

    /// Hashes domain elements at an address.
    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain;

    /// Hashes consecutive child pairs into one Merkle-tree layer.
    fn compute_tree_layer(
        parameter: &Self::Parameter,
        level: u8,
        parent_start: usize,
        children: &[Self::Domain],
    ) -> Vec<Self::Domain> {
        children
            .par_chunks_exact(2)
            .enumerate()
            .map(|(i, children)| {
                // Parent index in this layer
                let parent_pos = (parent_start + i) as u32;
                // Hash children into their parent using the tweak
                Self::apply(parameter, &Self::tree_tweak(level, parent_pos), children)
            })
            .collect()
    }

    /// Computes bottom-tree leaves from complete Winternitz chains.
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
        Self: Sized;
}

/// Walks `steps` positions in an addressed hash chain.
#[allow(clippy::too_long_first_doc_paragraph)]
pub fn chain<TH: TweakableHash>(
    parameter: &TH::Parameter,
    epoch: u32,
    chain_index: u8,
    start_pos_in_chain: u8,
    steps: usize,
    start: &TH::Domain,
) -> TH::Domain {
    let mut current = *start;

    for j in 0..steps {
        let tweak = TH::chain_tweak(epoch, chain_index, start_pos_in_chain + (j as u8) + 1u8);
        current = TH::apply(parameter, &tweak, &[current]);
    }

    current
}

pub mod blake3;
pub(crate) mod blake3_simd;

#[cfg(test)]
mod tests {
    use crate::symmetric::tweak_hash::blake3::Blake3TweakHash;

    use super::*;
    use proptest::prelude::*;

    type TestTH = Blake3TweakHash<128>;

    #[test]
    fn test_chain_associative() {
        let mut rng = rand::rng();

        let epoch = 9;
        let chain_index = 20;
        let parameter = TestTH::rand_parameter(&mut rng);
        let start = TestTH::rand_domain(&mut rng);
        let total_steps = 16;

        let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

        for split in 0..=total_steps {
            let steps_a = split;
            let steps_b = total_steps - split;

            let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
            let end_indirect = chain::<TestTH>(
                &parameter,
                epoch,
                chain_index,
                steps_a as u8,
                steps_b,
                &intermediate,
            );

            assert_eq!(end_direct, end_indirect);
        }
    }

    #[test]
    fn test_chain_associative_max_value() {
        let mut rng = rand::rng();

        let epoch = 12;
        let chain_index = 210;
        let parameter = TestTH::rand_parameter(&mut rng);
        let start = TestTH::rand_domain(&mut rng);
        let total_steps = u8::MAX as usize;
        let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

        for split in 0..=total_steps {
            let steps_a = split;
            let steps_b = total_steps - split;

            let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
            let end_indirect = chain::<TestTH>(
                &parameter,
                epoch,
                chain_index,
                steps_a as u8,
                steps_b,
                &intermediate,
            );

            assert_eq!(end_direct, end_indirect);
        }
    }

    proptest! {
        #[test]
        fn proptest_chain_associative(
            epoch in 0u32..100,
            chain_index in 0u8..10,
            total_steps in 0usize..16,
        ) {
            let mut rng = rand::rng();
            let parameter = TestTH::rand_parameter(&mut rng);
            let start = TestTH::rand_domain(&mut rng);
            let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);
            for split in 0..=total_steps {
                let steps_a = split;
                let steps_b = total_steps - split;
                let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
                let end_indirect = chain::<TestTH>(
                    &parameter,
                    epoch,
                    chain_index,
                    steps_a as u8,
                    steps_b,
                    &intermediate,
                );

                prop_assert_eq!(end_direct, end_indirect);
            }
        }
    }
}
