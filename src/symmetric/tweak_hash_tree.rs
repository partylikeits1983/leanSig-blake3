use crate::serialization::Serializable;
use crate::symmetric::tweak_hash::TweakableHash;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

/// One layer of a sparse Merkle tree.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
struct HashTreeLayer<TH: TweakableHash> {
    start_index: u64,
    nodes: Vec<TH::Domain>,
}

impl<TH: TweakableHash> Encode for HashTreeLayer<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        8 + 4 + self.nodes.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.start_index.ssz_append(buf);
        let offset: u32 = 12;
        buf.extend_from_slice(&offset.to_le_bytes());
        self.nodes.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashTreeLayer<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        const FIXED_SIZE: usize = 12;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        let start_index = u64::from_ssz_bytes(&bytes[0..8])?;
        let offset = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 12,
            }
        })?) as usize;

        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        let nodes = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self { start_index, nodes })
    }
}

impl<TH: TweakableHash> Serializable for HashTreeLayer<TH> {}

impl<TH: TweakableHash> HashTreeLayer<TH> {
    /// Pads a contiguous layer to begin with a left child and end with a right child.
    #[inline]
    fn padded<R: RngExt>(rng: &mut R, nodes: Vec<TH::Domain>, start_index: usize) -> Self {
        let end_index = start_index + nodes.len() - 1;
        let needs_front = (start_index & 1) == 1;
        let needs_back = (end_index & 1) == 0;
        let actual_start_index = start_index - (needs_front as usize);
        let mut out =
            Vec::with_capacity(nodes.len() + (needs_front as usize) + (needs_back as usize));
        if needs_front {
            out.push(TH::rand_domain(rng));
        }
        out.extend(nodes);
        if needs_back {
            out.push(TH::rand_domain(rng));
        }
        Self {
            start_index: actual_start_index as u64,
            nodes: out,
        }
    }
}

/// A contiguous subtree of a sparse Merkle tree.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HashSubTree<TH: TweakableHash> {
    /// Depth of the full tree.
    depth: u64,

    /// Lowest layer retained by this subtree.
    lowest_layer: u64,

    /// Layers in bottom-to-root order. Layer zero contains hashed leaves.
    layers: Vec<HashTreeLayer<TH>>,
}

impl<TH: TweakableHash> Encode for HashSubTree<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        8 + 8 + 4 + self.layers.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.depth.ssz_append(buf);
        self.lowest_layer.ssz_append(buf);
        let offset: u32 = 20;
        buf.extend_from_slice(&offset.to_le_bytes());
        self.layers.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashSubTree<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        const FIXED_SIZE: usize = 20;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        let depth = u64::from_ssz_bytes(&bytes[0..8])?;
        let lowest_layer = u64::from_ssz_bytes(&bytes[8..16])?;
        let offset = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 20,
            }
        })?) as usize;

        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        let layers = Vec::<HashTreeLayer<TH>>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self {
            depth,
            lowest_layer,
            layers,
        })
    }
}

/// A Merkle authentication path, excluding the leaf.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct HashTreeOpening<TH: TweakableHash> {
    co_path: Vec<TH::Domain>,
}

impl<TH: TweakableHash> Encode for HashTreeOpening<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        4 + self.co_path.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset: u32 = 4;
        buf.extend_from_slice(&offset.to_le_bytes());
        self.co_path.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashTreeOpening<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        const FIXED_SIZE: usize = 4;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        let offset = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 4,
            }
        })?) as usize;

        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        let co_path = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self { co_path })
    }
}

impl<TH: TweakableHash> Serializable for HashTreeOpening<TH> {}

impl<TH: TweakableHash> Serializable for HashSubTree<TH> {}

impl<TH> HashSubTree<TH>
where
    TH: TweakableHash,
{
    /// Builds from a contiguous run of nodes at `lowest_layer` up to the root.
    ///
    /// The input nodes must fit at `start_index`. The RNG supplies sparse padding.
    pub fn new_subtree<R: RngExt>(
        rng: &mut R,
        lowest_layer: usize,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        lowest_layer_nodes: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            lowest_layer < depth,
            "Hash-Tree new: lowest_layer exceeds depth. Ensure that it is between 0 and depth - 1."
        );

        assert!(
            start_index + lowest_layer_nodes.len() <= 1 << (depth - lowest_layer),
            "Hash-Tree new: Not enough space for lowest layer nodes. Consider changing start_index or number of lowest layer nodes."
        );

        let mut layers = Vec::with_capacity(depth + 1 - lowest_layer);
        layers.push(HashTreeLayer::padded(rng, lowest_layer_nodes, start_index));
        for level in lowest_layer..depth {
            let prev = &layers[level - lowest_layer];
            let parent_start = (prev.start_index >> 1) as usize;
            let parents =
                TH::compute_tree_layer(parameter, level as u8 + 1, parent_start, &prev.nodes);
            layers.push(HashTreeLayer::padded(rng, parents, parent_start));
        }

        Self {
            depth: depth as u64,
            lowest_layer: lowest_layer as u64,
            layers,
        }
    }

    /// Builds the upper half of an even-depth tree from bottom-tree roots.
    pub fn new_top_tree<R: RngExt>(
        rng: &mut R,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        roots_of_bottom_trees: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth.is_multiple_of(2),
            "Hash-Tree new top tree: Depth must be even."
        );

        let lowest_layer = depth / 2;
        let lowest_layer_nodes = roots_of_bottom_trees;
        Self::new_subtree(
            rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        )
    }

    /// Builds one full bottom tree in an even-depth tree.
    pub fn new_bottom_tree(
        depth: usize,
        bottom_tree_index: usize,
        parameter: &TH::Parameter,
        leafs: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth > 2 && depth.is_multiple_of(2),
            "Hash-Tree new bottom tree: Depth must be even and more than 2."
        );

        assert!(
            leafs.len() == 1 << (depth / 2),
            "Hash-Tree new bottom tree: Bottom trees must be full, not sparse."
        );

        // A full bottom tree does not retain padding, so a fixed local RNG is sufficient.
        let mut dummy_rng = StdRng::seed_from_u64(0);
        let leafs_per_bottom_tree = 1 << (depth / 2);
        let lowest_layer = 0;
        let lowest_layer_nodes = leafs;
        let start_index = bottom_tree_index * leafs_per_bottom_tree;
        let mut bottom_tree = Self::new_subtree(
            &mut dummy_rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        );

        // Discard layers above this bottom tree and retain its root alone.
        let bottom_tree_root = bottom_tree.layers[depth / 2].nodes[bottom_tree_index % 2];
        bottom_tree.layers.truncate(depth / 2);
        bottom_tree.layers.push(HashTreeLayer {
            start_index: bottom_tree_index as u64,
            nodes: vec![bottom_tree_root],
        });

        bottom_tree
    }

    /// Returns this subtree's root.
    #[must_use]
    pub fn root(&self) -> TH::Domain {
        self.layers
            .last()
            .expect("Hash-Tree must have at least one layer")
            .nodes[0]
    }

    /// Computes the path for a node in the lowest retained layer.
    #[must_use]
    pub fn path(&self, position: u32) -> HashTreeOpening<TH> {
        assert!(
            !self.layers.is_empty(),
            "Hash-Tree path: Need at least one layer"
        );
        assert!(
            (position as u64) >= self.layers[0].start_index,
            "Hash-Tree path: Invalid position, position before start index"
        );
        assert!(
            (position as u64) < self.layers[0].start_index + self.layers[0].nodes.len() as u64,
            "Hash-Tree path: Invalid position, position too large"
        );

        let mut co_path = Vec::with_capacity(self.depth as usize);
        let mut current_position = position;
        for l in 0..((self.depth - self.lowest_layer) as usize) {
            if self.layers[l].nodes.len() <= 1 {
                break;
            }
            let sibling_position = current_position ^ 0x01;
            let sibling_position_in_vec =
                (sibling_position as u64 - self.layers[l].start_index) as usize;
            let sibling = self.layers[l].nodes[sibling_position_in_vec];
            co_path.push(sibling);
            current_position >>= 1;
        }

        HashTreeOpening { co_path }
    }
}

/// Joins authentication paths from matching top and bottom trees.
#[must_use]
pub fn combined_path<TH: TweakableHash>(
    top_tree: &HashSubTree<TH>,
    bottom_tree: &HashSubTree<TH>,
    position: u32,
) -> HashTreeOpening<TH> {
    assert!(
        bottom_tree.depth == top_tree.depth,
        "Hash-Tree combined path: Bottom tree and top tree must have the same depth."
    );

    assert!(
        bottom_tree.depth.is_multiple_of(2),
        "Hash-Tree combined path: Tree depth must be even."
    );
    let depth = bottom_tree.depth;
    assert!(
        bottom_tree.layers[0]
            .start_index
            .is_multiple_of(1 << (depth / 2)),
        "Hash-Tree combined path: Bottom tree start index must be multiple of 1 << depth/2."
    );
    let bottom_tree_index = bottom_tree.layers[0].start_index / (1 << (depth / 2));

    let bottom_opening = bottom_tree.path(position);
    let top_opening = top_tree.path(bottom_tree_index as u32);
    let co_path = [bottom_opening.co_path, top_opening.co_path].concat();

    HashTreeOpening { co_path }
}

/// Verifies a Merkle authentication path.
///
/// `leaf` contains the chain ends; verification hashes them into the leaf node.
pub fn hash_tree_verify<TH: TweakableHash>(
    parameter: &TH::Parameter,
    root: &TH::Domain,
    position: u32,
    leaf: &[TH::Domain],
    opening: &HashTreeOpening<TH>,
) -> bool {
    let depth = opening.co_path.len();
    if depth > 32 {
        return false;
    }
    let num_leafs: u64 = 1 << depth;
    if (position as u64) >= num_leafs {
        return false;
    }

    debug_assert!((position as u64) < num_leafs);

    let tweak = TH::tree_tweak(0, position);
    let mut current_node = TH::apply(parameter, &tweak, leaf);

    let mut current_position = position;
    for l in 0..depth {
        let children = if current_position.is_multiple_of(2) {
            [current_node, opening.co_path[l]]
        } else {
            [opening.co_path[l], current_node]
        };
        current_position >>= 1;
        let tweak = TH::tree_tweak((l + 1) as u8, current_position);
        current_node = TH::apply(parameter, &tweak, &children);
    }

    current_node == *root
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use crate::symmetric::tweak_hash::blake3::Blake3TweakHash;

    use super::*;

    type TestTH = Blake3TweakHash<128>;

    fn test_commit_open_helper(
        num_leafs: usize,
        depth: usize,
        start_index: usize,
        leaf_len: usize,
    ) {
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let mut leaf = Vec::new();
            for _ in 0..leaf_len {
                leaf.push(TestTH::rand_domain(&mut rng));
            }
            leafs.push(leaf);
        }

        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (i + start_index) as u32),
                    v.as_slice(),
                )
            })
            .collect();

        let tree = HashSubTree::<TestTH>::new_subtree(
            &mut rng,
            0,
            depth,
            start_index,
            &parameter,
            leafs_hashes,
        );

        let root = tree.root();
        for (offset, leaf) in leafs.iter().enumerate().take(num_leafs) {
            let position = start_index as u32 + offset as u32;
            let path = tree.path(position);
            assert!(hash_tree_verify(&parameter, &root, position, leaf, &path));
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree() {
        let num_leafs = 1024;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_left() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 5;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_large() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 512;
        let leaf_len = 10;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_small() {
        let num_leafs = 2;
        let depth = 2;
        let start_index: usize = 2;
        let leaf_len = 6;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_sparse_non_aligned() {
        let num_leafs = 213;
        let depth = 10;
        let start_index: usize = 217;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    proptest! {
        #[test]
        fn proptest_commit_open_verify(
            num_leafs in 1usize..32,
            depth in 3usize..7,
            start_index in 0usize..64,
            leaf_len in 1usize..5,
        ) {
            prop_assume!(start_index + num_leafs <= 1 << depth);

            test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
        }
    }

    fn test_commit_open_helper_top_bottom(
        num_bottom_trees: usize,
        depth: usize,
        start_bottom_tree_index: usize,
        leaf_len: usize,
    ) {
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        let leafs_per_bottom_tree = 1 << (depth / 2);
        let num_leafs = num_bottom_trees * leafs_per_bottom_tree;
        let start_index = start_bottom_tree_index * leafs_per_bottom_tree;
        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let mut leaf = Vec::new();
            for _ in 0..leaf_len {
                leaf.push(TestTH::rand_domain(&mut rng));
            }
            leafs.push(leaf);
        }

        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (i + start_index) as u32),
                    v.as_slice(),
                )
            })
            .collect();

        let mut bottom_trees = Vec::with_capacity(num_bottom_trees);
        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let leafs_end = leafs_start + leafs_per_bottom_tree;
            let bottom_tree = HashSubTree::<TestTH>::new_bottom_tree(
                depth,
                bottom_tree_index,
                &parameter,
                leafs_hashes[leafs_start..leafs_end].to_vec(),
            );
            roots_of_bottom_trees.push(bottom_tree.root());
            bottom_trees.push(bottom_tree);
        }
        let top_tree = HashSubTree::<TestTH>::new_top_tree(
            &mut rng,
            depth,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );

        let root = top_tree.root();
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let bottom_tree = &bottom_trees[bottom_tree_index - start_bottom_tree_index];

            for l in 0..leafs_per_bottom_tree {
                let offset = leafs_start + l;
                let leaf = leafs[offset].clone();
                let position = start_index as u32 + offset as u32;
                let path = combined_path(&top_tree, bottom_tree, position);
                assert!(hash_tree_verify(&parameter, &root, position, &leaf, &path));
            }
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree_top_bottom() {
        let num_bottom_trees = 4;
        let depth = 4;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_left_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 8;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_middle_tree_right_top_bottom() {
        let num_bottom_trees = 7;
        let depth = 8;
        let start_bottom_tree_index: usize = 4;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_ssz_encoding_structure() {
        let mut rng = rand::rng();

        let nodes: Vec<_> = (0..3).map(|_| TestTH::rand_domain(&mut rng)).collect();
        let layer = HashTreeLayer::<TestTH> {
            start_index: 256,
            nodes,
        };
        let encoded = layer.as_ssz_bytes();
        assert!(encoded.len() >= 12);
        assert_eq!(u64::from_le_bytes(encoded[0..8].try_into().unwrap()), 256);
        assert_eq!(u32::from_le_bytes(encoded[8..12].try_into().unwrap()), 12);

        let tree = HashSubTree::<TestTH> {
            depth: 16,
            lowest_layer: 8,
            layers: vec![],
        };
        let encoded = tree.as_ssz_bytes();
        assert!(encoded.len() >= 20);
        assert_eq!(u64::from_le_bytes(encoded[0..8].try_into().unwrap()), 16);
        assert_eq!(u64::from_le_bytes(encoded[8..16].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(encoded[16..20].try_into().unwrap()), 20);

        let co_path: Vec<_> = (0..5).map(|_| TestTH::rand_domain(&mut rng)).collect();
        let opening = HashTreeOpening::<TestTH> { co_path };
        let encoded = opening.as_ssz_bytes();
        assert!(encoded.len() >= 4);
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), 4);
    }

    #[test]
    fn test_ssz_decoding_errors() {
        let encoded = vec![0u8; 8];
        let result = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        let mut encoded = vec![0u8; 12];
        encoded[0..8].copy_from_slice(&0u64.to_le_bytes());
        encoded[8..12].copy_from_slice(&99u32.to_le_bytes());
        let result = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 12, .. })
        ));

        let encoded = vec![0u8; 16];
        let result = HashSubTree::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        let mut encoded = vec![0u8; 20];
        encoded[0..8].copy_from_slice(&10u64.to_le_bytes());
        encoded[8..16].copy_from_slice(&5u64.to_le_bytes());
        encoded[16..20].copy_from_slice(&100u32.to_le_bytes());
        let result = HashSubTree::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 20, .. })
        ));

        let encoded = vec![0u8; 2];
        let result = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        let mut encoded = vec![0u8; 4];
        encoded[0..4].copy_from_slice(&10u32.to_le_bytes());
        let result = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 4, .. })
        ));

        let opening = HashTreeOpening::<TestTH> {
            co_path: vec![[0u8; 32]; 33],
        };
        assert!(!hash_tree_verify(&[0u8; 32], &[0u8; 32], 0, &[], &opening));
    }

    #[test]
    fn test_ssz_determinism() {
        let mut rng = rand::rng();

        let nodes: Vec<_> = (0..7).map(|_| TestTH::rand_domain(&mut rng)).collect();
        let layer = HashTreeLayer::<TestTH> {
            start_index: 999,
            nodes,
        };
        let encoded1 = layer.as_ssz_bytes();
        let encoded2 = layer.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);

        let layer = HashTreeLayer::<TestTH> {
            start_index: 4,
            nodes: (0..6).map(|_| TestTH::rand_domain(&mut rng)).collect(),
        };
        let tree = HashSubTree::<TestTH> {
            depth: 20,
            lowest_layer: 10,
            layers: vec![layer],
        };
        let encoded1 = tree.as_ssz_bytes();
        let encoded2 = tree.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);

        let co_path: Vec<_> = (0..15).map(|_| TestTH::rand_domain(&mut rng)).collect();
        let opening = HashTreeOpening::<TestTH> { co_path };
        let encoded1 = opening.as_ssz_bytes();
        let encoded2 = opening.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_ssz_merkle_integration() {
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        let num_leafs = 8;
        let depth = 3;
        let start_index = 0;
        let leaf_len = 2;
        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let leaf: Vec<_> = (0..leaf_len)
                .map(|_| TestTH::rand_domain(&mut rng))
                .collect();
            leafs.push(leaf);
        }
        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| TestTH::apply(&parameter, &TestTH::tree_tweak(0, i as u32), v.as_slice()))
            .collect();
        let tree = HashSubTree::<TestTH>::new_subtree(
            &mut rng,
            0,
            depth,
            start_index,
            &parameter,
            leafs_hashes,
        );
        let root = tree.root();

        let tree_encoded = tree.as_ssz_bytes();
        let tree_decoded = HashSubTree::<TestTH>::from_ssz_bytes(&tree_encoded).unwrap();
        assert_eq!(root, tree_decoded.root());

        let position = 3u32;
        let path = tree.path(position);
        let leaf = &leafs[position as usize];

        let path_encoded = path.as_ssz_bytes();
        let path_decoded = HashTreeOpening::<TestTH>::from_ssz_bytes(&path_encoded).unwrap();

        assert!(hash_tree_verify(
            &parameter,
            &root,
            position,
            leaf,
            &path_decoded
        ));

        let path_from_decoded = tree_decoded.path(position);
        assert!(hash_tree_verify(
            &parameter,
            &root,
            position,
            leaf,
            &path_from_decoded
        ));
    }

    proptest! {
        #[test]
        fn proptest_hash_tree_layer_ssz_roundtrip(
            start_index in 0u64..1000,
            num_nodes in 0usize..20,
        ) {
            let mut rng = rand::rng();
            let nodes: Vec<_> = (0..num_nodes).map(|_| TestTH::rand_domain(&mut rng)).collect();
            let layer = HashTreeLayer::<TestTH> {
                start_index,
                nodes,
            };

            let encoded = layer.as_ssz_bytes();
            let decoded = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(layer.start_index, decoded.start_index);
            prop_assert_eq!(layer.nodes.len(), decoded.nodes.len());
            for i in 0..layer.nodes.len() {
                prop_assert_eq!(layer.nodes[i], decoded.nodes[i]);
            }
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }

        #[test]
        fn proptest_hash_sub_tree_ssz_roundtrip(
            depth in 1u64..32,
            lowest_layer in 0u64..16,
            num_layers in 0usize..5,
        ) {
            prop_assume!(lowest_layer < depth);
            let mut rng = rand::rng();
            let mut layers = Vec::new();
            for _ in 0..num_layers {
                let num_nodes = rng.random_range(0..10);
                let layer = HashTreeLayer::<TestTH> {
                    start_index: rng.random_range(0..100),
                    nodes: (0..num_nodes).map(|_| TestTH::rand_domain(&mut rng)).collect(),
                };
                layers.push(layer);
            }
            let tree = HashSubTree::<TestTH> {
                depth,
                lowest_layer,
                layers,
            };

            let encoded = tree.as_ssz_bytes();
            let decoded = HashSubTree::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(tree.depth, decoded.depth);
            prop_assert_eq!(tree.lowest_layer, decoded.lowest_layer);
            prop_assert_eq!(tree.layers.len(), decoded.layers.len());
            for i in 0..tree.layers.len() {
                prop_assert_eq!(tree.layers[i].start_index, decoded.layers[i].start_index);
                prop_assert_eq!(tree.layers[i].nodes.len(), decoded.layers[i].nodes.len());
            }
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }

        #[test]
        fn proptest_hash_tree_opening_ssz_roundtrip(
            co_path_len in 0usize..64,
        ) {
            let mut rng = rand::rng();
            let co_path: Vec<_> = (0..co_path_len).map(|_| TestTH::rand_domain(&mut rng)).collect();
            let opening = HashTreeOpening::<TestTH> { co_path };
            let encoded = opening.as_ssz_bytes();
            let decoded = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(opening.co_path.len(), decoded.co_path.len());
            for i in 0..opening.co_path.len() {
                prop_assert_eq!(opening.co_path[i], decoded.co_path[i]);
            }
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }
    }
}
