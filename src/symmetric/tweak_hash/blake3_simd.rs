//! Pure-Rust SIMD helpers for batches of independent BLAKE3 invocations.
//!
//! This module implements only the fixed 70-byte derive-key-material hash used
//! by BLAKE3 Winternitz chains. The scalar BLAKE3 hasher remains the source of
//! truth, and differential tests ensure byte-for-byte compatibility.

// These functions implement the BLAKE3 compression round directly. Keeping
// the tiny vector operations inlined is important to avoid call overhead in
// the innermost key-generation loop.
#![allow(clippy::inline_always)]

use crate::HASH_LENGTH;

pub const SIMD_LANES: usize = 4;

#[cfg(target_arch = "aarch64")]
mod neon {
    use core::arch::aarch64::{
        uint8x16_t, uint16x8_t, uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u32,
        vqtbl1q_u8, vreinterpretq_u8_u32, vreinterpretq_u16_u32, vreinterpretq_u32_u8,
        vreinterpretq_u32_u16, vrev32q_u16, vshlq_n_u32, vsriq_n_u32, vst1q_u32,
    };

    use super::{HASH_LENGTH, SIMD_LANES};

    const BLOCK_LEN: usize = 64;
    const IV: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    const CHUNK_START: u8 = 1 << 0;
    const CHUNK_END: u8 = 1 << 1;
    const ROOT: u8 = 1 << 3;
    const KEYED_HASH: u8 = 1 << 4;
    const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

    #[derive(Clone, Copy)]
    #[repr(transparent)]
    struct V(uint32x4_t);

    impl V {
        #[inline(always)]
        fn splat(value: u32) -> Self {
            // SAFETY: AArch64 guarantees NEON support.
            Self(unsafe { vdupq_n_u32(value) })
        }

        #[inline(always)]
        fn from_lanes(lanes: [u32; SIMD_LANES]) -> Self {
            // SAFETY: lanes contains four initialized u32 values.
            Self(unsafe { vld1q_u32(lanes.as_ptr()) })
        }

        #[inline(always)]
        fn to_lanes(self) -> [u32; SIMD_LANES] {
            let mut lanes = [0; SIMD_LANES];
            // SAFETY: lanes has room for four u32 values.
            unsafe { vst1q_u32(lanes.as_mut_ptr(), self.0) };
            lanes
        }

        #[inline(always)]
        fn wrapping_add(self, rhs: Self) -> Self {
            // SAFETY: AArch64 guarantees NEON support.
            Self(unsafe { vaddq_u32(self.0, rhs.0) })
        }

        #[inline(always)]
        fn xor(self, rhs: Self) -> Self {
            // SAFETY: AArch64 guarantees NEON support.
            Self(unsafe { veorq_u32(self.0, rhs.0) })
        }

        #[inline(always)]
        fn rotate_right_16(self) -> Self {
            // SAFETY: Reinterpretations preserve all bits.
            let words: uint16x8_t = unsafe { vreinterpretq_u16_u32(self.0) };
            Self(unsafe { vreinterpretq_u32_u16(vrev32q_u16(words)) })
        }

        #[inline(always)]
        fn rotate_right_12(self) -> Self {
            // SAFETY: AArch64 guarantees NEON support.
            Self(unsafe { vsriq_n_u32::<12>(vshlq_n_u32::<20>(self.0), self.0) })
        }

        #[inline(always)]
        fn rotate_right_8(self) -> Self {
            const ROTATE_BYTES: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
            // SAFETY: All table indices address bytes within the input vector.
            let bytes: uint8x16_t = unsafe { vreinterpretq_u8_u32(self.0) };
            let table = unsafe { core::arch::aarch64::vld1q_u8(ROTATE_BYTES.as_ptr()) };
            Self(unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(bytes, table)) })
        }

        #[inline(always)]
        fn rotate_right_7(self) -> Self {
            // SAFETY: AArch64 guarantees NEON support.
            Self(unsafe { vsriq_n_u32::<7>(vshlq_n_u32::<25>(self.0), self.0) })
        }
    }

    #[inline(always)]
    fn g(state: &mut [V; 16], a: usize, b: usize, c: usize, d: usize, x: V, y: V) {
        let mut va = state[a];
        let mut vb = state[b];
        let mut vc = state[c];
        let mut vd = state[d];

        va = va.wrapping_add(vb).wrapping_add(x);
        vd = vd.xor(va).rotate_right_16();
        vc = vc.wrapping_add(vd);
        vb = vb.xor(vc).rotate_right_12();
        va = va.wrapping_add(vb).wrapping_add(y);
        vd = vd.xor(va).rotate_right_8();
        vc = vc.wrapping_add(vd);
        vb = vb.xor(vc).rotate_right_7();

        state[a] = va;
        state[b] = vb;
        state[c] = vc;
        state[d] = vd;
    }

    #[inline(always)]
    fn round(state: &mut [V; 16], message: &[V; 16], schedule: &[usize; 16]) {
        g(
            state,
            0,
            4,
            8,
            12,
            message[schedule[0]],
            message[schedule[1]],
        );
        g(
            state,
            1,
            5,
            9,
            13,
            message[schedule[2]],
            message[schedule[3]],
        );
        g(
            state,
            2,
            6,
            10,
            14,
            message[schedule[4]],
            message[schedule[5]],
        );
        g(
            state,
            3,
            7,
            11,
            15,
            message[schedule[6]],
            message[schedule[7]],
        );
        g(
            state,
            0,
            5,
            10,
            15,
            message[schedule[8]],
            message[schedule[9]],
        );
        g(
            state,
            1,
            6,
            11,
            12,
            message[schedule[10]],
            message[schedule[11]],
        );
        g(
            state,
            2,
            7,
            8,
            13,
            message[schedule[12]],
            message[schedule[13]],
        );
        g(
            state,
            3,
            4,
            9,
            14,
            message[schedule[14]],
            message[schedule[15]],
        );
    }

    fn words4(blocks: &[[u8; BLOCK_LEN]; SIMD_LANES]) -> [V; 16] {
        core::array::from_fn(|word| {
            let offset = word * 4;
            V::from_lanes(core::array::from_fn(|lane| {
                u32::from_le_bytes(
                    blocks[lane][offset..offset + 4]
                        .try_into()
                        .expect("four-byte word"),
                )
            }))
        })
    }

    #[inline]
    fn compress4(
        chaining_values: &mut [V; 8],
        blocks: &[[u8; BLOCK_LEN]; SIMD_LANES],
        block_len: u32,
        flags: u8,
    ) {
        let message = words4(blocks);
        let mut state = [
            chaining_values[0],
            chaining_values[1],
            chaining_values[2],
            chaining_values[3],
            chaining_values[4],
            chaining_values[5],
            chaining_values[6],
            chaining_values[7],
            V::splat(IV[0]),
            V::splat(IV[1]),
            V::splat(IV[2]),
            V::splat(IV[3]),
            V::splat(0),
            V::splat(0),
            V::splat(block_len),
            V::splat(u32::from(flags)),
        ];

        for schedule in &MSG_SCHEDULE {
            round(&mut state, &message, schedule);
        }
        for i in 0..8 {
            chaining_values[i] = state[i].xor(state[i + 8]);
        }
    }

    pub(super) fn hash_derive_key_material_70(
        context_key: &[u8; HASH_LENGTH],
        inputs: &[[u8; 70]; SIMD_LANES],
    ) -> [[u8; HASH_LENGTH]; SIMD_LANES] {
        let context_words: [u32; 8] = core::array::from_fn(|word| {
            let offset = word * 4;
            u32::from_le_bytes(
                context_key[offset..offset + 4]
                    .try_into()
                    .expect("four-byte word"),
            )
        });
        let mut chaining_values = context_words.map(V::splat);

        let first_blocks: [[u8; BLOCK_LEN]; SIMD_LANES] =
            core::array::from_fn(|lane| inputs[lane][..BLOCK_LEN].try_into().expect("full block"));
        compress4(
            &mut chaining_values,
            &first_blocks,
            BLOCK_LEN as u32,
            DERIVE_KEY_MATERIAL | CHUNK_START,
        );

        let last_blocks: [[u8; BLOCK_LEN]; SIMD_LANES] = core::array::from_fn(|lane| {
            let mut block = [0; BLOCK_LEN];
            block[..6].copy_from_slice(&inputs[lane][BLOCK_LEN..]);
            block
        });
        compress4(
            &mut chaining_values,
            &last_blocks,
            6,
            DERIVE_KEY_MATERIAL | CHUNK_END | ROOT,
        );

        let transposed: [[u32; SIMD_LANES]; 8] = chaining_values.map(V::to_lanes);
        core::array::from_fn(|lane| {
            let mut output = [0; HASH_LENGTH];
            for word in 0..8 {
                output[word * 4..word * 4 + 4]
                    .copy_from_slice(&transposed[word][lane].to_le_bytes());
            }
            output
        })
    }

    pub(super) fn keyed_hash<const INPUT_LEN: usize>(
        key: &[u8; HASH_LENGTH],
        inputs: &[[u8; INPUT_LEN]; SIMD_LANES],
    ) -> [[u8; HASH_LENGTH]; SIMD_LANES] {
        assert!(INPUT_LEN <= BLOCK_LEN);
        let key_words: [u32; 8] = core::array::from_fn(|word| {
            let offset = word * 4;
            u32::from_le_bytes(key[offset..offset + 4].try_into().expect("four-byte word"))
        });
        let mut chaining_values = key_words.map(V::splat);
        let blocks: [[u8; BLOCK_LEN]; SIMD_LANES] = core::array::from_fn(|lane| {
            let mut block = [0; BLOCK_LEN];
            block[..INPUT_LEN].copy_from_slice(&inputs[lane]);
            block
        });
        compress4(
            &mut chaining_values,
            &blocks,
            INPUT_LEN as u32,
            KEYED_HASH | CHUNK_START | CHUNK_END | ROOT,
        );

        let transposed: [[u32; SIMD_LANES]; 8] = chaining_values.map(V::to_lanes);
        core::array::from_fn(|lane| {
            let mut output = [0; HASH_LENGTH];
            for word in 0..8 {
                output[word * 4..word * 4 + 4]
                    .copy_from_slice(&transposed[word][lane].to_le_bytes());
            }
            output
        })
    }
}

pub fn keyed_hash_4<const INPUT_LEN: usize>(
    key: &[u8; HASH_LENGTH],
    inputs: &[[u8; INPUT_LEN]; SIMD_LANES],
) -> [[u8; HASH_LENGTH]; SIMD_LANES] {
    #[cfg(target_arch = "aarch64")]
    {
        neon::keyed_hash(key, inputs)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        inputs.map(|input| *blake3::keyed_hash(key, &input).as_bytes())
    }
}

pub fn chain_4(
    context_key: &[u8; HASH_LENGTH],
    parameter: &[u8; HASH_LENGTH],
    epochs: [u32; SIMD_LANES],
    chain_index: u8,
    start_position: u8,
    steps: usize,
    starts: [[u8; HASH_LENGTH]; SIMD_LANES],
) -> [[u8; HASH_LENGTH]; SIMD_LANES] {
    let mut values = starts;
    for step in 0..steps {
        let position = start_position + step as u8 + 1;
        let inputs: [[u8; 70]; SIMD_LANES] = core::array::from_fn(|lane| {
            let mut input = [0; 70];
            input[..32].copy_from_slice(parameter);
            input[32..36].copy_from_slice(&epochs[lane].to_le_bytes());
            input[36] = chain_index;
            input[37] = position;
            input[38..].copy_from_slice(&values[lane]);
            input
        });

        #[cfg(target_arch = "aarch64")]
        {
            values = neon::hash_derive_key_material_70(context_key, &inputs);
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            values = inputs.map(|input| {
                use blake3::hazmat::HasherExt;
                let mut hasher = blake3::Hasher::new_from_context_key(context_key);
                hasher.update(&input);
                *hasher.finalize().as_bytes()
            });
        }
    }
    values
}
