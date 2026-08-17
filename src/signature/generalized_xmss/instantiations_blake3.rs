//! Concrete LeanSig instantiations using BLAKE3 end to end.

/// Instantiations with lifetime 2^18.
pub mod lifetime_2_to_the_18 {
    /// Target-sum incomparable encodings.
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::blake3::Blake3MessageHash, prf::blake3::Blake3Prf,
                tweak_hash::blake3::Blake3TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;

        type MHw1 = Blake3MessageHash<155, 2>;
        type THw1 = Blake3TweakHash<155>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        pub type SIGTargetSumLifetime18W1NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw1<78>, THw1, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime18W1Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw1<86>, THw1, LOG_LIFETIME>;

        type MHw2 = Blake3MessageHash<78, 4>;
        type THw2 = Blake3TweakHash<78>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        pub type SIGTargetSumLifetime18W2NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw2<117>, THw2, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime18W2Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw2<129>, THw2, LOG_LIFETIME>;

        type MHw4 = Blake3MessageHash<39, 16>;
        type THw4 = Blake3TweakHash<39>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        pub type SIGTargetSumLifetime18W4NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw4<293>, THw4, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime18W4Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw4<322>, THw4, LOG_LIFETIME>;

        type MHw8 = Blake3MessageHash<20, 256>;
        type THw8 = Blake3TweakHash<20>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        pub type SIGTargetSumLifetime18W8NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw8<2550>, THw8, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime18W8Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw8<2805>, THw8, LOG_LIFETIME>;

        #[cfg(all(test, feature = "slow-tests"))]
        mod tests {
            use super::*;
            use crate::signature::{
                SignatureScheme, test_templates::test_signature_scheme_correctness,
            };

            #[test]
            fn w1_end_to_end() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W1NoOff>(
                    1032,
                    0,
                    SIGTargetSumLifetime18W1NoOff::LIFETIME as usize,
                );
            }
        }
    }
}

/// Instantiations with lifetime 2^20.
pub mod lifetime_2_to_the_20 {
    /// Target-sum incomparable encodings.
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::blake3::Blake3MessageHash, prf::blake3::Blake3Prf,
                tweak_hash::blake3::Blake3TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;

        type MHw1 = Blake3MessageHash<155, 2>;
        type THw1 = Blake3TweakHash<155>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        pub type SIGTargetSumLifetime20W1NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw1<78>, THw1, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime20W1Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw1<86>, THw1, LOG_LIFETIME>;

        type MHw2 = Blake3MessageHash<78, 4>;
        type THw2 = Blake3TweakHash<78>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        pub type SIGTargetSumLifetime20W2NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw2<117>, THw2, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime20W2Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw2<129>, THw2, LOG_LIFETIME>;

        type MHw4 = Blake3MessageHash<39, 16>;
        type THw4 = Blake3TweakHash<39>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        pub type SIGTargetSumLifetime20W4NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw4<293>, THw4, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime20W4Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw4<322>, THw4, LOG_LIFETIME>;

        type MHw8 = Blake3MessageHash<20, 256>;
        type THw8 = Blake3TweakHash<20>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        pub type SIGTargetSumLifetime20W8NoOff =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw8<2550>, THw8, LOG_LIFETIME>;
        pub type SIGTargetSumLifetime20W8Off10 =
            GeneralizedXMSSSignatureScheme<Blake3Prf, IEw8<2805>, THw8, LOG_LIFETIME>;
    }
}

/// Experimental long-lifetime instantiation using uniform base-8 BLAKE3 chunks.
pub mod lifetime_2_to_the_32 {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::{
            GeneralizedXMSSPublicKey, GeneralizedXMSSSecretKey, GeneralizedXMSSSignature,
            GeneralizedXMSSSignatureScheme,
        },
        symmetric::{
            message_hash::blake3::Blake3MessageHash, prf::blake3::Blake3Prf,
            tweak_hash::blake3::Blake3TweakHash,
        },
    };

    type MH = Blake3MessageHash<46, 8>;
    type TH = Blake3TweakHash<46>;
    type IE = TargetSumEncoding<MH, 200>;

    pub type SIGTargetSumLifetime32Dim46Base8 =
        GeneralizedXMSSSignatureScheme<Blake3Prf, IE, TH, 32>;
    pub type PubKeyTargetSumLifetime32Dim46Base8 = GeneralizedXMSSPublicKey<TH>;
    pub type SecretKeyTargetSumLifetime32Dim46Base8 =
        GeneralizedXMSSSecretKey<Blake3Prf, IE, TH, 32>;
    pub type SigTargetSumLifetime32Dim46Base8 = GeneralizedXMSSSignature<IE, TH>;
}

/// Small testing-only instantiation.
#[cfg(test)]
pub mod testing {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
        symmetric::{
            message_hash::blake3::Blake3MessageHash, prf::blake3::Blake3Prf,
            tweak_hash::blake3::Blake3TweakHash,
        },
    };

    type MH = Blake3MessageHash<16, 2>;
    type IE = TargetSumEncoding<MH, 8>;
    type TH = Blake3TweakHash<16>;
    pub type TestScheme = GeneralizedXMSSSignatureScheme<Blake3Prf, IE, TH, 8>;
}
