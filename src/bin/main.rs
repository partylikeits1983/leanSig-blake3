use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W2NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W8NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W1NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W2NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W4NoOff;
use leansig::signature::generalized_xmss::instantiations_blake3::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W8NoOff;
use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngExt};
use std::time::Instant;

fn measure_time<T: SignatureScheme, R: RngExt + CryptoRng>(description: &str, rng: &mut R) {
    let start = Instant::now();
    let (_pk, _sk) = T::key_gen(rng, 0, T::LIFETIME as usize);
    let duration = start.elapsed();
    println!("{description} - Gen: {duration:?}");
}

fn main() {
    let mut rng = rand::rng();

    measure_time::<SIGTargetSumLifetime18W1NoOff, ThreadRng>(
        "BLAKE3 - L 18 - Target Sum - w 1",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W2NoOff, ThreadRng>(
        "BLAKE3 - L 18 - Target Sum - w 2",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W4NoOff, ThreadRng>(
        "BLAKE3 - L 18 - Target Sum - w 4",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W8NoOff, ThreadRng>(
        "BLAKE3 - L 18 - Target Sum - w 8",
        &mut rng,
    );

    measure_time::<SIGTargetSumLifetime20W1NoOff, ThreadRng>(
        "BLAKE3 - L 20 - Target Sum - w 1",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W2NoOff, ThreadRng>(
        "BLAKE3 - L 20 - Target Sum - w 2",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W4NoOff, ThreadRng>(
        "BLAKE3 - L 20 - Target Sum - w 4",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W8NoOff, ThreadRng>(
        "BLAKE3 - L 20 - Target Sum - w 8",
        &mut rng,
    );
}
