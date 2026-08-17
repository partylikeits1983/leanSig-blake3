//! Small reproducible end-to-end performance harness.

use std::time::{Duration, Instant};

use leansig::{
    MESSAGE_LENGTH,
    serialization::Serializable,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1NoOff,
    },
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn configured_runs(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn print_stats(name: &str, samples: &[Duration]) {
    let mut nanos: Vec<u128> = samples.iter().map(Duration::as_nanos).collect();
    nanos.sort_unstable();
    let sum: u128 = nanos.iter().sum();
    let mean = sum / nanos.len() as u128;
    let median = nanos[nanos.len() / 2];
    let p95 = nanos[(nanos.len() * 95).div_ceil(100) - 1];
    println!("{name}_runs={}", nanos.len());
    println!("{name}_mean_ns={mean}");
    println!("{name}_median_ns={median}");
    println!("{name}_p95_ns={p95}");
}

fn benchmark<S: SignatureScheme>(label: &str) {
    let keygen_runs = configured_runs("LEANSIG_KEYGEN_RUNS", 3);
    let sign_runs = configured_runs("LEANSIG_SIGN_RUNS", 200);
    let mut keygen_samples = Vec::with_capacity(keygen_runs);
    let mut keypair = None;

    for run in 0..keygen_runs {
        let mut rng = StdRng::seed_from_u64(0x5eed_0000 + run as u64);
        let started = Instant::now();
        let generated = S::key_gen(&mut rng, 0, S::LIFETIME as usize);
        keygen_samples.push(started.elapsed());
        keypair = Some(generated);
    }

    let (pk, mut sk) = keypair.expect("at least one keygen run");
    let prepared = sk.get_prepared_interval();
    let initial_secret_key_bytes = sk.to_bytes().len();
    assert!(sign_runs <= (prepared.end - prepared.start) as usize);

    let mut rng = StdRng::seed_from_u64(0x51a0_0001);
    let mut sign_samples = Vec::with_capacity(sign_runs);
    let mut cases = Vec::with_capacity(sign_runs);
    for i in 0..sign_runs {
        let epoch = prepared.start as u32 + i as u32;
        let message: [u8; MESSAGE_LENGTH] = rng.random();
        let started = Instant::now();
        let signature = S::sign(&mut sk, epoch, &message).expect("benchmark signing must succeed");
        sign_samples.push(started.elapsed());
        cases.push((epoch, message, signature));
    }

    let mut verify_samples = Vec::with_capacity(sign_runs);
    for (epoch, message, signature) in &cases {
        let started = Instant::now();
        let valid = S::verify(&pk, *epoch, message, signature);
        verify_samples.push(started.elapsed());
        assert!(valid);
    }

    println!("scheme={label}");
    println!("lifetime={}", S::LIFETIME);
    print_stats("keygen", &keygen_samples);
    print_stats("sign", &sign_samples);
    print_stats("verify", &verify_samples);
    println!("public_key_bytes={}", pk.to_bytes().len());
    println!("secret_key_bytes={initial_secret_key_bytes}");
    println!("secret_key_bytes_after_signing={}", sk.to_bytes().len());
    println!("signature_bytes={}", cases[0].2.to_bytes().len());
}

fn main() {
    benchmark::<SIGTargetSumLifetime18W1NoOff>("blake3-l18-w1-no-offset");
}
