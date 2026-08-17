use std::hint::black_box;

use criterion::{BatchSize, Criterion, SamplingMode};
use rand::RngExt;

use leansig::{
    MESSAGE_LENGTH,
    serialization::Serializable,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::{
            SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W4NoOff,
        },
    },
};

fn benchmark_signature_scheme<S: SignatureScheme>(c: &mut Criterion, description: &str) {
    let mut group = c.benchmark_group(format!("BLAKE3: {description}"));
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = rand::rng();

    #[cfg(feature = "with-gen-benches-blake3")]
    {
        group.sample_size(10);
        group.bench_function("keygen", |b| {
            b.iter(|| S::key_gen(black_box(&mut rng), 0, S::LIFETIME as usize));
        });
    }

    let (pk, mut sk) = S::key_gen(&mut rng, 0, S::LIFETIME as usize);
    let prepared = sk.get_prepared_interval();
    let clean_sk = sk.to_bytes();
    let cases: Vec<(u32, [u8; MESSAGE_LENGTH], S::Signature)> = (0..128)
        .map(|i| {
            let epoch = prepared.start as u32 + i;
            let message = rng.random();
            let signature =
                S::sign(&mut sk, epoch, &message).expect("benchmark signing must succeed");
            assert!(S::verify(&pk, epoch, &message, &signature));
            (epoch, message, signature)
        })
        .collect();

    group.sample_size(100);
    let sign_epoch = cases[0].0;
    let sign_message = cases[0].1;
    group.bench_function("sign", |b| {
        b.iter_batched(
            || S::SecretKey::from_bytes(black_box(&clean_sk)).expect("valid benchmark key"),
            |mut fresh_sk| {
                black_box(
                    S::sign(
                        black_box(&mut fresh_sk),
                        black_box(sign_epoch),
                        black_box(&sign_message),
                    )
                    .expect("benchmark signing must succeed"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    let mut verify_index = 0usize;
    group.bench_function("verify", |b| {
        b.iter(|| {
            let (epoch, message, signature) = &cases[verify_index % cases.len()];
            verify_index += 1;
            S::verify(
                black_box(&pk),
                black_box(*epoch),
                black_box(message),
                black_box(signature),
            )
        });
    });

    group.finish();
}

pub fn bench_function_blake3(c: &mut Criterion) {
    benchmark_signature_scheme::<SIGTargetSumLifetime18W1NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 1",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime18W4NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 4",
    );
}
