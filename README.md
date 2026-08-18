# BLAKE3 LeanSig in Rust

An experimental synchronized hash-based signature scheme that uses BLAKE3 end to end.
This project is based on [LeanSig](https://github.com/leanEthereum/leanSig).

## Performance

Local results for the lifetime-`2^18` W1 target-sum parameter set on an Apple M4 Pro:

| Operation | Poseidon mean | BLAKE3 mean | Speedup |
|---|---:|---:|---:|
| Key generation | 3.488 s | 1.166 s | 2.99x |
| Signing | 346.8 µs | 51.1 µs | 6.79x |
| Verification | 264.0 µs | 19.5 µs | 13.54x |

The Poseidon run used three key-generation samples and 200 sign/verify samples.
The BLAKE3 run used five key-generation samples and 1,000 sign/verify samples.
These are local, directional results. They are not a cross-platform performance claim.

See [BENCHMARKS.md](BENCHMARKS.md) for the full method, latency distributions,
before/after optimization results, and serialized sizes.

## Status and security

This is a research prototype. Do not use it in production.

The implementation has received an internal code and security review. It has not
received an independent cryptographic audit. The BLAKE3 construction differs from
the field-oriented construction in the LeanSig paper, and its security parameters
do not have a dedicated proof for this variant. See [AUDIT.md](AUDIT.md) for the
fixed findings and remaining risks.

This scheme is stateful:

- A secret key may sign only once per epoch. The API records used epochs and rejects reuse.
- `sign` mutates the secret key. Persist the new state atomically before releasing the signature.
- Prevent rollback to old key files, snapshots, clones, or backups. Rollback can allow epoch reuse.
- Call `advance_preparation` as epochs move beyond the current prepared interval.

Key generation requires an RNG that implements `CryptoRng`. Deterministically seeded
RNGs in tests and benchmarks are for reproducibility only.

The format is not compatible with the Poseidon implementation or earlier BLAKE3
prototypes. Old keys and signatures cannot be decoded or verified by this version.

## Requirements

- Rust 1.90 or newer

## Basic use

```rust
use leansig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_blake3::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1NoOff,
    },
};
use rand::RngExt;

type S = SIGTargetSumLifetime18W1NoOff;

let mut rng = rand::rng();
let (pk, mut sk) = S::key_gen(&mut rng, 0, S::LIFETIME as usize);
let message: [u8; MESSAGE_LENGTH] = rng.random();
let epoch = 0;

let signature = S::sign(&mut sk, epoch, &message).expect("signing failed");

// Persist `sk` atomically before publishing `signature`.
assert!(S::verify(&pk, epoch, &message, &signature));
```

Secret keys initially prepare a limited epoch window. For later epochs, advance it
until the requested epoch is available:

```rust
while !sk.get_prepared_interval().contains(&u64::from(epoch)) {
    sk.advance_preparation();
}
```

## BLAKE3 construction

- PRF keys, public parameters, Merkle nodes, chain values, and signing randomness are 32 bytes.
- Chain starts and deterministic signing randomness use keyed BLAKE3 with separate tags.
- Chain, Merkle-leaf, Merkle-node, and message hashes use separate BLAKE3 contexts.
- Hash inputs bind the public parameter, address fields, and variable input lengths.
- Message hashing uses BLAKE3 XOF output. Power-of-two bases use bit packing; other bases use unbiased rejection sampling.
- Transcript integers use little-endian encoding.

Concrete parameter sets are under
`leansig::signature::generalized_xmss::instantiations_blake3`.
Their target-sum dimensions, bases, and targets come from the existing LeanSig sets.

## Tests

Run the default tests:

```sh
cargo test
```

Run all tests, including the slower concrete-parameter tests:

```sh
cargo test --release --features slow-tests
```

## Benchmarks

Run Criterion signing and verification benchmarks:

```sh
cargo bench
```

Include Criterion key-generation benchmarks:

```sh
cargo bench --features with-gen-benches-blake3
```

Run the reproducible end-to-end harness:

```sh
cargo run --release --bin perf
```

Set `LEANSIG_KEYGEN_RUNS` and `LEANSIG_SIGN_RUNS` to change its sample counts.

Extract Criterion means from an existing result directory:

```sh
python3 benchmark-mean.py target
python3 benchmark-mean.py target --intervals
```

## References

- [LeanSig repository](https://github.com/leanEthereum/leanSig)
- [Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055.pdf)
- [Official BLAKE3 Rust implementation](https://github.com/BLAKE3-team/BLAKE3)

## License

Apache-2.0
