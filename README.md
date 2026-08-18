# BLAKE3 LeanSig in Rust

BLAKE3-based [LeanSig](https://github.com/leanEthereum/leanSig) implementation in Rust.

## Performance

Benchmarked on an Apple M4 Pro using a key lifetime of 262,144 epochs and the W1 target-sum parameter set.

| Operation | Poseidon mean | BLAKE3 mean | Speedup |
|---|---:|---:|---:|
| Key generation | 3.488 s | 1.166 s | 2.99x |
| Signing | 346.8 µs | 51.1 µs | 6.79x |
| Verification | 264.0 µs | 19.5 µs | 13.54x |

[Full benchmark data and methodology](BENCHMARKS.md)

## Basic use

```rust
use leansig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
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
assert!(S::verify(&pk, epoch, &message, &signature));
```

## BLAKE3 construction

- PRF keys, public parameters, Merkle nodes, chain values, and signing randomness are 32 bytes.
- Chain starts and deterministic signing randomness use keyed BLAKE3 with separate tags.
- Chain, Merkle-leaf, Merkle-node, and message hashes use separate BLAKE3 contexts.
- Hash inputs bind the public parameter, address fields, and variable input lengths.
- Message hashing uses BLAKE3 XOF output. Power-of-two bases use bit packing; other bases use unbiased rejection sampling.
- Transcript integers use little-endian encoding.

Parameter sets are under `signature::generalized_xmss::instantiations_blake3`.

## Tests

```sh
cargo test
cargo test --release --features slow-tests
```

## Benchmarks

```sh
cargo bench
cargo bench --features with-gen-benches-blake3
cargo run --release --bin perf
```

Set `LEANSIG_KEYGEN_RUNS` and `LEANSIG_SIGN_RUNS` to change its sample counts.

## References

- [LeanSig repository](https://github.com/leanEthereum/leanSig)
- [Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055.pdf)
- [Official BLAKE3 Rust implementation](https://github.com/BLAKE3-team/BLAKE3)

## License

Apache-2.0
