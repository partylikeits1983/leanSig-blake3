# BLAKE3 LeanSig in Rust

This repository contains an experimental Rust implementation of synchronized hash-based signatures using BLAKE3 end to end.
It was originally developed in [this repository](https://github.com/b-wagn/hash-sig).


*Note: Rust version >= 1.90 is required.*

## Disclaimers

The code has *not been audited and is not meant to be used in production*. It is a playground to explore and benchmark these signatures. Use it at your own risk.

Key generation requires an RNG implementing Rust's `CryptoRng` marker trait. Tests and
benchmarks use either the thread RNG or a deterministically seeded `StdRng`; seeded RNGs
are for reproducible measurements only, not production key generation.

## Signature Interface

If you want to use this library, the main interface is that of a *(synchronized) signature scheme*, which is defined in the [Signature trait](https://github.com/leanEthereum/leanSig/blob/main/src/signature.rs). Here is a summary:
- A function `key_gen` to generate keys.
- A function `sign` to sign messages using the secret key with respect to an epoch.
- A function `verify` to verify signatures for a given message, public key, and epoch.

Importantly, each pair of secret key and epoch must not be used twice as input to `sign`.
The implementation records consumed epochs and rejects reuse, but callers must atomically
persist the mutated secret key and prevent rollback to an older serialized state.

Further, the secret keys need to be prepared for epochs by calling `sk.advance_preparation()`, which moves the interval `sk.get_prepared_interval()` further to the right.
In particular, we assume that users of the code sign for epochs in order and call `sk.advance_preparation()` at some point in the background
as soon as half of the current prepared interval has passed.


For a signature scheme `T: SignatureScheme`, an example to use this interface may be as follows:
```rust

// generate keys (assume we have an rng)
let (pk, mut sk) = T::key_gen(&mut rng, 0, T::LIFETIME as usize);

// get a random message and a random epoch
let message = rng.random();
let epoch = rng.random_range(0..activation_duration) as u32;

// make sure secret key is prepared for signing in this epoch
let mut iterations = 0;
while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
    sk.advance_preparation();
    iterations += 1;
}
assert!(sk.get_prepared_interval().contains(&(epoch as u64)));

// now we can sign
let sig = T::sign(&mut sk, epoch, &message).expect("signing succeeds");

// verify the signature
let is_valid = T::verify(&pk, epoch, &message, &sig);
```

See also function `test_signature_scheme_correctness` in [this file](https://github.com/leanEthereum/leanSig/blob/main/src/signature.rs).

## Schemes
The code implements a generic framework from [this paper](https://eprint.iacr.org/2025/055.pdf), which builds XMSS-like hash-based signatures from a primitive called incomparable encodings.
Concrete BLAKE3 instantiations are defined in
`leansig::signature::generalized_xmss::instantiations_blake3`.
The target-sum dimensions, bases, and targets are inherited from the existing LeanSig parameter sets, while all cryptographic values are 256-bit byte strings.

### BLAKE3 construction

- PRF keys, public salts, Merkle nodes, chain values, and signing randomness are all 32 bytes.
- Chain starts and deterministic signing randomness use keyed BLAKE3 with distinct purpose tags.
- Message hashing uses BLAKE3's XOF and unbiased rejection sampling to produce uniform chunks for any base from 2 through 256.
- Winternitz-chain, Merkle-leaf, and Merkle-node hashes use separate BLAKE3 derive-key contexts and bind all address metadata.
- Integers in cryptographic transcripts are encoded little-endian. Variable-length hash lists include their element count.

This is a new, wire-incompatible prototype. Keys and signatures created by earlier implementations cannot be decoded or verified by this version.

## Tests

Run the tests with

```
cargo test
```

By default, this will exclude some of the tests. In particular, correctness tests for real instantiations take quite long and are excluded.
If you want to run *all* tests, you can use

```
cargo test --release --features slow-tests
```

Removing the `--release` is also an option but tests will take even longer.

## Benchmarks

Benchmarks are provided using criterion.
They take a while, as key generation is expensive, and as a large number of schemes are benchmarked.
Run them with

```
cargo bench
```

The default Criterion suite measures signing and verification for representative lifetime-`2^18` W1 and W4 instantiations.
By default, key generation is not benchmarked. There are two options to benchmark it:
1. Run `cargo bench --features with-gen-benches-blake3`.
2. Run the reproducible end-to-end harness with `cargo run --release --bin perf`. Its key-generation and signing sample counts can be set with `LEANSIG_KEYGEN_RUNS` and `LEANSIG_SIGN_RUNS`.

If criterion only generates json files, one way to extract all means for all benchmarks easily (without re-running criterion) is to run

```
python3 benchmark-mean.py target
```

Confidence intervals can also be shown via

```
python3 benchmark-mean.py target --intervals
```

See [BENCHMARKS.md](BENCHMARKS.md) for the matched Poseidon/BLAKE3 comparison,
including methodology, latency distributions, and serialized-size tradeoffs.
The implementation review, fixed findings, and remaining deployment risks are in
[AUDIT.md](AUDIT.md).

## Status

The BLAKE3 construction intentionally deviates from the field-oriented construction in the paper. It has not been audited and should not be treated as production cryptography without an independent design and implementation review.

## License

Apache Version 2.0.
