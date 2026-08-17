# Poseidon and BLAKE3 comparison

Measured on 2026-08-18 using an Apple M4 Pro (12 cores, 24 GB) and
`rustc 1.91.0-nightly (ec7c02612 2025-08-05)`.

Both implementations used the lifetime-`2^18`, W1, target-sum-at-expectation
instantiation and were built with `cargo run --release --bin perf`. The Poseidon
source was an export of repository commit `c08a3ba`; the BLAKE3 source was the
working tree after this migration. Both runs used identical deterministic RNG
seeds, three full key-generation samples, and 200 unique prepared epochs and
messages for signing and verification. Build time is excluded.

| Operation | Poseidon mean | BLAKE3 mean | Speedup |
|---|---:|---:|---:|
| Key generation | 3.488 s | 1.256 s | 2.78x |
| Signing | 346.8 us | 55.7 us | 6.23x |
| Verification | 264.0 us | 22.5 us | 11.75x |

| Operation | Poseidon median / p95 | BLAKE3 median / p95 |
|---|---:|---:|
| Key generation | 3.483 s / 3.502 s | 1.255 s / 1.263 s |
| Signing | 299.0 us / 798.0 us | 52.2 us / 84.0 us |
| Verification | 261.8 us / 273.7 us | 22.4 us / 22.8 us |

The 256-bit BLAKE3 representation trades some serialized size for speed:

| Artifact | Poseidon | BLAKE3 | Change |
|---|---:|---:|---:|
| Public key | 48 bytes | 64 bytes | +33.3% |
| Prepared secret key | 86,588 bytes | 98,880 bytes | +14.2% |
| Signature | 4,880 bytes | 5,580 bytes | +14.3% |

These are local microbenchmark results rather than a cross-platform performance
claim. Key-generation results have only three samples because each sample builds
the complete lifetime-`2^18` key state.
