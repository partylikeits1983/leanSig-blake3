# Poseidon and BLAKE3 comparison

Measured on 2026-08-18 using an Apple M4 Pro (12 cores, 24 GB) and
`rustc 1.91.0-nightly (ec7c02612 2025-08-05)`.

Both implementations use the lifetime-`2^18`, W1, target-sum-at-expectation
instantiation and were built with `cargo run --release --bin perf`. The Poseidon
source is repository commit `c08a3ba`; the current implementation is the audited
BLAKE3 working tree. Both use identical deterministic benchmark seeds and unique
prepared epochs and messages. Build time is excluded.

Poseidon used three key-generation and 200 sign/verify samples. The final BLAKE3
run used five key-generation and 1,000 sign/verify samples, so the comparison is
directional rather than a statistically matched cross-implementation experiment.

| Operation | Poseidon mean | BLAKE3 mean | BLAKE3 speedup |
|---|---:|---:|---:|
| Key generation | 3.488 s | 1.166 s | 2.99x |
| Signing | 346.8 us | 51.1 us | 6.79x |
| Verification | 264.0 us | 19.5 us | 13.54x |

| Operation | Poseidon median / p95 | BLAKE3 median / p95 |
|---|---:|---:|
| Key generation | 3.483 s / 3.502 s | 1.164 s / 1.184 s |
| Signing | 299.0 us / 798.0 us | 47.3 us / 79.0 us |
| Verification | 261.8 us / 273.7 us | 19.4 us / 20.1 us |

The 256-bit BLAKE3 representation trades some serialized size for speed. The
initial BLAKE3 secret key includes an empty persisted epoch-use tracker; after
1,000 signatures that tracker adds 4,000 bytes.

| Artifact | Poseidon | BLAKE3 | Change |
|---|---:|---:|---:|
| Public key | 48 bytes | 64 bytes | +33.3% |
| Initial prepared secret key | 86,588 bytes | 98,884 bytes | +14.2% |
| Secret key after 1,000 signatures | n/a | 102,884 bytes | +4 bytes/signature in the prepared window |
| Signature | 4,880 bytes | 5,580 bytes | +14.3% |

## Audit-pass optimization A/B

For a cleaner optimization comparison, commit `c9b5319` and the final working tree
were measured consecutively with exactly five key-generation and 1,000 sign/verify
samples. The state-safety checks are included in the post-audit signing measurement.

| Operation | Before audit | After audit | Improvement |
|---|---:|---:|---:|
| Key generation mean | 1.301 s | 1.166 s | 10.4% |
| Signing mean | 51.7 us | 51.1 us | 1.1% |
| Verification mean | 22.6 us | 19.5 us | 13.8% |
| Key generation median | 1.297 s | 1.164 s | 10.3% |
| Signing median | 48.3 us | 47.3 us | 2.2% |
| Verification median | 22.4 us | 19.4 us | 13.6% |

These are local microbenchmark results rather than a cross-platform performance
claim. Key-generation sample counts are deliberately small because every sample
builds the complete lifetime-`2^18` key state.
Target-sum signing also has input-dependent retry counts; its small before/after
difference should be treated as effectively near-flat, while the Poseidon/BLAKE3
gap is much larger than this run-to-run variance.
