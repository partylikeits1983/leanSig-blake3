# Benchmarks

## Setup

- Date: 2026-08-18
- Machine: Apple M4 Pro, 12 cores, 24 GB RAM
- Rust: `rustc 1.91.0-nightly (ec7c02612 2025-08-05)`
- Parameters: 262,144-epoch W1 target-sum set
- Command: `cargo run --release --bin perf`
- Poseidon commit: `c08a3ba`
- BLAKE3 commit: `c50187a`

Both runs used deterministic seeds and unique epoch/message pairs. Build time was
not measured.

| Samples | Poseidon | BLAKE3 |
|---|---:|---:|
| Key generation | 3 | 5 |
| Sign/verify | 200 | 1,000 |

## Results

| Operation | Poseidon mean | BLAKE3 mean | Speedup |
|---|---:|---:|---:|
| Key generation | 3.488 s | 1.166 s | 2.99x |
| Signing | 346.8 µs | 51.1 µs | 6.79x |
| Verification | 264.0 µs | 19.5 µs | 13.54x |

| Operation | Poseidon median / p95 | BLAKE3 median / p95 |
|---|---:|---:|
| Key generation | 3.483 s / 3.502 s | 1.164 s / 1.184 s |
| Signing | 299.0 µs / 798.0 µs | 47.3 µs / 79.0 µs |
| Verification | 261.8 µs / 273.7 µs | 19.4 µs / 20.1 µs |

## Serialized sizes

| Artifact | Poseidon | BLAKE3 | Change |
|---|---:|---:|---:|
| Public key | 48 bytes | 64 bytes | +33.3% |
| Initial prepared secret key | 86,588 bytes | 98,884 bytes | +14.2% |
| Secret key after 1,000 signatures | n/a | 102,884 bytes | +4 bytes per recorded epoch |
| Signature | 4,880 bytes | 5,580 bytes | +14.3% |

## BLAKE3 optimization results

Baseline: `c9b5319`. Optimized: `c50187a`. Both runs used five key-generation
samples and 1,000 sign/verify samples.

| Operation | Baseline | Optimized | Change |
|---|---:|---:|---:|
| Key generation mean | 1.301 s | 1.166 s | -10.4% |
| Signing mean | 51.7 µs | 51.1 µs | -1.1% |
| Verification mean | 22.6 µs | 19.5 µs | -13.8% |
| Key generation median | 1.297 s | 1.164 s | -10.3% |
| Signing median | 48.3 µs | 47.3 µs | -2.2% |
| Verification median | 22.4 µs | 19.4 µs | -13.6% |

## Notes

- Results are specific to this machine and build.
- Key generation has few samples because each run builds the full key state.
- Target-sum signing time varies with the number of encoding retries.
- Poseidon chain and path values serialize to 28 bytes; BLAKE3 uses 32-byte
  outputs. For W1, this accounts for 692 of the 700 extra signature bytes. The
  other 8 bytes come from encoding randomness.
