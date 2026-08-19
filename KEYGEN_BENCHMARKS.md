# Key-generation scaling

This report covers the experimental BLAKE3 LeanSig/XMSS parameter set with a
maximum lifetime of 2^32 epochs, dimension 46, base 8, and target sum 200. The
`--epochs` argument controls the active interval generated inside that scheme;
it does not change the scheme's maximum lifetime.

## Setup

- Date: 2026-08-19
- Machine: Apple M4 Pro, 12 cores, 24 GB RAM
- Rust: `rustc 1.91.0-nightly (2025-08-05)`
- Build: `cargo run --release --bin keygen_lifetime32`
- BLAKE3: `pure` feature enabled
- SIMD: four independent hashes per AArch64 NEON vector
- Parallelism: Rayon using the machine's default worker count

Key-generation times exclude serialization, file I/O, and compilation. The
optimized runs use operating-system entropy; the earlier baseline used a fixed
benchmark seed. Results are specific to this machine and can vary with
temperature and background load.

## Results

The baseline used scalar calls through the public BLAKE3 hasher. The optimized
version batches the chain-start PRF and fixed 70-byte Winternitz chain hashes.
All values are wall-clock seconds.

| Active epochs | Baseline | Pure-Rust NEON | Optimized samples | Speedup |
|---:|---:|---:|---:|---:|
| 2^17 | 0.802 | 0.359 | 5 | 2.23x |
| 2^18 | 1.638 | 0.720 | 5 | 2.28x |
| 2^20 | 6.525 | 2.789 | 3 | 2.34x |
| 2^24 | 103.448 | 48.239 | 1 | 2.14x |

The 2^24 result is a single long sample and is more exposed to thermal
throttling. The smaller multi-sample results are better for comparing code
changes.

## 2^32 projection

No 2^32 run was performed and no full key was written. Linear extrapolation
from the optimized 2^20 and 2^24 results gives approximately 3.2–3.5 hours for
a full 2^32 active interval on this M4 Pro. The earlier scalar projection was
about 7.35 hours.

Finishing in 60 seconds would require roughly 71.6 million epochs per second.
This implementation sustains about 0.35–0.38 million epochs per second, so the
one-minute target still needs approximately another 190–205x throughput gain.
That is beyond what CPU SIMD tuning alone can plausibly supply while retaining
the same XMSS structure, BLAKE3 transcripts, and eager full-tree keygen.

## Reproducing a bounded run

```sh
cargo run --release --bin keygen_lifetime32 -- --epochs '2^20' --runs 3
```

The benchmark requires an explicit epoch count and never defaults to 2^32. A
full-lifetime run additionally requires `--allow-full-lifetime`. If
`--output-prefix` is supplied with a single run, keys are generated from OS
entropy, existing files are not overwritten, and the secret file is created
with mode 0600 on Unix.

## Compatibility checks

Differential tests compare SIMD results to the pre-existing scalar BLAKE3 path
for chain hashes and PRF outputs, including maximum epoch and index values. The
complete release test suite passes, so public keys and signatures remain on
the same LeanSig/XMSS scheme rather than switching to XMSS^MT.
