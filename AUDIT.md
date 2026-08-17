# Implementation audit (2026-08-18)

This is an internal implementation review, not an independent cryptographic audit.
It covered the BLAKE3 transcripts, key/state handling, randomness APIs, untrusted
signature verification, serialization, and benchmark methodology.

## Fixed findings

| Severity | Finding | Resolution |
|---|---|---|
| High | `sign` accepted an immutable secret key and allowed unlimited reuse of an epoch, contrary to the synchronized-signature security model. | `sign` now mutates the secret key, records consumed epochs, rejects reuse, and persists the tracker in canonical SSZ. Rust's exclusive mutable borrow also prevents safe concurrent signing with one in-memory key. |
| Medium | Key generation accepted any `RngExt`, including non-cryptographic generators. | All secret or security-parameter sampling APIs now require `CryptoRng`; padding-only randomness remains generic because it is not secret. |
| Medium | Merkle verification computed `1 << path_depth` before rejecting an oversized attacker-controlled path. Sufficiently large paths could panic. | Depth is checked before shifting, so oversized paths are safely rejected. |
| Low | Invalid or unprepared signing epochs triggered assertions. | These cases now return `EpochOutsideActivation` or `EpochNotPrepared`. |
| Low | Criterion repeatedly signed the same epoch and auto-discovered a duplicate empty benchmark target. | Each timed signature receives a freshly decoded clean state outside the timed closure, verification cases use unique epochs, and automatic bench discovery is disabled. |
| Dependency | RustSec reported vulnerable `crossbeam-epoch 0.9.18`, `ruint 1.17.2`, and (after the `ruint` update) `time 0.3.45` versions in the lockfile. | The lockfile now uses `crossbeam-epoch 0.9.20`, `ruint 1.20.0`, and `time 0.3.47`; warning-only affected `rand` and `anyhow` entries were also updated to patched versions. `ruint` raises the project MSRV to Rust 1.90. The unmaintained direct `bincode` dev dependency was removed. |

The BLAKE3 construction uses separate derive-key contexts for chains, Merkle leaves,
Merkle nodes, and message hashing. The PRF uses keyed BLAKE3 with fixed, distinct tags.
Every transcript binds its public parameter and fixed-width address fields; leaf hashes
also bind their arity. Non-power-of-two message alphabets use rejection sampling, while
power-of-two alphabets consume disjoint XOF bit groups. Both mappings are unbiased.

## Optimizations applied

- Cache and clone BLAKE3 derive-key hasher templates instead of hashing context strings
  for every invocation. This is equivalent to the base-hasher cloning pattern used by
  BLAKE3's own tools.
- Stream chain ends directly into the leaf hasher, eliminating one allocation per leaf.
- Bit-pack XOF output for power-of-two encoding bases; base 2 now consumes one bit rather
  than one byte per chunk.

The before/after measurements are in [BENCHMARKS.md](BENCHMARKS.md).

## Residual risks

- State rollback cannot be prevented inside a serialized key. A signer must atomically
  persist the updated secret key before releasing a signature and must prevent restoring
  old snapshots, cloned keys, or backups. Hardware-backed monotonic state is preferable.
- This BLAKE3 substitution and the inherited parameter sets do not have a dedicated
  reduction or independent cryptographic review. They intentionally deviate from the
  field-oriented LeanSig specification.
- Secret-key allocations are not zeroized or memory-locked. Process dumps, swap, and
  allocator copies remain in the deployment threat model.
- Canonical SSZ decoding validates the persisted epoch tracker. Other serde formats are
  intended for trusted local data and do not provide canonical-format validation.
- Local benchmarks are not a cross-platform performance guarantee.
- RustSec still emits warning-only unmaintained notices for the transitive `paste`
  and `derivative` crates in the lockfile. No known-vulnerability or unsoundness
  advisory remains after the lockfile updates.

Relevant primary references are the
[BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex),
the [official Rust implementation](https://github.com/BLAKE3-team/BLAKE3), and the
[synchronized-signature security model](https://eprint.iacr.org/2025/055.pdf).
