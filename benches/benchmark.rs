use criterion::{criterion_group, criterion_main};

mod benchmark_blake3;

use benchmark_blake3::bench_function_blake3;

criterion_group!(benches, bench_function_blake3);
criterion_main!(benches);
