#![allow(unused)]
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use digest::Digest;
use mucrdt::prelude::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

fn generate_kv_pairs(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    (0..n)
        .map(|_| {
            let key_len = rng.gen_range(1..100);
            let value_len = rng.gen_range(1..100);
            let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
            let value: Vec<u8> = (0..value_len).map(|_| rng.gen()).collect();
            (key, value)
        })
        .collect()
}

fn bench_insert<D: Digest + 'static>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(format!("forestry_{}", name));

    for size in [10, 100, 1000].iter() {
        let pairs = generate_kv_pairs(*size);

        group.bench_with_input(BenchmarkId::new("sequential", size), &pairs, |b, pairs| {
            b.iter(|| {
                let mut forest = Forestry::<D>::empty();
                for (key, value) in pairs {
                    black_box(forest.insert(key, value)).unwrap();
                }
            });
        });

        group.bench_with_input(
            BenchmarkId::new("random_order", size),
            &pairs,
            |b, pairs| {
                b.iter(|| {
                    let mut forest = Forestry::<D>::empty();
                    let mut pairs = pairs.clone();
                    let mut rng = ChaCha8Rng::seed_from_u64(42);
                    pairs.shuffle(&mut rng);
                    for (key, value) in pairs {
                        black_box(forest.insert(&key, &value)).unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

fn forestry_benchmark(c: &mut Criterion) {
    // Blake2
    #[cfg(feature = "blake2")]
    bench_insert::<blake2::Blake2s256>(c, "blake2s");
    #[cfg(feature = "blake2")]
    bench_insert::<blake2::Blake2b512>(c, "blake2b");

    // Blake3
    #[cfg(feature = "blake3")]
    bench_insert::<blake3::Hasher>(c, "blake3");

    // SHA2
    #[cfg(feature = "sha2")]
    bench_insert::<sha2::Sha256>(c, "sha256");
    #[cfg(feature = "sha2")]
    bench_insert::<sha2::Sha512>(c, "sha512");

    // SHA3
    #[cfg(feature = "sha3")]
    bench_insert::<sha3::Sha3_256>(c, "sha3_256");
    #[cfg(feature = "sha3")]
    bench_insert::<sha3::Sha3_512>(c, "sha3_512");
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_secs(20));
    targets = forestry_benchmark
);
criterion_main!(benches);
