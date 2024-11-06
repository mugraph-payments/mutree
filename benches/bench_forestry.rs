#![allow(unused)]
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use digest::Digest;
use mucrdt::prelude::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

struct BenchData {
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    rng: ChaCha8Rng,
}

impl BenchData {
    fn new(size: usize) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let pairs = (0..size)
            .map(|_| {
                let key_len = rng.gen_range(1..100);
                let value_len = rng.gen_range(1..100);
                let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
                let value: Vec<u8> = (0..value_len).map(|_| rng.gen()).collect();
                (key, value)
            })
            .collect();

        Self { pairs, rng }
    }
}

fn bench_insert<D: Digest + 'static>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(format!("forestry_{}", name));

    for size in [10, 100, 1000].iter() {
        let bench_data = BenchData::new(*size);

        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &bench_data,
            |b, data| {
                b.iter(|| {
                    let mut forestry = black_box(Forestry::<D>::empty());

                    for (key, value) in &data.pairs {
                        black_box(forestry.insert(key, value)).unwrap();
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("random_order", size),
            &bench_data,
            |b, data| {
                b.iter_with_setup(
                    || {
                        let mut pairs = data.pairs.clone();
                        let mut rng = data.rng.clone();
                        let mut forestry = Forestry::<D>::empty();

                        pairs.shuffle(&mut rng);

                        (forestry, pairs)
                    },
                    |(mut forestry, pairs)| {
                        for (key, value) in pairs {
                            black_box(forestry.insert(&key, &value)).unwrap();
                        }
                    },
                );
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
        .sample_size(10)
        .measurement_time(Duration::from_secs(3));
    targets = forestry_benchmark
);
criterion_main!(benches);
