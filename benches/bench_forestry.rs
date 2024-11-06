#![allow(unused)]
use std::{any::type_name, time::Duration};

use criterion::{
    black_box,
    criterion_group,
    criterion_main,
    measurement::{Measurement, WallTime},
    BenchmarkId,
    Criterion,
};
use criterion_cycles_per_byte::CyclesPerByte;
use digest::Digest;
use mutree::prelude::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

struct BenchData<D: Digest + 'static> {
    forestry: Forestry<D>,
    insert_key: Vec<u8>,
    insert_value: Vec<u8>,
    rng: ChaCha8Rng,
}

impl<D: Digest + 'static> BenchData<D> {
    fn new(size: usize) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut forestry = Forestry::<D>::empty();

        // Pre-populate the Forestry
        for _ in 0..size {
            let key_len = rng.gen_range(1..100);
            let value_len = rng.gen_range(1..100);
            let key: Vec<u8> = (0..key_len).map(|_| rng.gen()).collect();
            let value: Vec<u8> = (0..value_len).map(|_| rng.gen()).collect();
            forestry.insert(&key, &value).unwrap();
        }

        // Generate a single key-value pair for insertion
        let insert_key_len = rng.gen_range(1..100);
        let insert_value_len = rng.gen_range(1..100);
        let insert_key: Vec<u8> = (0..insert_key_len).map(|_| rng.gen()).collect();
        let insert_value: Vec<u8> = (0..insert_value_len).map(|_| rng.gen()).collect();

        Self {
            forestry,
            insert_key,
            insert_value,
            rng,
        }
    }
}

fn bench_insert<D: Digest + 'static, T: Measurement>(c: &mut Criterion<T>, name: &str) {
    let type_name = type_name::<T>().split(":").take(1).collect::<Vec<_>>()[0];
    let mut group = c.benchmark_group(format!("forestry/{}/{}", name, type_name));

    for size in [10, 100, 1000].iter() {
        let bench_data = BenchData::<D>::new(*size);

        group.bench_with_input(BenchmarkId::new("insert", size), &bench_data, |b, data| {
            b.iter(|| {
                let mut forestry = black_box(data.forestry.clone());
                black_box(forestry.insert(&data.insert_key, &data.insert_value)).unwrap();
            });
        });
    }

    group.finish();
}

fn forestry_benchmark<T: Measurement>(c: &mut Criterion<T>) {
    // Blake2s-256
    #[cfg(feature = "blake2")]
    bench_insert::<blake2::Blake2s256, T>(c, "blake2s");

    // Blake2b-256
    #[cfg(feature = "blake2")]
    bench_insert::<blake2::Blake2b<digest::consts::U32>, T>(c, "blake2b");

    // Blake3
    #[cfg(feature = "blake3")]
    bench_insert::<blake3::Hasher, T>(c, "blake3");

    // SHA2
    #[cfg(feature = "sha2")]
    bench_insert::<sha2::Sha256, T>(c, "sha256");

    // SHA3
    #[cfg(feature = "sha3")]
    bench_insert::<sha3::Sha3_256, T>(c, "sha3_256");
}

fn cycles_per_byte_bench(c: &mut Criterion<CyclesPerByte>) {
    forestry_benchmark(c)
}

fn wall_time_bench(c: &mut Criterion<WallTime>) {
    forestry_benchmark(c);
}

criterion_group!(
    name = benches_cycles;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .with_measurement(CyclesPerByte);
    targets = cycles_per_byte_bench
);

criterion_group!(
    name = benches_time;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3));
    targets = wall_time_bench
);

criterion_main!(benches_cycles, benches_time);
