use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use file_encryptor::crypto::encryption::{decrypt_data, encrypt_data};
use file_encryptor::crypto::key_derivation::derive_key_from_password;

fn bench_key_derivation(c: &mut Criterion) {
    c.bench_function("argon2id_key_derivation", |b| {
        b.iter(|| derive_key_from_password("BenchmarkP@ss123!", None).unwrap())
    });

    c.bench_function("argon2id_key_derivation_with_device_id", |b| {
        b.iter(|| derive_key_from_password("BenchmarkP@ss123!", Some("device_id_bench")).unwrap())
    });
}

fn bench_encryption(c: &mut Criterion) {
    let password = "BenchmarkP@ss123!";

    let mut group = c.benchmark_group("aes256gcm_encrypt");
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0xABu8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| encrypt_data(&data, password, None).unwrap())
        });
    }
    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let password = "BenchmarkP@ss123!";

    let mut group = c.benchmark_group("aes256gcm_decrypt");
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0xABu8; *size];
        let encrypted = encrypt_data(&data, password, None).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| decrypt_data(&encrypted, password, None).unwrap())
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_encryption,
    bench_decryption
);
criterion_main!(benches);
