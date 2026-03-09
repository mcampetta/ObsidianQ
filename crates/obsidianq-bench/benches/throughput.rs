//! Criterion-based throughput benchmarks.
//!
//! Run with:
//!   cargo bench -p obsidianq-bench
//!
//! Generates HTML reports in target/criterion/

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::RngCore;
use std::io::Cursor;

use obsidianq_core::{
    crypto::kdf::MasterKey,
    engine::{EncryptParams, DEFAULT_CHUNK_SIZE},
    format::{Mode, SuiteId},
};

// ── Helper ────────────────────────────────────────────────────────────────────

fn make_master() -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut id);
    (key, id)
}

fn encrypt_buf(plaintext: &[u8], suite: SuiteId, compress: bool) -> Vec<u8> {
    let (raw, file_id) = make_master();
    let master_key = MasterKey::from_bytes(raw);
    let params = EncryptParams {
        master_key,
        kem_data: vec![0u8; 32],
        mode: Mode::Password,
        suite,
        chunk_size: DEFAULT_CHUNK_SIZE,
        compress,
        file_id,
    };
    let mut out = Cursor::new(Vec::with_capacity(plaintext.len() + 65536));
    obsidianq_core::encrypt(params, &mut Cursor::new(plaintext), &mut out).unwrap();
    out.into_inner()
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

const SIZES_MIB: &[usize] = &[1, 100];

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    for &mib in SIZES_MIB {
        let size = mib * 1024 * 1024;
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);

        group.throughput(Throughput::Bytes(size as u64));

        // XChaCha20 no-compress
        group.bench_with_input(
            BenchmarkId::new("xchacha20/no-compress", format!("{mib}MiB")),
            &data,
            |b, d| b.iter(|| encrypt_buf(d, SuiteId::XChaCha20Poly1305, false)),
        );

        // AES-256-GCM no-compress
        group.bench_with_input(
            BenchmarkId::new("aesgcm/no-compress", format!("{mib}MiB")),
            &data,
            |b, d| b.iter(|| encrypt_buf(d, SuiteId::Aes256Gcm, false)),
        );

        // XChaCha20 + zstd compress
        group.bench_with_input(
            BenchmarkId::new("xchacha20/compress", format!("{mib}MiB")),
            &data,
            |b, d| b.iter(|| encrypt_buf(d, SuiteId::XChaCha20Poly1305, true)),
        );
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    for &mib in SIZES_MIB {
        let size = mib * 1024 * 1024;
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);

        // Pre-encrypt for the decrypt benchmark.
        let (raw, _) = make_master();
        let file_id = [0u8; 16];
        let ciphertext = {
            let mk = MasterKey::from_bytes(raw);
            let params = EncryptParams {
                master_key: mk,
                kem_data: vec![0u8; 32],
                mode: Mode::Password,
                suite: SuiteId::XChaCha20Poly1305,
                chunk_size: DEFAULT_CHUNK_SIZE,
                compress: false,
                file_id,
            };
            let mut out = Cursor::new(Vec::new());
            obsidianq_core::encrypt(params, &mut Cursor::new(&data), &mut out).unwrap();
            out.into_inner()
        };

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("xchacha20/no-compress", format!("{mib}MiB")),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    let mk = MasterKey::from_bytes(raw);
                    let mut out = Cursor::new(Vec::with_capacity(size));
                    obsidianq_core::decrypt(&mk, &mut Cursor::new(ct), &mut out).unwrap();
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
