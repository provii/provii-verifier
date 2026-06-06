// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//! Performance benchmarks for Argon2id API key hashing and verification
//!
//! This benchmark suite measures the performance impact of the updated Argon2id parameters:
//! - Memory cost: 65536 KiB (64 MiB) - up from 19456 KiB (19 MiB)
//! - Time cost: 3 iterations - up from 2
//! - Parallelism: 4 threads - up from 1
//!
//! Target: < 100ms p95 for verification operations
//! Expected: ~60ms for new parameters (vs. ~18ms for old parameters)
//!
//! Note: This bench is excluded on wasm32 targets where criterion is unavailable.

// criterion is only a dev-dependency for non-wasm32 targets; this bench cannot
// compile on wasm32-unknown-unknown (the default Cloudflare Workers target).
#[cfg(not(target_arch = "wasm32"))]
mod bench {
    use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
    use provii_verifier::security::hash::{hash_api_key, verify_api_key};

    /// Benchmark hashing with new Argon2id parameters (64 MiB, t=3, p=4)
    fn bench_hash_new_params(c: &mut Criterion) {
        let mut group = c.benchmark_group("argon2id_hash");

        // Configure for slower operations
        group.sample_size(10); // Fewer samples since this is slow
        group.measurement_time(std::time::Duration::from_secs(10));

        group.bench_function("hash_64mib_t3_p4", |b| {
            b.iter(|| {
                let key = "test-api-key-benchmark";
                hash_api_key(black_box(key)).unwrap()
            });
        });

        group.finish();
    }

    /// Benchmark verification with new Argon2id parameters (64 MiB, t=3, p=4)
    fn bench_verify_new_params(c: &mut Criterion) {
        let mut group = c.benchmark_group("argon2id_verify");

        // Configure for slower operations
        group.sample_size(10);
        group.measurement_time(std::time::Duration::from_secs(10));

        // Pre-generate hash for verification testing
        let key = "test-api-key-benchmark";
        let hash = hash_api_key(key).unwrap();

        group.bench_function("verify_64mib_t3_p4", |b| {
            b.iter(|| verify_api_key(black_box(key), black_box(&hash)));
        });

        group.finish();
    }

    /// Benchmark verification with different key lengths
    fn bench_verify_key_lengths(c: &mut Criterion) {
        let mut group = c.benchmark_group("argon2id_verify_key_lengths");

        group.sample_size(10);
        group.measurement_time(std::time::Duration::from_secs(10));

        let key_lengths = vec![
            ("short", "abc123"),
            ("medium", "provii_api_key_1234567890abcdef"),
            ("long", &"a".repeat(100)),
        ];

        for (name, key) in key_lengths {
            let hash = hash_api_key(key).unwrap();

            group.bench_with_input(
                BenchmarkId::from_parameter(name),
                &(key, hash),
                |b, (k, h)| {
                    b.iter(|| verify_api_key(black_box(k), black_box(h)));
                },
            );
        }

        group.finish();
    }

    /// Benchmark hash + verify round trip (simulates complete authentication flow)
    fn bench_hash_verify_roundtrip(c: &mut Criterion) {
        let mut group = c.benchmark_group("argon2id_roundtrip");

        group.sample_size(10);
        group.measurement_time(std::time::Duration::from_secs(10));

        group.bench_function("hash_and_verify_64mib_t3_p4", |b| {
            b.iter(|| {
                let key = "test-api-key-roundtrip";
                let hash = hash_api_key(black_box(key)).unwrap();
                verify_api_key(black_box(key), black_box(&hash))
            });
        });

        group.finish();
    }

    /// Benchmark backward compatibility: verify old parameter hashes
    fn bench_verify_old_params(c: &mut Criterion) {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2, ParamsBuilder, Version,
        };
        use zeroize::Zeroizing;

        let mut group = c.benchmark_group("argon2id_verify_backward_compat");

        group.sample_size(10);
        group.measurement_time(std::time::Duration::from_secs(10));

        // Create hash with old parameters (19 MiB, t=2, p=1)
        let key = "old-params-test";
        let salt = SaltString::generate(&mut OsRng);
        let old_params = ParamsBuilder::new()
            .m_cost(19456) // 19 MiB
            .t_cost(2)
            .p_cost(1)
            .build()
            .unwrap();

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, old_params);
        let api_key_bytes = Zeroizing::new(key.as_bytes().to_vec());
        let old_hash = argon2
            .hash_password(&api_key_bytes, &salt)
            .unwrap()
            .to_string();

        group.bench_function("verify_19mib_t2_p1", |b| {
            b.iter(|| verify_api_key(black_box(key), black_box(&old_hash)));
        });

        group.finish();
    }

    criterion_group!(
        benches,
        bench_hash_new_params,
        bench_verify_new_params,
        bench_verify_key_lengths,
        bench_hash_verify_roundtrip,
        bench_verify_old_params,
    );
    criterion_main!(benches);
} // mod bench

// On wasm32, criterion is unavailable. Provide a stub main so the bench
// crate compiles but does nothing.
#[cfg(target_arch = "wasm32")]
fn main() {}
