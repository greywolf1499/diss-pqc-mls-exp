//! # Cryptographic Primitives Benchmark Suite
//!
//! This file defines a comprehensive benchmark suite for evaluating the performance of various
//! cryptographic signature primitives. Using the `criterion.rs` framework, it measures the
//! execution time of three fundamental operations:
//!
//! 1.  **Key Generation**: The process of creating a new public and secret key pair.
//! 2.  **Signing**: The process of generating a digital signature for a message.
//! 3.  **Verification**: The process of verifying a signature against a message.
//!
//! The benchmarks iterate over all cryptographic primitives provided by the `pqc_crypto_bench`
//! library, allowing for a direct performance comparison between classical and post-quantum
//! schemes.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use pqc_crypto_bench::get_all_primitives;

/// Benchmarks the key generation process for each cryptographic primitive.
///
/// This function iterates through all available signature algorithms and measures
/// the time required to generate a new key pair for each. The results are grouped
/// under "1. Key Generation" in the final report.
fn benchmark_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("1. Key Generation");

    for primitive in get_all_primitives() {
        group.bench_function(BenchmarkId::from_parameter(primitive.name()), |b| {
            // The timed routine is just the key generation itself.
            b.iter(|| primitive.generate_keypair());
        });
    }
    group.finish();
}

/// Benchmarks the signing operation for each cryptographic primitive.
///
/// A fixed message is used for signing across all algorithms. The `iter_batched`
/// method from Criterion is employed to separate the setup phase (key generation)
/// from the timed routine (signing), ensuring that only the signing operation
/// itself is measured.
fn benchmark_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("2. Signing");
    let message = b"This is a test message for the signing benchmark.";

    for primitive in get_all_primitives() {
        group.bench_with_input(
            BenchmarkId::from_parameter(primitive.name()),
            message,
            |b, msg| {
                // `iter_batched` is used to isolate the signing operation from key generation.
                // The setup closure generates a fresh key pair for each batch of measurements,
                // but this setup time is not included in the final result.
                b.iter_batched(
                    || {
                        // SETUP: Generate a new key pair. Only the secret key is needed.
                        let (_, secret_key) = primitive.generate_keypair();
                        secret_key
                    },
                    |secret_key| {
                        // TIMED ROUTINE: Perform the signing operation with the generated key.
                        primitive.sign(&secret_key, msg);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

/// Benchmarks the verification operation for each cryptographic primitive.
///
/// This function measures the time taken to verify a signature. The `iter_batched`
/// method ensures that the untimed setup phase includes both key generation and
/// the creation of a signature. The timed routine is focused exclusively on the
/// verification process.
fn benchmark_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("3. Verification");
    let message = b"This is a test message for the verification benchmark.";

    for primitive in get_all_primitives() {
        group.bench_with_input(
            BenchmarkId::from_parameter(primitive.name()),
            message,
            |b, msg| {
                // The setup for this benchmark is more complex, involving key generation
                // and signing. This is all performed outside of the timed measurement.
                b.iter_batched(
                    || {
                        // SETUP: Generate a key pair and a signature for the message.
                        let (public_key, secret_key) = primitive.generate_keypair();
                        let signature = primitive.sign(&secret_key, msg);
                        (public_key, signature)
                    },
                    |(public_key, signature)| {
                        // TIMED ROUTINE: Perform the verification using the public key.
                        primitive.verify(&public_key, msg, &signature);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, benchmark_keygen, benchmark_sign, benchmark_verify);

criterion_main!(benches);
