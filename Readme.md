# Post-Quantum Cryptography Performance Benchmark

## Overview

This project provides a framework for benchmarking the performance of various cryptographic signature algorithms, with a focus on comparing classical schemes against post-quantum cryptography (PQC) candidates. It was developed to support dissertation research on the performance implications of integrating PQC into higher-level protocols.

The core of this repository is a Rust library that abstracts different cryptographic primitives under a unified API, allowing for consistent and comparable performance measurements using the `criterion.rs` benchmarking framework.

## Benchmarked Operations

The following cryptographic operations are benchmarked for each algorithm:

1.  **Key Generation**: The time taken to create a new public/secret key pair.
2.  **Signing**: The time taken to generate a digital signature for a fixed message.
3.  **Verification**: The time taken to verify a digital signature.

## Supported Algorithms

The benchmark suite includes a selection of classical and post-quantum signature schemes, primarily drawing from the NIST PQC Standardization process.

### Classical Schemes
-   `Ed25519`

### Post-Quantum Schemes (by NIST Security Level)

#### Level 1
-   `ML-DSA-44`
-   `FALCON-512`
-   `SPHINCS-SHA2-128f`
-   `SPHINCS-SHA2-128s`

#### Level 3
-   `ML-DSA-65`
-   `SPHINCS-SHA2-192f`
-   `SPHINCS-SHA2-192s`

#### Level 5
-   `ML-DSA-87`
-   `FALCON-1024`
-   `SPHINCS-SHA2-256f`
-   `SPHINCS-SHA2-256s`

## Project Structure

-   `src/lib.rs`: The main library crate. It defines the `SignaturePrimitive` trait and provides wrappers for each supported cryptographic algorithm.
-   `benches/primitives_benchmark.rs`: The Criterion benchmark suite. It uses the library to run and measure the performance of the keygen, sign, and verify operations.
-   `Cargo.toml`: The project manifest, defining dependencies like `oqs`, `ed25519-dalek`, and `criterion`.

## Prerequisites

-   [Rust programming language](https://www.rust-lang.org/tools/install)
-   A C compiler (like `gcc` or `clang`) for the `oqs-sys` dependency.

## How to Run the Benchmarks

To run the full benchmark suite, use the following Cargo command from the root of the project directory:

```sh
cargo bench
```

This command will compile the project in release mode and execute all defined benchmarks. The process may take several minutes to complete, as Criterion performs multiple iterations to ensure statistical significance.

## Viewing the Results

Upon completion, Criterion generates a detailed HTML report. You can find this report at:

`target/criterion/report/index.html`

Opening this file in a web browser will display interactive charts and tables comparing the performance of all benchmarked algorithms for each operation (Key Generation, Signing, and Verification).
