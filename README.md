# PQC Integration in OpenMLS: A Performance Analysis for a Master's Dissertation

This repository contains the code and experiments for a Master's dissertation on the practical implications of integrating Post-Quantum Cryptography (PQC) into the Messaging Layer Security (MLS) protocol. The project uses a modified version of the [OpenMLS](https://github.com/openmls/openmls) library to conduct a comprehensive analysis of performance, and artifact size overhead when using PQC signature schemes.

This work is structured around three distinct but related experiments, each contained within its own directory.

## Project Structure

The repository is organized into three main components:

-   `pqc-primitive-bench/`: An experiment to benchmark the performance of raw cryptographic primitives (key generation, signing, verification) for various classical and PQC signature schemes.
-   `mls-artifact-size/`: An experiment to measure the size of key MLS artifacts (e.g., `KeyPackage`, `Commit`, `Welcome` messages) when using different PQC and classical signature schemes.
-   `pqc-openmls/`: The core of the project, containing a modified version of the OpenMLS library integrated with PQC algorithms via `liboqs`. This component includes an extensive benchmark suite to measure the performance of core MLS operations.

## The Experiments

### 1. Raw Cryptographic Primitive Benchmarks

This experiment establishes a baseline understanding of the performance characteristics of the cryptographic algorithms used in the subsequent experiments.

-   **Objective**: To measure the performance of key generation, signing, and verification operations for a range of classical and PQC signature schemes.
-   **Algorithms Benchmarked**: Includes classical schemes like `Ed25519` and PQC schemes from the NIST PQC standardization process such as `ML-DSA`, `FALCON`, and `SPHINCS+` at various security levels.
-   **Location**: `pqc-primitive-bench/`

For detailed instructions on how to run these benchmarks, please refer to the `pqc-primitive-bench/Readme.md` file, or [click here](pqc-primitive-bench/Readme.md).

### 2. MLS Artifact Size Measurement

This experiment quantifies the impact of PQC on the size of MLS protocol messages, which has direct implications for bandwidth usage in real-world applications.

-   **Objective**: To measure and compare the size of critical MLS artifacts when generated with different signature schemes.
-   **Operations Measured**: `KeyPackage` generation, adding/removing members, self-updates, and application messages.
-   **Location**: `mls-artifact-size/`

For detailed instructions on how to run the sizing experiments, please refer to the `mls-artifact-size/Readme.md` file.

### 3. PQC-Integrated OpenMLS Performance Benchmarks

This is the central experiment of the dissertation, analyzing the real-world performance impact of PQC on a full MLS implementation.

-   **Objective**: To measure the performance of core MLS operations within an implementation that uses PQC for digital signatures.
-   **Implementation**: A modified version of `openmls` that uses `liboqs` to provide PQC capabilities.
-   **Operations Benchmarked**: Group creation, member addition (from sender and receiver perspectives), self-updates, member removal, and application messaging.
-   **Location**: `pqc-openmls/`

The benchmark suite is highly configurable, allowing for tests across different ciphersuites and group sizes. For detailed instructions on running the benchmarks, please see the `pqc-openmls/openmls/benches/Readme.md` file.

## How to Use This Repository

To replicate the experiments, navigate to the directory of the experiment you are interested in and follow the instructions in its respective `README.md` file. Each experiment is self-contained with its own dependencies and runner scripts.

```sh
# To run the primitive benchmarks
cd pqc-primitive-bench
cargo bench

# To run the artifact sizing experiment
cd ../mls-artifact-size
cargo run --release

# To run the OpenMLS performance benchmarks
cd ../pqc-openmls/openmls
./run_benchmarks_by_ciphersuite.zsh
```

This project provides a comprehensive toolset for researchers and developers interested in the practical aspects of integrating post-quantum cryptography into secure messaging protocols.
