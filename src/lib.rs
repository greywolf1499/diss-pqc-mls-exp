//! # Post-Quantum Cryptography Benchmark Library
//!
//! This library provides a standardized framework for benchmarking the performance of various
//! cryptographic signature algorithms. It offers a unified interface for key generation,
//! signing, and verification across both classical and post-quantum cryptographic schemes.
//!
//! The primary goal is to facilitate performance analysis of these primitives using tools
//! like `criterion.rs`. The resulting data can be used to evaluate the potential performance
//! impact of integrating post-quantum cryptography into higher-level protocols.
//!
//! The core of the library is the `SignaturePrimitive` trait, which abstracts the specific
//! details of each cryptographic implementation.

use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey, ed25519::signature::SignerMut,
};
use oqs::{Result as OqsResult, init as oqs_init, sig};
use rand::rngs::OsRng;

/// A type alias for a public key, represented as a vector of bytes.
pub type PublicKey = Vec<u8>;
/// A type alias for a secret key, represented as a vector of bytes.
pub type SecretKey = Vec<u8>;
/// A type alias for a cryptographic signature, represented as a vector of bytes.
pub type Signature = Vec<u8>;

// Wrapper for ed25519-dalek functionality.
fn ed25519_generate_keypair() -> Result<(PublicKey, SecretKey), Box<dyn std::error::Error>> {
    let sk = Ed25519SigningKey::generate(&mut OsRng);
    Ok((sk.verifying_key().to_bytes().into(), sk.to_bytes().into()))
}

fn ed25519_sign(
    private: &SecretKey,
    payload: &[u8],
) -> Result<Signature, Box<dyn std::error::Error>> {
    let mut sk = Ed25519SigningKey::try_from(private.as_slice())
        .map_err(|_| "Invalid Ed25519 secret key")?;
    let signature = sk.sign(payload);
    Ok(signature.to_bytes().into())
}

fn ed25519_verify(
    public: &PublicKey,
    payload: &[u8],
    signature: &Signature,
) -> Result<bool, Box<dyn std::error::Error>> {
    let pk = Ed25519VerifyingKey::try_from(public.as_slice())
        .map_err(|_| "Invalid Ed25519 public key")?;
    if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err("Invalid Ed25519 signature length".into());
    }
    let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    sig.copy_from_slice(signature);

    Ok(pk
        .verify_strict(payload, &Ed25519Signature::from(sig))
        .is_ok())
}

// Wrapper for OQS functionality.
fn oqs_generate_keypair(algorithm: sig::Algorithm) -> OqsResult<(Vec<u8>, Vec<u8>)> {
    oqs_init();
    let sigalg = sig::Sig::new(algorithm).map_err(|_| oqs::Error::Error)?;
    let (public_key, secret_key) = sigalg.keypair()?;
    let public_key_bytes = public_key.into_vec();
    let secret_key_bytes = secret_key.into_vec();
    Ok((public_key_bytes, secret_key_bytes))
}

fn oqs_sign(algorithm: sig::Algorithm, private: &[u8], payload: &[u8]) -> OqsResult<Vec<u8>> {
    oqs_init();
    let sigalg = sig::Sig::new(algorithm).expect("Failed to initialize OQS signature algorithm");
    let sk = sigalg
        .secret_key_from_bytes(private)
        .expect("Invalid OQS secret key");
    let signature = sigalg.sign(payload, sk).expect("Failed to sign payload");
    Ok(signature.into_vec())
}

fn oqs_verify(
    algorithm: sig::Algorithm,
    public: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, oqs::Error> {
    oqs_init();
    let sigalg = sig::Sig::new(algorithm).expect("Failed to initialize OQS signature algorithm");
    let pk = sigalg
        .public_key_from_bytes(public)
        .expect("Invalid OQS public key");
    let sig = sigalg
        .signature_from_bytes(signature)
        .expect("Invalid OQS signature");
    Ok(sigalg.verify(payload, &sig, pk).is_ok())
}

/// A trait for abstracting cryptographic signature algorithms.
///
/// This trait provides a common interface for different signature schemes,
/// allowing for uniform key generation, signing, and verification operations.
pub trait SignaturePrimitive {
    /// Returns the unique name of the algorithm.
    ///
    /// This name is used for identification purposes in benchmark reports.
    fn name(&self) -> &'static str;

    /// Generates a new public/secret key pair.
    ///
    /// # Returns
    /// A tuple containing the public key and the secret key as byte vectors.
    fn generate_keypair(&self) -> (PublicKey, SecretKey);

    /// Creates a digital signature for a given message payload using a secret key.
    ///
    /// # Arguments
    /// * `secret_key` - The secret key to be used for signing.
    /// * `message` - The message payload to be signed.
    ///
    /// # Returns
    /// The resulting signature as a byte vector.
    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature;

    /// Verifies a digital signature against a message payload using a public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key for verification.
    /// * `message` - The message payload that was signed.
    /// * `signature` - The signature to be verified.
    ///
    /// # Returns
    /// `true` if the signature is valid for the given message and public key, `false` otherwise.
    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool;
}

// Classical Signature Primitives
// ------------------------------

/// An implementation of the Ed25519 signature scheme, a widely used
/// classical elliptic curve algorithm.
pub struct Ed25519;
impl SignaturePrimitive for Ed25519 {
    fn name(&self) -> &'static str {
        "Ed25519"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match ed25519_generate_keypair() {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate Ed25519 keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match ed25519_sign(secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with Ed25519: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match ed25519_verify(public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify Ed25519 signature: {}", e),
        }
    }
}

// NIST Post-Quantum Cryptography - Level 1
// ----------------------------------------

/// An implementation of ML-DSA-44 (Dilithium2), a lattice-based signature
/// scheme selected for standardization by NIST, corresponding to security level 1.
pub struct MlDsa44;
impl SignaturePrimitive for MlDsa44 {
    fn name(&self) -> &'static str {
        "ML-DSA-44"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        oqs_generate_keypair(sig::Algorithm::MlDsa44)
            .map(|(pk, sk)| (pk, sk))
            .expect("Failed to generate ML-DSA-44 keypair")
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::MlDsa44, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with ML-DSA-44: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(sig::Algorithm::MlDsa44, public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify ML-DSA-44 signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-128f (fast variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 1.
pub struct SphincsSha2128fSimple;
impl SignaturePrimitive for SphincsSha2128fSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-128f"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2128fSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-128f keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2128fSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-128f: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2128fSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-128f signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-128s (small variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 1,
/// optimized for smaller signature sizes.
pub struct SphincsSha2128sSimple;
impl SignaturePrimitive for SphincsSha2128sSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-128s"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2128sSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-128s keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2128sSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-128s: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2128sSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-128s signature: {}", e),
        }
    }
}

/// An implementation of FALCON-512, a lattice-based signature scheme
/// selected for standardization by NIST, corresponding to security level 1.
pub struct Falcon512;
impl SignaturePrimitive for Falcon512 {
    fn name(&self) -> &'static str {
        "FALCON-512"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::Falcon512) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate FALCON-512 keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::Falcon512, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with FALCON-512: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(sig::Algorithm::Falcon512, public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify FALCON-512 signature: {}", e),
        }
    }
}

// NIST Post-Quantum Cryptography - Level 3
// ----------------------------------------

/// An implementation of ML-DSA-65 (Dilithium3), a lattice-based signature
/// scheme corresponding to NIST security level 3.
pub struct MlDsa65;
impl SignaturePrimitive for MlDsa65 {
    fn name(&self) -> &'static str {
        "ML-DSA-65"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::MlDsa65) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate ML-DSA-65 keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::MlDsa65, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with ML-DSA-65: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(sig::Algorithm::MlDsa65, public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify ML-DSA-65 signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-192f (fast variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 3.
pub struct SphincsSha2192fSimple;
impl SignaturePrimitive for SphincsSha2192fSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-192f"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2192fSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-192f keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2192fSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-192f: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2192fSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-192f signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-192s (small variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 3,
/// optimized for smaller signature sizes.
pub struct SphincsSha2192sSimple;
impl SignaturePrimitive for SphincsSha2192sSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-192s"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2192sSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-192s keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2192sSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-192s: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2192sSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-192s signature: {}", e),
        }
    }
}

// NIST Post-Quantum Cryptography - Level 5
// ----------------------------------------

/// An implementation of ML-DSA-87 (Dilithium5), a lattice-based signature
/// scheme corresponding to NIST security level 5.
pub struct MlDsa87;
impl SignaturePrimitive for MlDsa87 {
    fn name(&self) -> &'static str {
        "ML-DSA-87"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::MlDsa87) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate ML-DSA-87 keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::MlDsa87, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with ML-DSA-87: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(sig::Algorithm::MlDsa87, public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify ML-DSA-87 signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-256f (fast variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 5.
pub struct SphincsSha2256fSimple;
impl SignaturePrimitive for SphincsSha2256fSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-256f"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2256fSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-256f keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2256fSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-256f: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2256fSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-256f signature: {}", e),
        }
    }
}

/// An implementation of SPHINCS-SHA2-256s (small variant), a stateless
/// hash-based signature scheme corresponding to NIST security level 5,
/// optimized for smaller signature sizes.
pub struct SphincsSha2256sSimple;
impl SignaturePrimitive for SphincsSha2256sSimple {
    fn name(&self) -> &'static str {
        "SPHINCS-SHA2-256s"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::SphincsSha2256sSimple) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate SPHINCS-SHA2-256s keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::SphincsSha2256sSimple, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with SPHINCS-SHA2-256s: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(
            sig::Algorithm::SphincsSha2256sSimple,
            public_key,
            message,
            signature,
        ) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify SPHINCS-SHA2-256s signature: {}", e),
        }
    }
}

/// An implementation of FALCON-1024, a lattice-based signature scheme
/// corresponding to NIST security level 5.
pub struct Falcon1024;
impl SignaturePrimitive for Falcon1024 {
    fn name(&self) -> &'static str {
        "FALCON-1024"
    }

    fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        match oqs_generate_keypair(sig::Algorithm::Falcon1024) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => panic!("Failed to generate FALCON-1024 keypair: {}", e),
        }
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Signature {
        match oqs_sign(sig::Algorithm::Falcon1024, secret_key, message) {
            Ok(signature) => signature,
            Err(e) => panic!("Failed to sign message with FALCON-1024: {}", e),
        }
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        match oqs_verify(sig::Algorithm::Falcon1024, public_key, message, signature) {
            Ok(valid) => valid,
            Err(e) => panic!("Failed to verify FALCON-1024 signature: {}", e),
        }
    }
}

/// Returns a vector containing an instance of every signature primitive available.
///
/// This function is useful for iterating over all supported algorithms in benchmarks.
pub fn get_all_primitives() -> Vec<Box<dyn SignaturePrimitive>> {
    vec![
        // Classical
        Box::new(Ed25519),
        // NIST Level 1
        Box::new(MlDsa44),
        Box::new(SphincsSha2128fSimple),
        Box::new(SphincsSha2128sSimple),
        Box::new(Falcon512),
        // NIST Level 3
        Box::new(MlDsa65),
        Box::new(SphincsSha2192fSimple),
        Box::new(SphincsSha2192sSimple),
        // NIST Level 5
        Box::new(MlDsa87),
        Box::new(SphincsSha2256fSimple),
        Box::new(SphincsSha2256sSimple),
        Box::new(Falcon1024),
    ]
}
