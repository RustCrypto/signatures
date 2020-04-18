//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)

pub use p256::{NistP256, PublicKey, SecretKey};

/// ASN.1 DER encoded NIST P-256 ECDSA signature
pub type Asn1Signature = crate::Asn1Signature<NistP256>;

/// Fixed-sized (a.k.a. "raw") NIST P-256 ECDSA signature
pub type FixedSignature = crate::FixedSignature<NistP256>;

#[cfg(feature = "digest")]
impl signature::PrehashSignature for Asn1Signature {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "digest")]
impl signature::PrehashSignature for FixedSignature {
    type Digest = sha2::Sha256;
}
