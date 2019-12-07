//! secp256k1 elliptic curve

pub use elliptic_curve::weierstrass::curve::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// ASN.1 DER encoded secp256k1 ECDSA signature
pub type Asn1Signature = crate::Asn1Signature<Secp256k1>;

/// Fixed-sized (a.k.a. "raw") secp256k1 ECDSA signature
pub type FixedSignature = crate::FixedSignature<Secp256k1>;

#[cfg(feature = "digest")]
impl signature::DigestSignature for Asn1Signature {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "digest")]
impl signature::DigestSignature for FixedSignature {
    type Digest = sha2::Sha256;
}
