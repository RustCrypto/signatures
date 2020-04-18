//! NIST P-384 elliptic curve (a.k.a. secp384r1)

pub use p384::{NistP384, PublicKey, SecretKey};

/// ASN.1 DER encoded NIST P-384 ECDSA signature
pub type Asn1Signature = crate::Asn1Signature<NistP384>;

/// Fixed-sized (a.k.a. "raw") NIST P-384 ECDSA signature
pub type FixedSignature = crate::FixedSignature<NistP384>;

#[cfg(feature = "digest")]
impl signature::PrehashSignature for Asn1Signature {
    type Digest = sha2::Sha384;
}

#[cfg(feature = "digest")]
impl signature::PrehashSignature for FixedSignature {
    type Digest = sha2::Sha384;
}
