//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)

use super::Curve;
use generic_array::typenum::U32;

/// The NIST P-256 elliptic curve: y² = x³ - 3x + b over a ~256-bit prime field
/// where b is "verifiably random"† constant:
///
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
///
/// † NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)
///
/// NIST P-256 is also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
/// and is specified in FIPS 186-4: Digital Signature Standard (DSS):
///
/// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
///
/// This curve is part of the US National Security Agency's "Suite B" and
/// and is widely used in protocols like TLS and the associated X.509 PKI.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct NistP256;

impl Curve for NistP256 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

/// ASN.1 DER encoded NIST P-256 ECDSA signature
pub type Asn1Signature = crate::Asn1Signature<NistP256>;

/// Fixed-sized (a.k.a. "raw") NIST P-256 ECDSA signature
pub type FixedSignature = crate::FixedSignature<NistP256>;

#[cfg(feature = "digest")]
impl signature::DigestSignature for Asn1Signature {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "digest")]
impl signature::DigestSignature for FixedSignature {
    type Digest = sha2::Sha256;
}
