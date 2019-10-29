//! secp256k1 elliptic curve

use super::Curve;
use generic_array::typenum::U32;

/// secp256k1 elliptic curve.
///
/// Specified in Certicom's SECG in SEC 2: Recommended Elliptic Curve Domain Parameters:
///
/// <https://www.secg.org/sec2-v2.pdf>
///
/// The curve's equation is `y² = x³ + 7` over a ~256-bit prime field.
///
/// It's primarily notable for its use in Bitcoin and other cryptocurrencies.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp256k1;

impl Curve for Secp256k1 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

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
