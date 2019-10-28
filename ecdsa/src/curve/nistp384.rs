//! NIST P-384 elliptic curve (a.k.a. secp384r1)

use super::Curve;
use generic_array::typenum::U48;

/// The NIST P-384 elliptic curve: y² = x³ - 3x + b over a ~384-bit prime field
/// where b is "verifiably random"† constant:
///
/// b = 2758019355995970587784901184038904809305690585636156852142
///     8707301988689241309860865136260764883745107765439761230575
///
/// † NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)
///
/// NIST P-384 is also known as secp384r1 (SECG) and is specified in
/// FIPS 186-4: Digital Signature Standard (DSS):
///
/// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
///
/// This curve is part of the US National Security Agency's "Suite B" and
/// and is widely used in protocols like TLS and the associated X.509 PKI.
#[derive(Debug, Default)]
pub struct NistP384;

impl Curve for NistP384 {
    /// 384-bit (48-byte) private scalar
    type ScalarSize = U48;
}

/// Fixed-sized (a.k.a. "raw") NIST P-384 ECDSA signature
pub type FixedSignature = crate::fixed_signature::FixedSignature<NistP384>;
