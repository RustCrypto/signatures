//! Elliptic curves used by ECDSA

use generic_array::{
    typenum::{U32, U48},
    ArrayLength,
};

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait Curve {
    /// Size of an integer modulo p (i.e. the curve's order) when serialized
    /// as octets (i.e. bytes). This also describes the size of an ECDSA
    /// private key, as well as half the size of a fixed-width signature.
    type ScalarSize: ArrayLength<u8>;
}

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
pub struct NistP256;

impl Curve for NistP256 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

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
pub struct NistP384;

impl Curve for NistP384 {
    /// Random 384-bit (48-byte) private scalar
    type ScalarSize = U48;
}

/// The secp256k1 elliptic curve: y² = x³ + 7 over a ~256-bit prime field.
/// Specified in Certicom's SECG in SEC 2: Recommended Elliptic Curve Domain Parameters:
///
/// <http://www.secg.org/sec2-v2.pdf>
///
/// This curve is most notable for its use in Bitcoin and other cryptocurrencies.
pub struct Secp256k1;

impl Curve for Secp256k1 {
    /// Random 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}
