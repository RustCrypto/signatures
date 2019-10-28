//! Elliptic curves used by ECDSA

pub mod nistp256;
pub mod nistp384;
pub mod secp256k1;

pub use self::{nistp256::NistP256, nistp384::NistP384, secp256k1::Secp256k1};

use core::fmt::Debug;

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait Curve: Debug + Default + Send + Sync {
    /// Size of an integer modulo p (i.e. the curve's order) when serialized
    /// as octets (i.e. bytes). This also describes the size of an ECDSA
    /// private key, as well as half the size of a fixed-width signature.
    type ScalarSize;
}
