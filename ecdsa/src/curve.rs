//! Elliptic curves (short Weierstrass form) used by ECDSA

// Elliptic curves
pub mod nistp256;
pub mod nistp384;
pub mod secp256k1;

// Elliptic curve points
pub mod point;

pub use self::{
    nistp256::NistP256,
    nistp384::NistP384,
    point::{CompressedCurvePoint, UncompressedCurvePoint},
    secp256k1::Secp256k1,
};

use core::{fmt::Debug, ops::Add};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength,
};

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Size of an integer modulo p (i.e. the curve's order) when serialized
    /// as octets (i.e. bytes).
    ///
    /// This is also the size of a raw ECDSA private key (as such a key is a
    /// scalar), and is equal to half the size of a fixed-width signature.
    type ScalarSize: ArrayLength<u8> + Add + Add<U1> + Eq + Ord + Unsigned;
}
