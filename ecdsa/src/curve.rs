//! Elliptic curves (short Weierstrass form) used by ECDSA

pub use elliptic_curve::weierstrass::{point::*, Curve};

// NIST P-256

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub mod nistp256;

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub use self::nistp256::NistP256;

// NIST P-384

#[cfg(feature = "p384")]
#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
pub mod nistp384;

#[cfg(feature = "p384")]
#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
pub use self::nistp384::NistP384;

// secp256k1 (K-256)

#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub mod secp256k1;

#[cfg(feature = "k256")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub use self::secp256k1::Secp256k1;
