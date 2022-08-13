//! RSA signing key.

use crate::Signature;
use digest::DynDigest;
use signature::{RandomizedSigner, Signer};

/// RSA Signing key using PKCS1v15 padding
pub trait PKCS1v15SigningKey: Signer<Signature> {}
/// RSA Verifying key using PKCS1v15 padding
pub trait PKCS1v15BlindedSigningKey: RandomizedSigner<Signature> {}

/// RSA Signing key using PSS padding
pub trait PSSSigningKey<D: DynDigest>: RandomizedSigner<Signature> {}
/// RSA Verifying key using PSS padding
pub trait PSSBlindedSigningKey<D: DynDigest>: RandomizedSigner<Signature> {}
