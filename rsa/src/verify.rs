//! RSA verifying key.

use crate::Signature;
use digest::DynDigest;
use signature::Verifier;

/// RSA Verifying key using PKCS1v15 padding
pub trait PKCS1v15VerifyingKey: Verifier<Signature> {}

/// RSA Verifying key using PSS padding
pub trait PSSVerifyingKey<D: DynDigest>: Verifier<Signature> {}
