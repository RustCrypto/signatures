use crate::{digest::Digest, signature::Signature};

/// Marker trait for `Signature` types computable as `S(H(m))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// For signature types that implement this trait, a blanket impl of
/// `Signer` will be provided for all types that `impl digest::Signer`.
pub trait Digestable: Signature {
    /// Preferred `Digest` algorithm to use when computing this signature type.
    type Digest: Digest;
}
