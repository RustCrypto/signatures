use super::Digest;

/// Marker trait for `Signature` types computable as `S(H(m))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// For signature types that implement this trait, a blanket impl of
/// `Signer` will be provided for all types that `impl digest::Signer`.
pub trait Signature: crate::signature::Signature {
    type Digest: Digest;
}
