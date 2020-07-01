//! secp256k1 elliptic curve

#[cfg(feature = "k256-arithmetic")]
mod normalize_s;
pub mod recoverable_signature;

pub use k256::{PublicKey, Secp256k1, SecretKey};
pub use recoverable_signature::{RecoverableSignature, RecoveryId};

#[cfg(feature = "k256-arithmetic")]
use normalize_s::ScalarPair;

/// ASN.1 DER encoded secp256k1 ECDSA signature.
pub type Asn1Signature = crate::Asn1Signature<Secp256k1>;

/// Fixed-sized (a.k.a. "raw") secp256k1 ECDSA signature.
pub type FixedSignature = crate::FixedSignature<Secp256k1>;

#[cfg(feature = "digest")]
impl signature::PrehashSignature for Asn1Signature {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "digest")]
impl signature::PrehashSignature for FixedSignature {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "k256-arithmetic")]
impl Asn1Signature {
    /// Normalize signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    pub fn normalize_s(&self) -> Result<Self, signature::Error> {
        // The `Asn1Signature` type should always contain a valid ASN.1 signature
        let r_and_s = ScalarPair::from_asn1_signature(&self).expect("invalid ASN.1 signature");
        normalize_s::normalize_s(r_and_s).map(|sig| Self::from(&sig))
    }
}

#[cfg(feature = "k256-arithmetic")]
impl FixedSignature {
    /// Normalize signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    pub fn normalize_s(&self) -> Result<Self, signature::Error> {
        let r_and_s = ScalarPair::from_fixed_signature(&self);
        normalize_s::normalize_s(r_and_s)
    }
}
