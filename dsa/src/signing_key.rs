//!
//! Module containing the definition of the private key container
//!

use crate::{sig::Signature, Components, VerifyingKey, DSA_OID};
use core::cmp::min;
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    typenum::{IsLess, Le, NonZero},
    Digest, FixedOutput, HashMarker, OutputSizeUser,
};
use num_bigint::BigUint;
use num_traits::One;
use pkcs8::{
    der::{asn1::UIntRef, AnyRef, Decode, Encode},
    AlgorithmIdentifier, DecodePrivateKey, EncodePrivateKey, PrivateKeyInfo, SecretDocument,
};
use rand::{CryptoRng, RngCore};
use signature::{DigestSigner, RandomizedDigestSigner};
use zeroize::Zeroizing;

/// DSA private key.
///
/// The [`(try_)sign_digest_with_rng`](::signature::RandomizedDigestSigner) API uses regular non-deterministic signatures,
/// while the [`(try_)sign_digest`](::signature::DigestSigner) API uses deterministic signatures as described in RFC 6979
#[derive(Clone, PartialEq)]
#[must_use]
pub struct SigningKey {
    /// Public key
    verifying_key: VerifyingKey,

    /// Private component x
    x: Zeroizing<BigUint>,
}

opaque_debug::implement!(SigningKey);

impl SigningKey {
    /// Construct a new private key from the public key and private component
    pub fn from_components(verifying_key: VerifyingKey, x: BigUint) -> signature::Result<Self> {
        let signing_key = Self {
            verifying_key,
            x: Zeroizing::new(x),
        };

        if !signing_key.is_valid() {
            return Err(signature::Error::new());
        }
        Ok(signing_key)
    }

    /// Generate a new DSA keypair
    #[inline]
    pub fn generate<R>(rng: &mut R, components: Components) -> SigningKey
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        crate::generate::keypair(rng, components)
    }

    /// DSA public key
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// DSA private component
    ///
    /// If you decide to clone this value, please consider using [`Zeroize::zeroize`](::zeroize::Zeroize::zeroize()) to zero out the memory after you're done using the clone
    #[must_use]
    pub fn x(&self) -> &BigUint {
        &self.x
    }

    /// Check whether the private key is valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.verifying_key().is_valid() {
            return false;
        }

        *self.x() >= BigUint::one() && self.x() < self.verifying_key().components().q()
    }

    /// Sign some pre-hashed data
    fn sign_prehashed(&self, (k, inv_k): (BigUint, BigUint), hash: &[u8]) -> Option<Signature> {
        let components = self.verifying_key().components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let x = self.x();

        let r = g.modpow(&k, p) % q;

        let n = (q.bits() / 8) as usize;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let s = (inv_k * (z + x * &r)) % q;

        let signature = Signature::from_components(r, s);
        // r or s might be 0 (very unlikely but possible)
        if !signature.r_s_valid(q) {
            return None;
        }

        Some(signature)
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: Digest + CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn try_sign_digest(&self, digest: D) -> Result<Signature, signature::Error> {
        let hash = digest.finalize_fixed();
        let ks = crate::generate::secret_number_rfc6979::<D>(self, &hash);

        self.sign_prehashed(ks, &hash)
            .ok_or_else(signature::Error::new)
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey
where
    D: Digest,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<Signature, signature::Error> {
        let ks = crate::generate::secret_number(&mut rng, self.verifying_key().components())
            .ok_or_else(signature::Error::new)?;
        let hash = digest.finalize();

        self.sign_prehashed(ks, &hash)
            .ok_or_else(signature::Error::new)
    }
}

impl EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let parameters = self.verifying_key().components().to_vec()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifier {
            oid: DSA_OID,
            parameters: Some(parameters),
        };

        let x_bytes = self.x.to_bytes_be();
        let x = UIntRef::new(&x_bytes)?;
        let signing_key = x.to_vec()?;

        let signing_key_info = PrivateKeyInfo::new(algorithm, &signing_key);
        signing_key_info.try_into()
    }
}

impl<'a> TryFrom<PrivateKeyInfo<'a>> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyInfo<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(DSA_OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components: Components = parameters.decode_into()?;

        let x = UIntRef::from_der(value.private_key)?;
        let x = BigUint::from_bytes_be(x.as_bytes());

        let y = if let Some(y_bytes) = value.public_key {
            let y = UIntRef::from_der(y_bytes)?;
            BigUint::from_bytes_be(y.as_bytes())
        } else {
            crate::generate::public_component(&components, &x)
        };

        let verifying_key =
            VerifyingKey::from_components(components, y).map_err(|_| pkcs8::Error::KeyMalformed)?;

        SigningKey::from_components(verifying_key, x).map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl DecodePrivateKey for SigningKey {}
