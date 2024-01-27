//!
//! Module containing the definition of the private key container
//!

use crate::{Components, Signature, VerifyingKey, OID};
use core::{
    cmp::min,
    fmt::{self, Debug},
};
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset};
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::{
    der::{asn1::UintRef, AnyRef, Decode, Encode},
    AlgorithmIdentifierRef, EncodePrivateKey, PrivateKeyInfo, SecretDocument,
};
use signature::{
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
    rand_core::CryptoRngCore,
    DigestSigner, RandomizedDigestSigner, Signer,
};
use zeroize::{Zeroize, Zeroizing};

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

impl SigningKey {
    /// Construct a new private key from the public key and private component
    pub fn from_components(verifying_key: VerifyingKey, x: BigUint) -> signature::Result<Self> {
        if x.is_zero() || x > *verifying_key.components().q() {
            return Err(signature::Error::new());
        }

        Ok(Self {
            verifying_key,
            x: Zeroizing::new(x),
        })
    }

    /// Generate a new DSA keypair
    #[inline]
    pub fn generate(rng: &mut impl CryptoRngCore, components: Components) -> SigningKey {
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

    /// Try to sign the given message digest deterministically with a prehashed digest.
    /// The parameter `D` must match the hash function used to sign the digest.
    ///
    /// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
    pub fn sign_prehashed_rfc6979<D>(&self, prehash: &[u8]) -> Result<Signature, signature::Error>
    where
        D: Digest + BlockSizeUser + FixedOutputReset,
    {
        let k_kinv = crate::generate::secret_number_rfc6979::<D>(self, prehash);
        self.sign_prehashed(k_kinv, prehash)
    }

    /// Sign some pre-hashed data
    fn sign_prehashed(
        &self,
        (k, inv_k): (BigUint, BigUint),
        hash: &[u8],
    ) -> signature::Result<Signature> {
        let components = self.verifying_key().components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let x = self.x();

        let r = g.modpow(&k, p) % q;

        let n = q.bits() / 8;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let s = (inv_k * (z + x * &r)) % q;

        let signature = Signature::from_components(r, s)?;

        if signature.r() < q && signature.s() < q {
            Ok(signature)
        } else {
            Err(signature::Error::new())
        }
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let digest = sha2::Sha256::new_with_prefix(msg);
        self.try_sign_digest(digest)
    }
}

impl PrehashSigner<Signature> for SigningKey {
    /// Warning: This uses `sha2::Sha256` as the hash function for the digest. If you need to use a different one, use [`SigningKey::sign_prehashed_rfc6979`].
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature, signature::Error> {
        let k_kinv = crate::generate::secret_number_rfc6979::<sha2::Sha256>(self, prehash);
        self.sign_prehashed(k_kinv, prehash)
    }
}

impl RandomizedPrehashSigner<Signature> for SigningKey {
    fn sign_prehash_with_rng(
        &self,
        mut rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<Signature, signature::Error> {
        let components = self.verifying_key.components();

        if let Some(k_kinv) = crate::generate::secret_number(&mut rng, components) {
            self.sign_prehashed(k_kinv, prehash)
        } else {
            Err(signature::Error::new())
        }
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    fn try_sign_digest(&self, digest: D) -> Result<Signature, signature::Error> {
        let hash = digest.finalize_fixed();
        let ks = crate::generate::secret_number_rfc6979::<D>(self, &hash);

        self.sign_prehashed(ks, &hash)
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey
where
    D: Digest,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: &mut impl CryptoRngCore,
        digest: D,
    ) -> Result<Signature, signature::Error> {
        let ks = crate::generate::secret_number(&mut rng, self.verifying_key().components())
            .ok_or_else(signature::Error::new)?;
        let hash = digest.finalize();

        self.sign_prehashed(ks, &hash)
    }
}

impl EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let parameters = self.verifying_key().components().to_der()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifierRef {
            oid: OID,
            parameters: Some(parameters),
        };

        let mut x_bytes = self.x().to_bytes_be();
        let x = UintRef::new(&x_bytes)?;
        let mut signing_key = x.to_der()?;

        let signing_key_info = PrivateKeyInfo::new(algorithm, &signing_key);
        let secret_document = signing_key_info.try_into()?;

        signing_key.zeroize();
        x_bytes.zeroize();

        Ok(secret_document)
    }
}

impl<'a> TryFrom<PrivateKeyInfo<'a>> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyInfo<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components = parameters.decode_as::<Components>()?;

        let x = UintRef::from_der(value.private_key)?;
        let x = BigUint::from_bytes_be(x.as_bytes());

        let y = if let Some(y_bytes) = value.public_key {
            let y = UintRef::from_der(y_bytes)?;
            BigUint::from_bytes_be(y.as_bytes())
        } else {
            crate::generate::public_component(&components, &x)
        };

        let verifying_key =
            VerifyingKey::from_components(components, y).map_err(|_| pkcs8::Error::KeyMalformed)?;

        SigningKey::from_components(verifying_key, x).map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}
