//!
//! Module containing the definition of the private key container
//!

#![cfg(feature = "hazmat")]

use crate::{Signature, VerifyingKey};
use core::{
    cmp::min,
    fmt::{self, Debug},
};
use crypto_bigint::{
    BoxedUint, NonZero, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use digest::{Update, block_api::EagerHash};
use signature::{
    DigestSigner, MultipartSigner, RandomizedDigestSigner, Signer,
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
    rand_core::TryCryptoRng,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "hazmat")]
use {crate::Components, signature::rand_core::CryptoRng};
#[cfg(feature = "pkcs8")]
use {
    crate::OID,
    pkcs8::{
        AlgorithmIdentifierRef, EncodePrivateKey, PrivateKeyInfoRef, SecretDocument,
        der::{
            AnyRef, Decode, Encode,
            asn1::{OctetStringRef, UintRef},
        },
    },
    zeroize::Zeroize,
};

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
    x: Zeroizing<NonZero<BoxedUint>>,
}

impl SigningKey {
    /// Construct a new private key from the public key and private component
    pub fn from_components(verifying_key: VerifyingKey, x: BoxedUint) -> signature::Result<Self> {
        let x = NonZero::new(x)
            .into_option()
            .ok_or_else(signature::Error::new)?;

        if x > *verifying_key.components().q() {
            return Err(signature::Error::new());
        }

        Ok(Self {
            verifying_key,
            x: Zeroizing::new(x),
        })
    }

    /// Generate a new DSA keypair
    #[cfg(feature = "hazmat")]
    #[inline]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, components: Components) -> SigningKey {
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
    pub fn x(&self) -> &NonZero<BoxedUint> {
        &self.x
    }

    /// Try to sign the given message digest deterministically with a prehashed digest.
    /// The parameter `D` must match the hash function used to sign the digest.
    ///
    /// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
    #[cfg(feature = "hazmat")]
    pub fn sign_prehashed_rfc6979<D>(&self, prehash: &[u8]) -> Result<Signature, signature::Error>
    where
        D: EagerHash,
    {
        let k_kinv = crate::generate::secret_number_rfc6979::<D>(self, prehash)?;
        self.sign_prehashed(k_kinv, prehash)
    }

    /// Sign some pre-hashed data
    fn sign_prehashed(
        &self,
        (k, inv_k): (BoxedUint, BoxedUint),
        hash: &[u8],
    ) -> signature::Result<Signature> {
        let components = self.verifying_key().components();
        let key_size = &components.key_size;
        let (p, q, g) = (components.p(), components.q(), components.g());
        let x = self.x();

        debug_assert_eq!(key_size.n_aligned(), q.bits_precision());

        let x = x.resize(p.bits_precision());
        let x = &x;

        let k = k.resize(p.bits_precision());
        let inv_k = inv_k.resize(p.bits_precision());

        let params = BoxedMontyParams::new(p.clone());
        let form = BoxedMontyForm::new((**g).clone(), params);
        let r = form.pow(&k).retrieve() % q.resize(p.bits_precision());
        debug_assert_eq!(key_size.l_aligned(), r.bits_precision());

        let r_short = r.clone().resize(key_size.n_aligned());
        let n = q.bits() / 8;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n as usize, block_size);
        let z = BoxedUint::from_be_slice(&hash[..z_len], z_len as u32 * 8)
            .expect("invariant violation");

        let s = inv_k.mul_mod(&(z + &**x * &r), &q.resize(key_size.l_aligned()));
        let s = s.resize(key_size.n_aligned());

        debug_assert_eq!(key_size.n_aligned(), r_short.bits_precision());
        debug_assert_eq!(key_size.n_aligned(), s.bits_precision());
        let signature = Signature::from_components(r_short, s).ok_or_else(signature::Error::new)?;

        if signature.r() < q && signature.s() < q {
            Ok(signature)
        } else {
            Err(signature::Error::new())
        }
    }
}

impl ZeroizeOnDrop for SigningKey {}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.try_multipart_sign(&[msg])
    }
}

impl MultipartSigner<Signature> for SigningKey {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature, signature::Error> {
        self.try_sign_digest(|digest: &mut sha2::Sha256| {
            msg.iter().for_each(|slice| digest.update(slice));
            Ok(())
        })
    }
}

impl PrehashSigner<Signature> for SigningKey {
    /// Warning: This uses `sha2::Sha256` as the hash function for the digest. If you need to use a different one, use [`SigningKey::sign_prehashed_rfc6979`].
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature, signature::Error> {
        let k_kinv = crate::generate::secret_number_rfc6979::<sha2::Sha256>(self, prehash)?;
        self.sign_prehashed(k_kinv, prehash)
    }
}

impl RandomizedPrehashSigner<Signature> for SigningKey {
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> Result<Signature, signature::Error> {
        let components = self.verifying_key.components();

        if let Some(k_kinv) = crate::generate::secret_number(rng, components)? {
            self.sign_prehashed(k_kinv, prehash)
        } else {
            Err(signature::Error::new())
        }
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: EagerHash + Update,
{
    fn try_sign_digest<F: Fn(&mut D) -> Result<(), signature::Error>>(
        &self,
        f: F,
    ) -> Result<Signature, signature::Error> {
        let mut digest = D::new();
        f(&mut digest)?;
        let hash = digest.finalize();
        let ks = crate::generate::secret_number_rfc6979::<D>(self, &hash)?;

        self.sign_prehashed(ks, &hash)
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey
where
    D: EagerHash + Update,
{
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> Result<(), signature::Error>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> Result<Signature, signature::Error> {
        let ks = crate::generate::secret_number(rng, self.verifying_key().components())?
            .ok_or_else(signature::Error::new)?;
        let mut digest = D::new();
        f(&mut digest)?;
        let hash = digest.finalize();

        self.sign_prehashed(ks, &hash)
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let parameters = self.verifying_key().components().to_der()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifierRef {
            oid: OID,
            parameters: Some(parameters),
        };

        let mut x_bytes = self.x().to_be_bytes();
        let x = UintRef::new(&x_bytes)?;
        let mut signing_key = x.to_der()?;

        let signing_key_info =
            PrivateKeyInfoRef::new(algorithm, OctetStringRef::new(&signing_key)?);
        let secret_document = signing_key_info.try_into()?;

        signing_key.zeroize();
        x_bytes.zeroize();

        Ok(secret_document)
    }
}

#[cfg(feature = "pkcs8")]
impl<'a> TryFrom<PrivateKeyInfoRef<'a>> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyInfoRef<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components = parameters.decode_as::<Components>()?;

        // Use the precision of `p`. `p` will always have the largest precision.
        // Every operation is mod `p` anyway, so it will always fit.
        let precision = components.p().bits_precision();

        let x = UintRef::from_der(value.private_key.into())?;
        let x = BoxedUint::from_be_slice(x.as_bytes(), precision)
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        let x = NonZero::new(x)
            .into_option()
            .ok_or(pkcs8::Error::KeyMalformed)?;

        let y = if let Some(y_bytes) = value.public_key.as_ref().and_then(|bs| bs.as_bytes()) {
            let y = UintRef::from_der(y_bytes)?;
            BoxedUint::from_be_slice(y.as_bytes(), precision)
                .map_err(|_| pkcs8::Error::KeyMalformed)?
        } else {
            crate::generate::public_component(&components, &x)
                .into_option()
                .ok_or(pkcs8::Error::KeyMalformed)?
                .get()
        };

        let verifying_key =
            VerifyingKey::from_components(components, y).map_err(|_| pkcs8::Error::KeyMalformed)?;

        SigningKey::from_components(verifying_key, x.get()).map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}
