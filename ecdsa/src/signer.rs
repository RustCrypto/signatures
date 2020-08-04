//! ECDSA signer. Generic over elliptic curves.
//!
//! Requires an [`elliptic_curve::Arithmetic`] impl on the curve, and a
//! [`SignPrimitive`] impl on its associated `Scalar` type.

// TODO(tarcieri): RFC 6979; support for hardware crypto accelerators

use crate::{
    hazmat::{DigestPrimitive, SignPrimitive},
    Error, Signature, SignatureSize,
};
use elliptic_curve::{
    generic_array::ArrayLength,
    ops::Invert,
    weierstrass::Curve,
    zeroize::{Zeroize, Zeroizing},
    Arithmetic, FromBytes, SecretKey,
};

#[cfg(feature = "rand")]
use {
    elliptic_curve::Generate,
    signature::{
        digest::Digest,
        rand_core::{CryptoRng, RngCore},
        RandomizedDigestSigner, RandomizedSigner,
    },
};

/// ECDSA signer
pub struct Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    secret_scalar: C::Scalar,
}

impl<C> Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Create a new signer
    pub fn new(secret_key: &SecretKey<C>) -> Result<Self, Error> {
        let scalar = C::Scalar::from_bytes(secret_key.as_bytes());

        if scalar.is_some().into() {
            Ok(Self {
                secret_scalar: scalar.unwrap(),
            })
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
impl<C, D> RandomizedDigestSigner<D, Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic,
    D: Digest<OutputSize = C::ElementSize>,
    C::Scalar: Invert<Output = C::Scalar> + Generate + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign_digest_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<Signature<C>, Error> {
        let ephemeral_scalar = Zeroizing::new(C::Scalar::generate(rng));

        self.secret_scalar
            .try_sign_prehashed(&*ephemeral_scalar, &digest.finalize())
    }
}

#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
impl<C> RandomizedSigner<Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic + DigestPrimitive,
    C::Digest: Digest<OutputSize = C::ElementSize>,
    C::Scalar: Invert<Output = C::Scalar> + Generate + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> Result<Signature<C>, Error> {
        self.try_sign_digest_with_rng(rng, C::Digest::new().chain(msg))
    }
}

impl<C> Zeroize for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,

    SignatureSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.secret_scalar.zeroize();
    }
}

impl<C> Drop for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,

    SignatureSize<C>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}
