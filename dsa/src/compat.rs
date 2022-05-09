//!
//! Types providing compatibility with the [signature](::signature) crate
//!
//! Example:
//!
//! ```
//! # use dsa::{Components, PrivateKey, compat::{Signer, Verifier}, consts::DSA_1024_160};
//! # use signature::{Signer as _, Verifier as _};
//! # use sha1::Sha1;
//! # fn generate() -> PrivateKey {
//! # let mut rng = rand::thread_rng();
//! # let components = Components::generate(&mut rng, DSA_1024_160);
//! # PrivateKey::generate(&mut rng, components)
//! # }
//! let private_key = generate();
//! let public_key = private_key.public_key().clone();
//! let signer: Signer<Sha1> = private_key.into();
//! let verifier: Verifier<Sha1> = public_key.into();
//!
//! let signature = signer.sign(b"hello world");
//! assert!(verifier.verify(b"hello world", &signature).is_ok());
//! assert!(verifier.verify(b"not hello world", &signature).is_err());
//! ```
//!

use crate::{PrivateKey, PublicKey, Signature as InnerSignature};
use core::fmt;
use digest::Digest;
use pkcs8::der::{self, Encode};
use std::{marker::PhantomData, ops::Deref};

/// Container implementing the [Signature](::signature::Signature) trait
pub struct Signature {
    /// Signature in DER form. This field gets generated whenever this container is constructed
    ///
    /// If the signature for whatever reason gets updated, this field needs to be updated as well.
    /// Otherwise calls to the `as_ref` function will not reflect the changes
    raw_signature: Vec<u8>,

    /// The actual signature used for the signing operations
    signature: InnerSignature,
}

impl Signature {
    /// Deconstruct the compatibility container
    pub fn into_inner(self) -> InnerSignature {
        self.signature
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.raw_signature
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.signature, f)
    }
}

impl Deref for Signature {
    type Target = InnerSignature;

    fn deref(&self) -> &Self::Target {
        &self.signature
    }
}

impl TryFrom<InnerSignature> for Signature {
    type Error = der::Error;

    fn try_from(signature: InnerSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            raw_signature: signature.to_vec()?,
            signature,
        })
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        InnerSignature::from_der(bytes)
            .map(TryInto::try_into)
            .map_err(signature::Error::from_source)?
            .map_err(signature::Error::from_source)
    }
}

/// Container implementing the [Signer](::signature::Signer) trait
pub struct Signer<D> {
    /// Phantom data for binding the digest generic parameter
    _digest_phantom: PhantomData<D>,

    /// Private key for signing messages
    private_key: PrivateKey,
}

impl<D> Signer<D> {
    /// Deconstruct the compatibility container
    pub fn into_inner(self) -> PrivateKey {
        self.private_key
    }
}

impl<D> From<PrivateKey> for Signer<D> {
    fn from(private_key: PrivateKey) -> Self {
        Self {
            _digest_phantom: PhantomData,
            private_key,
        }
    }
}

impl<D> signature::Signer<Signature> for Signer<D>
where
    D: Digest,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.private_key
            .sign::<_, D>(&mut rand::thread_rng(), msg)
            .map(TryInto::try_into)
            .ok_or_else(signature::Error::new)?
            .map_err(signature::Error::from_source)
    }
}

/// Container implementing the [Verifier](::signature::Verifier) trait
pub struct Verifier<D> {
    /// Phantom data for binding the digest generic parameter
    _digest_phantom: PhantomData<D>,

    /// Public key for verifying messages
    public_key: PublicKey,
}

impl<D> Verifier<D> {
    /// Deconstruct the compatibility container
    pub fn into_inner(self) -> PublicKey {
        self.public_key
    }
}

impl<D> From<PublicKey> for Verifier<D> {
    fn from(public_key: PublicKey) -> Self {
        Self {
            _digest_phantom: PhantomData,
            public_key,
        }
    }
}

impl<D> signature::Verifier<Signature> for Verifier<D>
where
    D: Digest,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        if !self
            .public_key
            .verify::<D>(msg, signature)
            .ok_or_else(signature::Error::new)?
        {
            return Err(signature::Error::new());
        }

        Ok(())
    }
}
