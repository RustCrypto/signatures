//! PKCS#8 private key support.
//!
//! Implements Ed448 PKCS#8 private keys as described in RFC8410 Section 7:
//! <https://datatracker.ietf.org/doc/html/rfc8410#section-7>
//!
//! ## SemVer Notes
//!
//! The `pkcs8` module of this crate is exempted from SemVer as it uses a
//! pre-1.0 dependency (the `pkcs8` crate).
//!
//! However, breaking changes to this module will be accompanied by a minor
//! version bump.
//!
//! Please lock to a specific minor version of the `ed448` crate to avoid
//! breaking changes when using this module.
pub use pkcs8::{DecodePrivateKey, Error, ObjectIdentifier, PrivateKeyInfo, Result};

use core::fmt;

/// Algorithm [`ObjectIdentifier`] for the Ed448 digital signature algorithm
/// (`id-Ed448`).
///
/// <http://oid-info.com/get/1.3.101.113>
pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

/// Ed448 Algorithm Identifier.
pub const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

pub struct KeypairBytes {
    /// Ed448 secret key.
    ///
    /// Little endian serialization of an element of the Curve448 scalar
    /// field, prior to "clamping" (i.e. setting/clearing bits to ensure the
    /// scalar is actually a valid field element)
    pub secret_key: [u8; Self::BYTE_SIZE / 2],

    /// Ed448 public key (if available).
    ///
    /// Compressed Edwards-y encoded curve point.
    pub public_key: Option<PublicKeyBytes>,
}

impl KeypairBytes {
    /// Size of an Ed448 keypair when serialized as bytes.
    const BYTE_SIZE: usize = 114;

    /// Parse raw keypair from a 114-byte input.
    pub fn from_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Self {
        let (sk, pk) = bytes.split_at(Self::BYTE_SIZE / 2);

        Self {
            secret_key: sk.try_into().expect("secret key size error"),
            public_key: Some(PublicKeyBytes(
                pk.try_into().expect("public key size error"),
            )),
        }
    }

    /// Serialize as a 64-byte keypair.
    ///
    /// # Returns
    ///
    /// - `Some(bytes)` if the `public_key` is present.
    /// - `None` if the `public_key` is absent (i.e. `None`).
    pub fn to_bytes(&self) -> Option<[u8; Self::BYTE_SIZE]> {
        if let Some(public_key) = &self.public_key {
            let mut result = [0u8; Self::BYTE_SIZE];
            let (sk, pk) = result.split_at_mut(Self::BYTE_SIZE / 2);
            sk.copy_from_slice(&self.secret_key);
            pk.copy_from_slice(public_key.as_ref());
            Some(result)
        } else {
            None
        }
    }
}

impl TryFrom<PrivateKeyInfo<'_>> for KeypairBytes {
    type Error = Error;

    fn try_from(private_key: PrivateKeyInfo<'_>) -> Result<Self> {
        private_key.algorithm.assert_algorithm_oid(ALGORITHM_OID)?;

        if private_key.algorithm.parameters.is_some() {
            return Err(Error::ParametersMalformed);
        }

        // Ed25519 PKCS#8 keys are represented as a nested OCTET STRING
        // (i.e. an OCTET STRING within an OCTET STRING).
        //
        // This match statement checks and removes the inner OCTET STRING
        // header value:
        //
        // - 0x04: OCTET STRING tag
        // - 0x39: 57-byte length
        let secret_key = match private_key.private_key {
            [0x04, 0x39, rest @ ..] => rest.try_into().map_err(|_| Error::KeyMalformed),
            _ => Err(Error::KeyMalformed),
        }?;

        let public_key = private_key
            .public_key
            .map(|bytes| bytes.try_into().map_err(|_| Error::KeyMalformed))
            .transpose()?
            .map(PublicKeyBytes);

        Ok(Self {
            secret_key,
            public_key,
        })
    }
}

impl fmt::Debug for KeypairBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeypairBytes")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicKeyBytes(pub [u8; Self::BYTE_SIZE]);

impl PublicKeyBytes {
    /// Size of an Ed448 public key when serialized as bytes.
    const BYTE_SIZE: usize = 57;

    /// Returns the raw bytes of the public key.
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }
}

impl AsRef<[u8; Self::BYTE_SIZE]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKeyBytes(")?;

        for &byte in self.as_ref() {
            write!(f, "{:02X}", byte)?;
        }

        f.write_str(")")
    }
}
