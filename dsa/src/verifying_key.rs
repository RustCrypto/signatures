//!
//! Module containing the definition of the public key container
//!

use crate::{sig::Signature, two, Components, DSA_OID};
use core::cmp::min;
use digest::Digest;
use num_bigint::{BigUint, ModInverse};
use num_traits::One;
use pkcs8::{
    der::{asn1::UIntRef, AnyRef, Decode, Encode},
    spki, AlgorithmIdentifier, DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfo,
};
use signature::DigestVerifier;

/// DSA public key.
#[derive(Clone, PartialEq, PartialOrd)]
#[must_use]
pub struct VerifyingKey {
    /// common components
    components: Components,

    /// Public component y
    y: BigUint,
}

opaque_debug::implement!(VerifyingKey);

impl VerifyingKey {
    /// Construct a new public key from the common components and the public component
    ///
    /// These values are not getting verified for validity
    pub const fn from_components(components: Components, y: BigUint) -> Self {
        Self { components, y }
    }

    /// DSA common components
    pub const fn components(&self) -> &Components {
        &self.components
    }

    /// DSA public component
    #[must_use]
    pub const fn y(&self) -> &BigUint {
        &self.y
    }

    /// Check whether the public key is valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let components = self.components();
        if !components.is_valid() {
            return false;
        }

        *self.y() >= two() && self.y().modpow(components.q(), components.p()) == BigUint::one()
    }

    /// Verify some prehashed data
    #[must_use]
    fn verify_prehashed(&self, hash: &[u8], signature: &Signature) -> Option<bool> {
        // Refuse to verify with an invalid key
        if !self.is_valid() {
            return None;
        }

        let components = self.components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let (r, s) = (signature.r(), signature.s());
        let y = self.y();

        let w = s.mod_inverse(q)?.to_biguint().unwrap();

        let n = (q.bits() / 8) as usize;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let u1 = (&z * &w) % q;
        let u2 = (r * &w) % q;
        let v = (g.modpow(&u1, p) * y.modpow(&u2, p) % p) % q;

        Some(v == *r)
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), signature::Error> {
        let hash = digest.finalize();

        let is_valid = self
            .verify_prehashed(&hash, signature)
            .ok_or_else(signature::Error::new)?;

        if !is_valid {
            return Err(signature::Error::new());
        }

        Ok(())
    }
}

impl EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        let parameters = self.components.to_vec()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifier {
            oid: DSA_OID,
            parameters: Some(parameters),
        };

        let y_bytes = self.y.to_bytes_be();
        let y = UIntRef::new(&y_bytes)?;
        let public_key = y.to_vec()?;

        SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: &public_key,
        }
        .try_into()
    }
}

impl<'a> TryFrom<SubjectPublicKeyInfo<'a>> for VerifyingKey {
    type Error = spki::Error;

    fn try_from(value: SubjectPublicKeyInfo<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(DSA_OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components = parameters.decode_into()?;

        let y = UIntRef::from_der(value.subject_public_key)?;
        let y = BigUint::from_bytes_be(y.as_bytes());

        Ok(Self::from_components(components, y))
    }
}

impl DecodePublicKey for VerifyingKey {}
