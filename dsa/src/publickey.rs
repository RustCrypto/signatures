//!
//! Module containing the definition of the public key container
//!

use crate::{Components, Signature, DSA_OID};
use core::cmp::min;
use digest::Digest;
use num_bigint::{BigUint, ModInverse};
use num_traits::One;
use pkcs8::{
    der::{asn1::UIntRef, AnyRef, Decode, Encode},
    spki, AlgorithmIdentifier, DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfo,
};

/// DSA public key
#[derive(Clone, PartialEq, PartialOrd)]
#[must_use]
pub struct PublicKey {
    /// common components
    components: Components,

    /// Public component y
    y: BigUint,
}

opaque_debug::implement!(PublicKey);

impl PublicKey {
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

        self.y().modpow(components.q(), components.p()) == BigUint::one()
    }

    /// Verify if the signature matches the provided hash
    #[must_use]
    pub fn verify<D>(&self, data: &[u8], signature: &Signature) -> Option<bool>
    where
        D: Digest,
    {
        // Refuse to verify with an invalid key
        if !self.is_valid() {
            return None;
        }

        let components = self.components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let (r, s) = (signature.r(), signature.s());
        let y = self.y();
        let hash = D::digest(data);

        let w = s.mod_inverse(q)?.to_biguint().unwrap();

        let n = (q.bits() / 8) as usize;
        let block_size = <D as Digest>::output_size();

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let u1 = (&z * &w) % q;
        let u2 = (r * &w) % q;
        let v = (g.modpow(&u1, p) * y.modpow(&u2, p) % p) % q;

        Some(v == *r)
    }
}

impl EncodePublicKey for PublicKey {
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

        let public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: &public_key,
        };

        public_key_info.try_into()
    }
}

impl<'a> TryFrom<SubjectPublicKeyInfo<'a>> for PublicKey {
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

impl DecodePublicKey for PublicKey {}

#[cfg(test)]
mod test {
    // We abused the deprecated attribute for unsecure key sizes
    // But we want to use those small key sizes for fast tests
    #![allow(deprecated)]

    use crate::{consts::DSA_1024_160, Components, PrivateKey, PublicKey};
    use num_bigint::BigUint;
    use num_traits::One;
    use pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

    fn generate_public_key() -> PublicKey {
        let mut rng = rand::thread_rng();
        let components = Components::generate(&mut rng, DSA_1024_160);
        let private_key = PrivateKey::generate(&mut rng, components);

        private_key.public_key().clone()
    }

    #[test]
    fn encode_decode_public_key() {
        let public_key = generate_public_key();
        let encoded_public_key = public_key.to_public_key_pem(LineEnding::LF).unwrap();
        let decoded_public_key = PublicKey::from_public_key_pem(&encoded_public_key).unwrap();

        assert_eq!(public_key, decoded_public_key);
    }

    #[test]
    fn validate_public_key() {
        let public_key = generate_public_key();
        let p = public_key.components().p();
        let q = public_key.components().q();

        // Taken from the parameter validation from bouncy castle
        assert_eq!(public_key.y().modpow(q, p), BigUint::one());
    }
}
