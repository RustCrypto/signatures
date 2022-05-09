//!
//! Module containing the definition of the private key container
//!

use crate::{Components, PublicKey, Signature, DSA_OID};
use core::cmp::min;
use digest::Digest;
use num_bigint::BigUint;
use pkcs8::{
    der::{asn1::UIntRef, AnyRef, Decode, Encode},
    AlgorithmIdentifier, DecodePrivateKey, EncodePrivateKey, PrivateKeyInfo, SecretDocument,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// DSA private key
#[derive(Clone, PartialEq)]
#[must_use]
pub struct PrivateKey {
    /// Public key
    public_key: PublicKey,

    /// Private component x
    x: Zeroizing<BigUint>,
}

opaque_debug::implement!(PrivateKey);

impl PrivateKey {
    /// Construct a new private key from the public key and private component
    ///
    /// These values are not getting verified for validity
    pub fn from_components(public_key: PublicKey, x: BigUint) -> Self {
        Self {
            public_key,
            x: Zeroizing::new(x),
        }
    }

    /// Generate a new DSA keypair
    /// Generate a new DSA keypair using the common components
    #[inline]
    pub fn generate<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
        components: Components,
    ) -> PrivateKey {
        crate::generate::keypair(rng, components)
    }

    /// DSA public key
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// DSA private component
    #[must_use]
    pub fn x(&self) -> &BigUint {
        &self.x
    }

    /// Check whether the private key is valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.public_key().components().is_valid()
    }

    /// Sign data with the private key
    pub fn sign<R: CryptoRng + RngCore + ?Sized, D: Digest>(
        &self,
        rng: &mut R,
        data: &[u8],
    ) -> Option<Signature> {
        // Refuse to sign with an invalid key
        if !self.is_valid() {
            return None;
        }

        let components = self.public_key().components();
        let (k, inv_k) = crate::generate::secret_number(rng, components)?;
        let (p, q, g) = (components.p(), components.q(), components.g());
        let hash = D::digest(data);
        let x = self.x();

        let r = g.modpow(&k, p) % q;

        let n = (q.bits() / 8) as usize;
        let block_size = <D as Digest>::output_size();

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let s = (inv_k * (z + x * &r)) % q;

        Some(Signature::new(r, s))
    }
}

impl EncodePrivateKey for PrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let parameters = self.public_key().components().to_vec()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifier {
            oid: DSA_OID,
            parameters: Some(parameters),
        };

        let x_bytes = self.x.to_bytes_be();
        let x = UIntRef::new(&x_bytes)?;
        let private_key = x.to_vec()?;

        let private_key_info = PrivateKeyInfo::new(algorithm, &private_key);
        private_key_info.try_into()
    }
}

impl<'a> TryFrom<PrivateKeyInfo<'a>> for PrivateKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyInfo<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(DSA_OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components = parameters.decode_into()?;

        let x = UIntRef::from_der(value.private_key)?;
        let x = BigUint::from_bytes_be(x.as_bytes());

        let y = if let Some(y_bytes) = value.public_key {
            let y = UIntRef::from_der(y_bytes)?;
            BigUint::from_bytes_be(y.as_bytes())
        } else {
            crate::generate::public_component(&components, &x)
        };

        let public_key = PublicKey::from_components(components, y);
        Ok(PrivateKey::from_components(public_key, x))
    }
}

impl DecodePrivateKey for PrivateKey {}

#[cfg(test)]
mod test {
    // We abused the deprecated attribute for unsecure key sizes
    // But we want to use those small key sizes for fast tests
    #![allow(deprecated)]

    use crate::{consts::DSA_1024_160, Components, PrivateKey};
    use num_bigint::BigUint;
    use num_traits::Zero;
    use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use sha1::Sha1;

    fn generate_keypair() -> PrivateKey {
        let mut rng = rand::thread_rng();
        let components = Components::generate(&mut rng, DSA_1024_160);
        PrivateKey::generate(&mut rng, components)
    }

    #[test]
    fn encode_decode_private_key() {
        let private_key = generate_keypair();
        let encoded_private_key = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let decoded_private_key = PrivateKey::from_pkcs8_pem(&encoded_private_key).unwrap();

        assert_eq!(private_key, decoded_private_key);
    }

    #[test]
    fn sign_and_verify() {
        const DATA: &[u8] = b"SIGN AND VERIFY THOSE BYTES";

        let private_key = generate_keypair();
        let public_key = private_key.public_key();

        let signature = private_key
            .sign::<_, Sha1>(&mut rand::thread_rng(), DATA)
            .expect("Failed to sign");
        assert!(public_key
            .verify::<Sha1>(DATA, &signature)
            .expect("Failed to verify"));
    }

    #[test]
    fn verify_validity() {
        let private_key = generate_keypair();
        let components = private_key.public_key().components();

        assert!(
            BigUint::zero() < *private_key.x() && private_key.x() < components.q(),
            "Requirement 0<x<q not met"
        );
        assert_eq!(
            *private_key.public_key().y(),
            components.g().modpow(private_key.x(), components.p()),
            "Requirement y=(g^x)%p not met"
        );
    }
}
