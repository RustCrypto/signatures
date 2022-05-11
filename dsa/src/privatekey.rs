//!
//! Module containing the definition of the private key container
//!

use crate::{sig::Signature, Components, PublicKey, DSA_OID};
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

/// DSA private key
///
/// The [`(try_)sign_digest_with_rng`](::signature::RandomizedDigestSigner) API uses regular non-deterministic signatures,
/// while the [`(try_)sign_digest`](::signature::DigestSigner) API uses deterministic signatures as described in RFC 6979
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
    ///
    /// If you decide to clone this value, please consider using [`Zeroize::zeroize`](::zeroize::Zeroize::zeroize()) to zero out the memory region the libs of this integer are located in
    #[must_use]
    pub fn x(&self) -> &BigUint {
        &self.x
    }

    /// Check whether the private key is valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.public_key().is_valid() {
            return false;
        }

        *self.x() >= BigUint::one() && self.x() < self.public_key().components().q()
    }

    /// Sign some pre-hashed data
    fn sign_prehashed(&self, (k, inv_k): (BigUint, BigUint), hash: &[u8]) -> Option<Signature> {
        // Refuse to sign with an invalid key
        if !self.is_valid() {
            return None;
        }

        let components = self.public_key().components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let x = self.x();

        let r = g.modpow(&k, p) % q;

        let n = (q.bits() / 8) as usize;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n, block_size);
        let z = BigUint::from_bytes_be(&hash[..z_len]);

        let s = (inv_k * (z + x * &r)) % q;

        Some(Signature::from_components(r, s))
    }
}

impl<D> DigestSigner<D, Signature> for PrivateKey
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

impl<D> RandomizedDigestSigner<D, Signature> for PrivateKey
where
    D: Digest,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<Signature, signature::Error> {
        let ks = crate::generate::secret_number(&mut rng, self.public_key().components())
            .ok_or_else(signature::Error::new)?;
        let hash = digest.finalize();

        self.sign_prehashed(ks, &hash)
            .ok_or_else(signature::Error::new)
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
        let components: Components = parameters.decode_into()?;

        if !components.is_valid() {
            return Err(pkcs8::Error::KeyMalformed);
        }

        let x = UIntRef::from_der(value.private_key)?;
        let x = BigUint::from_bytes_be(x.as_bytes());

        let y = if let Some(y_bytes) = value.public_key {
            let y = UIntRef::from_der(y_bytes)?;
            BigUint::from_bytes_be(y.as_bytes())
        } else {
            crate::generate::public_component(&components, &x)
        };

        let public_key = PublicKey::from_components(components, y);
        let private_key = PrivateKey::from_components(public_key, x);

        if !private_key.is_valid() {
            return Err(pkcs8::Error::KeyMalformed);
        }

        Ok(private_key)
    }
}

impl DecodePrivateKey for PrivateKey {}

#[cfg(test)]
mod test {
    // We abused the deprecated attribute for unsecure key sizes
    // But we want to use those small key sizes for fast tests
    #![allow(deprecated)]

    use crate::{consts::DSA_1024_160, Components, PrivateKey, PublicKey, Signature};
    use digest::Digest;
    use num_bigint::BigUint;
    use num_traits::{Num, Zero};
    use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use sha1::Sha1;
    use sha2::Sha224;
    use signature::{DigestSigner, DigestVerifier, RandomizedDigestSigner};

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

        let signature =
            private_key.sign_digest_with_rng(rand::thread_rng(), Sha1::new().chain_update(DATA));

        assert!(public_key
            .verify_digest(Sha1::new().chain_update(DATA), &signature)
            .is_ok());
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

    #[test]
    fn rfc6979_signatures() {
        // TODO: Clean up this messy test

        const MESSAGE: &[u8] = b"sample";
        const MESSAGE_2: &[u8] = b"test";

        let p = BigUint::from_str_radix(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
                E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
                73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
                881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
            16,
        )
        .unwrap();
        let q = BigUint::from_str_radix("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16).unwrap();
        let g = BigUint::from_str_radix(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
            89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
            87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
            17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
            16,
        )
        .unwrap();

        let x = BigUint::from_str_radix("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7", 16).unwrap();
        let y = BigUint::from_str_radix(
            "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
            92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
            4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
            82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B",
            16,
        )
        .unwrap();

        let sha1_signature = Signature::from_components(
            BigUint::from_str_radix("2E1A0C2562B2912CAAF89186FB0F42001585DA55", 16).unwrap(),
            BigUint::from_str_radix("29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5", 16).unwrap(),
        );
        let sha1_signature_2 = Signature::from_components(
            BigUint::from_str_radix("42AB2052FD43E123F0607F115052A67DCD9C5C77", 16).unwrap(),
            BigUint::from_str_radix("183916B0230D45B9931491D4C6B0BD2FB4AAF088", 16).unwrap(),
        );

        let sha224_signature = Signature::from_components(
            BigUint::from_str_radix("4BC3B686AEA70145856814A6F1BB53346F02101E", 16).unwrap(),
            BigUint::from_str_radix("410697B92295D994D21EDD2F4ADA85566F6F94C1", 16).unwrap(),
        );
        let sha224_signature_2 = Signature::from_components(
            BigUint::from_str_radix("6868E9964E36C1689F6037F91F28D5F2C30610F2", 16).unwrap(),
            BigUint::from_str_radix("49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F", 16).unwrap(),
        );

        let components = Components::from_components(p, q, g);
        let public_key = PublicKey::from_components(components, y);
        let private_key = PrivateKey::from_components(public_key, x);

        let sha1_hash = Sha1::digest(MESSAGE);
        let sha1_hash2 = Sha1::digest(MESSAGE_2);

        let sha224_hash = Sha224::digest(MESSAGE);
        let sha224_hash_2 = Sha224::digest(MESSAGE_2);

        let sha1_k =
            BigUint::from_str_radix("7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B", 16).unwrap();
        let sha1_k_2 =
            BigUint::from_str_radix("5C842DF4F9E344EE09F056838B42C7A17F4A6433", 16).unwrap();

        let sha224_k =
            BigUint::from_str_radix("562097C06782D60C3037BA7BE104774344687649", 16).unwrap();
        let sha224_k_2 =
            BigUint::from_str_radix("4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297", 16).unwrap();

        let (gen_sha1_k, _) =
            crate::generate::secret_number_rfc6979::<Sha1>(&private_key, &sha1_hash);
        let (gen_sha1_k_2, _) =
            crate::generate::secret_number_rfc6979::<Sha1>(&private_key, &sha1_hash2);

        let (gen_sha224_k, _) =
            crate::generate::secret_number_rfc6979::<Sha224>(&private_key, &sha224_hash);
        let (gen_sha224_k_2, _) =
            crate::generate::secret_number_rfc6979::<Sha224>(&private_key, &sha224_hash_2);

        assert_eq!(sha1_k, gen_sha1_k, "SHA1 test #1");
        assert_eq!(sha1_k_2, gen_sha1_k_2, "SHA1 test #2");

        assert_eq!(sha224_k, gen_sha224_k, "SHA224 test #1");
        assert_eq!(sha224_k_2, gen_sha224_k_2, "SHA224 test #2");

        let sha1_generated = private_key.sign_digest(Sha1::new().chain_update(MESSAGE));
        let sha1_generated_2 = private_key.sign_digest(Sha1::new().chain_update(MESSAGE_2));

        let sha224_generated = private_key.sign_digest(Sha224::new().chain_update(MESSAGE));
        let sha224_generated_2 = private_key.sign_digest(Sha224::new().chain_update(MESSAGE_2));

        assert_eq!(sha1_signature, sha1_generated, "SHA1 test #1");
        assert_eq!(sha1_signature_2, sha1_generated_2, "SHA1 test #2");

        assert_eq!(sha224_signature, sha224_generated, "SHA224 test #1");
        assert_eq!(sha224_signature_2, sha224_generated_2, "SHA224 test #2");
    }
}
