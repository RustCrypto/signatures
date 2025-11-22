//!
//! Module containing the definition of the public key container
//!

use crate::{Components, Signature, two};
use core::cmp::min;
use crypto_bigint::{
    BoxedUint, NonZero, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use digest::{Update, block_api::EagerHash};
use signature::{DigestVerifier, MultipartVerifier, Verifier, hazmat::PrehashVerifier};

#[cfg(feature = "pkcs8")]
use {
    crate::OID,
    pkcs8::{
        AlgorithmIdentifierRef, EncodePublicKey, SubjectPublicKeyInfoRef,
        der::{
            AnyRef, Decode, Encode,
            asn1::{BitStringRef, UintRef},
        },
        spki,
    },
};

/// DSA public key.
#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[must_use]
pub struct VerifyingKey {
    /// common components
    components: Components,

    /// Public component y
    y: NonZero<BoxedUint>,
}

impl VerifyingKey {
    /// Construct a new public key from the common components and the public component
    pub fn from_components(components: Components, y: BoxedUint) -> signature::Result<Self> {
        let y = NonZero::new(y)
            .into_option()
            .ok_or_else(signature::Error::new)?;

        let params = BoxedMontyParams::new_vartime(components.p().clone());
        let form = BoxedMontyForm::new((*y).clone(), params);

        if *y < two() || form.pow(components.q()).retrieve() != BoxedUint::one() {
            return Err(signature::Error::new());
        }

        Ok(Self { components, y })
    }

    /// DSA common components
    pub const fn components(&self) -> &Components {
        &self.components
    }

    /// DSA public component
    #[must_use]
    pub const fn y(&self) -> &NonZero<BoxedUint> {
        &self.y
    }

    /// Verify some prehashed data
    #[must_use]
    fn verify_prehashed(&self, hash: &[u8], signature: &Signature) -> Option<bool> {
        let components = self.components();
        let (p, q, g) = (components.p(), components.q(), components.g());
        let (r, s) = (signature.r(), signature.s());
        let y = self.y();

        if r >= q || s >= q {
            return Some(false);
        }

        let q = &q.resize(p.bits_precision());
        let r = &r.resize(p.bits_precision());
        let s = &s.resize(p.bits_precision());

        let w: BoxedUint = Option::from(s.invert_mod(q))?;

        let n = q.bits() / 8;
        let block_size = hash.len(); // Hash function output size

        let z_len = min(n as usize, block_size);
        let z = BoxedUint::from_be_slice(&hash[..z_len], z_len as u32 * 8)
            .expect("invariant violation");

        let z = z.resize(p.bits_precision());
        let w = w.resize(q.bits_precision());

        let u1 = (&z * &w) % q.resize(p.bits_precision());
        let u2 = r.mul_mod(&w, q);

        let p1_params = BoxedMontyParams::new(p.clone());
        let p2_params = BoxedMontyParams::new(p.clone());

        let g_form = BoxedMontyForm::new((**g).clone(), p1_params);
        let y_form = BoxedMontyForm::new((**y).clone(), p2_params);

        let v1 = g_form.pow(&u1).retrieve();
        let v2 = y_form.pow(&u2).retrieve();
        let v3 = v1 * v2;
        let p = p.resize(v3.bits_precision());
        let q = q.resize(v3.bits_precision());
        let v4 = v3 % p.as_nz_ref();
        let v = v4 % q;

        Some(v == **r)
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        self.multipart_verify(&[msg], signature)
    }
}

impl MultipartVerifier<Signature> for VerifyingKey {
    fn multipart_verify(
        &self,
        msg: &[&[u8]],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        self.verify_digest(
            |digest: &mut sha2::Sha256| {
                msg.iter().for_each(|slice| digest.update(slice));
                Ok(())
            },
            signature,
        )
    }
}

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        if let Some(true) = self.verify_prehashed(prehash, signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: EagerHash + Update,
{
    fn verify_digest<F: Fn(&mut D) -> Result<(), signature::Error>>(
        &self,
        f: F,
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        let mut digest = D::new();
        f(&mut digest)?;
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

#[cfg(feature = "pkcs8")]
impl EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        let parameters = self.components.to_der()?;
        let parameters = AnyRef::from_der(&parameters)?;
        let algorithm = AlgorithmIdentifierRef {
            oid: OID,
            parameters: Some(parameters),
        };

        let y_bytes = self.y.to_be_bytes();
        let y = UintRef::new(&y_bytes)?;
        let public_key = y.to_der()?;

        SubjectPublicKeyInfoRef {
            algorithm,
            subject_public_key: BitStringRef::new(0, &public_key)?,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for VerifyingKey {
    type Error = spki::Error;

    fn try_from(value: SubjectPublicKeyInfoRef<'a>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(OID)?;

        let parameters = value.algorithm.parameters_any()?;
        let components = parameters.decode_as()?;
        let y = UintRef::from_der(
            value
                .subject_public_key
                .as_bytes()
                .ok_or(spki::Error::KeyMalformed)?,
        )?;
        let y = BoxedUint::from_be_slice_vartime(y.as_bytes());

        Self::from_components(components, y).map_err(|_| spki::Error::KeyMalformed)
    }
}
