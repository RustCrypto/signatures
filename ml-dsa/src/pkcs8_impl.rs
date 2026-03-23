//! PKCS#8 private key encoding support.

#![cfg(feature = "pkcs8")]

use crate::{
    EncodedVerifyingKey, KeyGen, KeyPair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature,
    SigningKey, VerifyingKey,
};
use ::pkcs8::{
    AlgorithmIdentifierRef, PrivateKeyInfoRef,
    der::{
        self, AnyRef, Reader, TagNumber,
        asn1::{ContextSpecific, OctetStringRef},
    },
    spki::{
        self, AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
        SubjectPublicKeyInfoRef,
    },
};
use const_oid::db::fips204;

#[cfg(feature = "alloc")]
use pkcs8::{
    EncodePrivateKey, EncodePublicKey,
    der::{
        Encode, TagMode,
        asn1::{BitString, BitStringRef},
    },
    spki::{SignatureBitStringEncoding, SubjectPublicKeyInfo},
};

/// Tag number for the seed value.
const SEED_TAG_NUMBER: TagNumber = TagNumber(0);

/// ML-KEM seed serialized as ASN.1.
type SeedString<'a> = ContextSpecific<&'a OctetStringRef>;

impl AssociatedAlgorithmIdentifier for MlDsa44 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_44,
        parameters: None,
    };
}

impl AssociatedAlgorithmIdentifier for MlDsa65 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_65,
        parameters: None,
    };
}

impl AssociatedAlgorithmIdentifier for MlDsa87 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_87,
        parameters: None,
    };
}

impl<P> AssociatedAlgorithmIdentifier for Signature<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = P::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> SignatureBitStringEncoding for Signature<P> {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.encode().to_vec())
    }
}

impl<P> SignatureAlgorithmIdentifier for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

impl<P> TryFrom<PrivateKeyInfoRef<'_>> for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    fn try_from(private_key_info: PrivateKeyInfoRef<'_>) -> ::pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let mut reader = der::SliceReader::new(private_key_info.private_key.as_bytes())?;
        let seed_string = SeedString::decode_implicit(&mut reader, SEED_TAG_NUMBER)?
            .ok_or(pkcs8::Error::KeyMalformed)?;
        let seed = seed_string
            .value
            .as_bytes()
            .try_into()
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        reader.finish()?;

        Ok(P::from_seed(&seed))
    }
}

#[cfg(feature = "alloc")]
impl<P> EncodePrivateKey for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> ::pkcs8::Result<der::SecretDocument> {
        let seed_der = SeedString {
            tag_mode: TagMode::Implicit,
            tag_number: SEED_TAG_NUMBER,
            value: OctetStringRef::new(&self.seed)?,
        }
        .to_der()?;

        let private_key = OctetStringRef::new(&seed_der)?;
        let private_key_info = PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, private_key);
        ::pkcs8::SecretDocument::encode_msg(&private_key_info).map_err(::pkcs8::Error::Asn1)
    }
}

impl<P> SignatureAlgorithmIdentifier for SigningKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

impl<P> TryFrom<PrivateKeyInfoRef<'_>> for SigningKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    fn try_from(private_key_info: ::pkcs8::PrivateKeyInfoRef<'_>) -> ::pkcs8::Result<Self> {
        let keypair = KeyPair::try_from(private_key_info)?;

        Ok(keypair.signing_key)
    }
}

impl<P> SignatureAlgorithmIdentifier for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "alloc")]
impl<P> EncodePublicKey for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let public_key = self.encode();
        let subject_public_key = BitStringRef::new(0, &public_key)?;

        SubjectPublicKeyInfo {
            algorithm: P::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}

impl<P> TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        spki.algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        Ok(Self::decode(
            &EncodedVerifyingKey::<P>::try_from(
                spki.subject_public_key
                    .as_bytes()
                    .ok_or_else(|| der::Tag::BitString.value_error().to_error())?,
            )
            .map_err(|_| ::pkcs8::Error::KeyMalformed)?,
        ))
    }
}
