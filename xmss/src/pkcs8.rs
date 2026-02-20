//! PKCS#8 encoding/decoding support for XMSS keys and signatures.

use const_oid::ObjectIdentifier;
use der::asn1::BitStringRef;
use pkcs8::{AlgorithmIdentifierRef, EncodePrivateKey, PrivateKeyInfo};
use spki::{EncodePublicKey, SubjectPublicKeyInfoRef};

use crate::error::Error;
use crate::params::XmssParameter;
use crate::xmss::{KeyPair, SigningKey, VerifyingKey};

/// OID for XMSS hash-based signatures: `id-alg-xmss-hashsig`
/// 0.4.0.127.0.15.1.1.13.0
const XMSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.127.0.15.1.1.13.0");

/// OID for XMSSMT hash-based signatures: `id-alg-xmssmt-hashsig`
/// 0.4.0.127.0.15.1.1.14.0
const XMSSMT_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.127.0.15.1.1.14.0");

/// Returns the appropriate ASN.1 OID for the given parameter set.
fn algorithm_oid<P: XmssParameter>() -> ObjectIdentifier {
    let oid = P::oid();
    if oid.is_xmss() { XMSS_OID } else { XMSSMT_OID }
}

impl<P: XmssParameter> EncodePublicKey for VerifyingKey<P> {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        use der::Encode;

        let algorithm = AlgorithmIdentifierRef {
            oid: algorithm_oid::<P>(),
            parameters: None,
        };
        let pk_bytes = self.as_ref();
        let subject_public_key =
            BitStringRef::from_bytes(pk_bytes).map_err(|_| spki::Error::KeyMalformed)?;
        let spki_ref = SubjectPublicKeyInfoRef {
            algorithm,
            subject_public_key,
        };
        let der_bytes = spki_ref.to_der().map_err(|_| spki::Error::KeyMalformed)?;
        der::Document::try_from(der_bytes.as_slice()).map_err(|_| spki::Error::KeyMalformed)
    }
}

impl<P: XmssParameter> TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKey<P> {
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        let expected_oid = algorithm_oid::<P>();
        if spki.algorithm.oid != expected_oid {
            return Err(spki::Error::OidUnknown {
                oid: spki.algorithm.oid,
            });
        }
        let pk_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;
        VerifyingKey::<P>::try_from(pk_bytes).map_err(|_| spki::Error::KeyMalformed)
    }
}

impl<P: XmssParameter> EncodePrivateKey for KeyPair<P> {
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        let algo = AlgorithmIdentifierRef {
            oid: algorithm_oid::<P>(),
            parameters: None,
        };
        let sk_bytes = self.signing_key_ref().as_ref();
        let pk_bytes = self.verifying_key().as_ref();
        let pki = PrivateKeyInfo {
            algorithm: algo,
            private_key: sk_bytes,
            public_key: Some(pk_bytes),
        };
        pki.try_into()
    }
}

impl<P: XmssParameter> KeyPair<P> {
    /// Decodes a key pair from PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> crate::error::XmssResult<Self> {
        let pk_info = PrivateKeyInfo::try_from(der_bytes).map_err(|_| Error::InvalidKeyLength {
            expected: 0,
            got: der_bytes.len(),
        })?;

        let expected_oid = algorithm_oid::<P>();
        if pk_info.algorithm.oid != expected_oid {
            return Err(Error::InvalidOid(0));
        }

        let signing_key = SigningKey::<P>::try_from(pk_info.private_key)?;
        let verifying_key = if let Some(pk_bytes) = pk_info.public_key {
            VerifyingKey::<P>::try_from(pk_bytes)?
        } else {
            VerifyingKey::from(&signing_key)
        };

        Ok(KeyPair::new(signing_key, verifying_key))
    }
}
