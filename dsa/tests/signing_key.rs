//! Integration tests for `dsa::SigningKey`.

// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]
#![cfg(all(feature = "hazmat", feature = "pkcs8"))]

use crypto_bigint::{
    BoxedUint, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use digest::Digest;
use dsa::{Components, KeySize, SigningKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use pkcs8::{
    DecodePrivateKey, EncodePrivateKey, LineEnding, PrivateKeyInfoRef,
    der::{
        Decode, Encode,
        asn1::{BitStringRef, UintRef},
    },
};
use sha1::Sha1;
use signature::{DigestVerifier, RandomizedDigestSigner};

const OPENSSL_PEM_PRIVATE_KEY: &str = include_str!("pems/private.pem");

#[test]
fn pkcs8_checks_supplied_public_component_consistency() {
    let key = SigningKey::from_pkcs8_pem(OPENSSL_PEM_PRIVATE_KEY).unwrap();
    let document = key.to_pkcs8_der().unwrap();
    let public = key.verifying_key().y().to_be_bytes();
    let supplied = UintRef::new(&public).unwrap().to_der().unwrap();
    let mut info = PrivateKeyInfoRef::from_der(document.as_bytes()).unwrap();
    info.public_key = Some(BitStringRef::from_bytes(&supplied).unwrap());
    assert_eq!(SigningKey::try_from(info).unwrap(), key);

    // Both alternatives are valid subgroup elements but belong to different
    // private components, so subgroup checks alone cannot reject them.
    let components = key.verifying_key().components();
    let params = BoxedMontyParams::new(components.p().clone());
    let generator = BoxedMontyForm::new((**components.g()).clone(), &params);
    for exponent in [1u64, 2] {
        let different = generator.pow(&BoxedUint::from(exponent)).retrieve();
        assert_ne!(different, **key.verifying_key().y());
        assert!(dsa::VerifyingKey::from_components(components.clone(), different.clone()).is_ok());
        let bytes = different.to_be_bytes();
        let supplied = UintRef::new(&bytes).unwrap().to_der().unwrap();
        let mut info = PrivateKeyInfoRef::from_der(document.as_bytes()).unwrap();
        info.public_key = Some(BitStringRef::from_bytes(&supplied).unwrap());
        assert!(SigningKey::try_from(info).is_err());
    }

    // Documents omitting the optional public component still derive it.
    assert_eq!(
        SigningKey::from_pkcs8_der(document.as_bytes()).unwrap(),
        key
    );
}

fn generate_keypair() -> SigningKey {
    let mut rng = UnwrapErr(SysRng);
    let components =
        Components::try_generate_from_rng_with_key_size(&mut rng, KeySize::DSA_1024_160).unwrap();
    SigningKey::try_generate_from_rng_with_components(&mut rng, components).unwrap()
}

#[test]
fn decode_encode_openssl_signing_key() {
    let signing_key = SigningKey::from_pkcs8_pem(OPENSSL_PEM_PRIVATE_KEY)
        .expect("Failed to decode PEM encoded OpenSSL key");

    let reencoded_signing_key = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key into PEM representation");

    assert_eq!(*reencoded_signing_key, OPENSSL_PEM_PRIVATE_KEY);
}

#[test]
fn encode_decode_signing_key() {
    let signing_key = generate_keypair();
    let encoded_signing_key = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let decoded_signing_key = SigningKey::from_pkcs8_pem(&encoded_signing_key).unwrap();

    assert_eq!(signing_key, decoded_signing_key);
}

#[test]
fn sign_and_verify() {
    const DATA: &[u8] = b"SIGN AND VERIFY THOSE BYTES";

    let signing_key = generate_keypair();
    let verifying_key = signing_key.verifying_key();
    let mut rng = UnwrapErr(SysRng);

    let signature =
        signing_key.sign_digest_with_rng(&mut rng, |digest: &mut Sha1| digest.update(DATA));

    assert!(
        verifying_key
            .verify_digest(
                |digest: &mut Sha1| {
                    digest.update(DATA);
                    Ok(())
                },
                &signature
            )
            .is_ok()
    );
}

#[test]
fn verify_validity() {
    let signing_key = generate_keypair();
    let components = signing_key.verifying_key().components();

    let params = BoxedMontyParams::new(Odd::new((**components.p()).clone()).unwrap());
    let form = BoxedMontyForm::new((**components.g()).clone(), &params);

    assert!(
        BoxedUint::zero() < **signing_key.x() && signing_key.x() < components.q(),
        "Requirement 0<x<q not met"
    );
    assert_eq!(
        **signing_key.verifying_key().y(),
        form.pow(signing_key.x()).retrieve(),
        "Requirement y=(g^x)%p not met"
    );
}
