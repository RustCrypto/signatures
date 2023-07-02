//! PKCS#8 private key tests

#![cfg(feature = "pkcs8")]

use ed448::pkcs8::{DecodePrivateKey, KeypairBytes};

use hex_literal::hex;

/// Ed448 PKCS#8 v1 private key encoded as ASN.1 DER.
const PKCS8_V1_DER: &[u8] = include_bytes!("examples/pkcs8-v1.der");

#[test]
fn decode_pkcs8_v1() {
    let keypair = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();

    // Extracted with:
    // $ openssl asn1parse -inform der -in tests/examples/pkcs8-v1.der
    assert_eq!(
        keypair.secret_key,
        &hex!("8A57471AA375074DC7D75EA2252E9933BB15C107E4F9A2F9CFEA6C418BEBB0774D1ABB671B58B96EFF95F35D63F2418422A59C7EAE3E00D70F")[..]
    );

    assert_eq!(keypair.public_key, None);
}
