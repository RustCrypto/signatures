#![cfg(feature = "alloc")]

use hex_literal::hex;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use slh_dsa::{Sha2_128s, SigningKey, VerifyingKey};
use std::ops::Deref;

#[test]
fn pkcs8_output() {
    let signing = SigningKey::<Sha2_128s>::try_from(&hex!("A0FC7756572F3008F544399C25C9E087C28287AB54ADB1601FCACF85C2995A54404F690CD9A145512F61F2E4DE9292DA71371E754B3C2A79F2471E14608A2E34")[..]).unwrap();

    let out = signing.to_pkcs8_pem(LineEnding::LF).unwrap();

    assert_eq!(
        out.deref(),
        r#"-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAMUBECg/HdWVy8wCPVEOZwlyeCHwoKHq1StsWAfys+F
wplaVEBPaQzZoUVRL2Hy5N6SktpxNx51SzwqefJHHhRgii40
-----END PRIVATE KEY-----
"#
    );

    let parsed = SigningKey::<Sha2_128s>::from_pkcs8_pem(out.deref()).unwrap();

    assert_eq!(parsed, signing);

    let public: VerifyingKey<Sha2_128s> = parsed.as_ref().clone();

    let out = public.to_public_key_pem(LineEnding::LF).unwrap();

    assert_eq!(
        out.deref(),
        r#"-----BEGIN PUBLIC KEY-----
MDAwCwYJYIZIAWUDBAMUAyEAQE9pDNmhRVEvYfLk3pKS2nE3HnVLPCp58kceFGCK
LjQ=
-----END PUBLIC KEY-----
"#
    );
}
