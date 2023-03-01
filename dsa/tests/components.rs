use dsa::Components;
use pkcs8::{
    der::{Decode, Encode},
    Document,
};

const OPENSSL_PEM_COMPONENTS: &str = include_str!("pems/params.pem");

#[test]
fn decode_encode_openssl_components() {
    let (_, document) =
        Document::from_pem(OPENSSL_PEM_COMPONENTS).expect("Failed to parse components PEM");
    let raw_components = document.as_bytes();

    let components =
        Components::from_der(raw_components).expect("Failed to parse DER into component structure");

    let reencoded_components = components
        .to_der()
        .expect("Failed to encode components to DER");

    assert_eq!(raw_components, reencoded_components);
}
