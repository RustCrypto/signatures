//! Tests for serde serializers/deserializers

#![cfg(feature = "serde")]

use ed448_signature::{Signature, SignatureBytes};
use hex_literal::hex;

const EXAMPLE_SIGNATURE: SignatureBytes = hex!(
    "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807"
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7"
);

#[test]
fn test_serialize() {
    let signature = Signature::try_from(&EXAMPLE_SIGNATURE[..]).unwrap();
    let encoded_signature: Vec<u8> = bincode::serialize(&signature).unwrap();
    assert_eq!(&EXAMPLE_SIGNATURE[..], &encoded_signature[..]);
}

#[test]
fn test_deserialize() {
    let signature = bincode::deserialize::<Signature>(&EXAMPLE_SIGNATURE).unwrap();
    assert_eq!(EXAMPLE_SIGNATURE, signature.to_bytes());
}
