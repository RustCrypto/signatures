//! Smoke tests which use `MockCurve`

#![cfg(feature = "dev")]

use elliptic_curve::dev::MockCurve;

type Signature = ecdsa::Signature<MockCurve>;
type SignatureBytes = ecdsa::SignatureBytes<MockCurve>;

#[test]
fn rejects_all_zero_signature() {
    let all_zero_bytes = SignatureBytes::default();
    assert!(Signature::try_from(all_zero_bytes.as_ref()).is_err());
}

#[test]
fn rejects_unicode_signature_without_panicking() {
    // `é` straddles the byte-64 split between the two scalar encodings.
    let input = format!("{}é{}", "0".repeat(63), "0".repeat(63));
    assert_eq!(input.len(), 128);
    assert!(input.parse::<Signature>().is_err());
}
