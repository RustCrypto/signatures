//! Hexadecimal display/serialization tests.

use ed448::Signature;
use hex_literal::hex;
use std::str::FromStr;

/// Test 1 signature from RFC 8032 § 7.4
/// <https://datatracker.ietf.org/doc/html/rfc8032#section-7.4>
const TEST_1_SIGNATURE: [u8; Signature::BYTE_SIZE] = hex!(
    "533a37f6bbe457251f023c0d88f976ae
    2dfb504a843e34d2074fd823d41a591f
    2b233f034f628281f2fd7a22ddd47d78
    28c59bd0a21bfd3980ff0d2028d4b18a
    9df63e006c5d1c2d345b925d8dc00b41
    04852db99ac5c7cdda8530a113a0f4db
    b61149f05a7363268c71d95808ff2e65
    2600"
);

#[test]
fn display() {
    let sig = Signature::from_bytes(&TEST_1_SIGNATURE);
    assert_eq!(
        sig.to_string(),
        "533A37F6BBE457251F023C0D88F976AE2DFB504A843E34D2074FD823D41A591F2B233F034F628281F2FD7A22DDD47D7828C59BD0A21BFD3980FF0D2028D4B18A9DF63E006C5D1C2D345B925D8DC00B4104852DB99AC5C7CDDA8530A113A0F4DBB61149F05A7363268C71D95808FF2E652600"
    )
}

#[test]
fn lower_hex() {
    let sig = Signature::from_bytes(&TEST_1_SIGNATURE);
    assert_eq!(
        format!("{:x}", sig),
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"
    )
}

#[test]
fn upper_hex() {
    let sig = Signature::from_bytes(&TEST_1_SIGNATURE);
    assert_eq!(
        format!("{:X}", sig),
        "533A37F6BBE457251F023C0D88F976AE2DFB504A843E34D2074FD823D41A591F2B233F034F628281F2FD7A22DDD47D7828C59BD0A21BFD3980FF0D2028D4B18A9DF63E006C5D1C2D345B925D8DC00B4104852DB99AC5C7CDDA8530A113A0F4DBB61149F05A7363268C71D95808FF2E652600"
    )
}

#[test]
fn from_str_lower() {
    let sig = Signature::from_str("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600").unwrap();
    assert_eq!(sig.to_bytes(), TEST_1_SIGNATURE);
}

#[test]
fn from_str_upper() {
    let sig = Signature::from_str("533A37F6BBE457251F023C0D88F976AE2DFB504A843E34D2074FD823D41A591F2B233F034F628281F2FD7A22DDD47D7828C59BD0A21BFD3980FF0D2028D4B18A9DF63E006C5D1C2D345B925D8DC00B4104852DB99AC5C7CDDA8530A113A0F4DBB61149F05A7363268C71D95808FF2E652600").unwrap();
    assert_eq!(sig.to_bytes(), TEST_1_SIGNATURE);
}

#[test]
fn from_str_rejects_mixed_case() {
    let result = Signature::from_str(
        "533A37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
    );
    assert!(result.is_err());
}
