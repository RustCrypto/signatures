//! RFC6979 test vectors.
//!
//! <https://datatracker.ietf.org/doc/html/rfc6979#appendix-A>

use hex_literal::hex;
use rfc6979::{
    KGenerator,
    bigint::{U128, U256, U576},
};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

/// Test vector used by RFC6979
const EXAMPLE_MSG: &str = "sample";

/// "Detailed Example" from RFC6979 Appendix A.1.
///
/// Example for ECDSA on the curve K-163 described in FIPS 186-4 (also known as "ansix9t163k1"
/// in X9.62), defined over a field GF(2^163)
#[test]
fn k163_sha256() {
    let q = U256::from_be_hex("000000000000000000000004000000000000000000020108A2E0CC0D99F8A5EF");
    let x = hex!("009A4D6792295A7F730FC3F2B49CBC0F62E862272F");
    let h = Sha256::digest(EXAMPLE_MSG);

    let mut kgen = KGenerator::<Sha256, U256>::new(&x, &h, b"", &q);
    let mut k = [0u8; 21];
    kgen.fill_next_k(&mut k);
    assert_eq!(k, hex!("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B"));
}

/// Example from RFC6979 Appendix A.2.7.
#[test]
fn p521_sha512() {
    let q = U576::from_be_hex(
        "00000000000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    );
    let x = hex!(
        "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
    );
    let h = Sha512::digest(EXAMPLE_MSG);

    let mut kgen = KGenerator::<Sha512, U576>::new(&x, &h, b"", &q);
    let mut k = [0u8; 66];
    kgen.fill_next_k(&mut k);

    let expected_k = hex!(
        "01DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3"
    );
    assert_eq!(k, expected_k);
}

/// Ensure things are working with the SHA-3 crate, which doesn't support `block_api`.
/// (this is largely an HMAC-DRBG test)
#[test]
fn non_block_api() {
    let q = U128::from_u128(0xffffffffffffffffffffffff);
    let x = hex!("000000000000000000000000");
    let h = hex!("080808080808080808080808");

    let mut kgen = KGenerator::<Sha3_256, U128>::new(&x, &h, b"", &q);
    let mut k = [0u8; 12];
    kgen.fill_next_k(&mut k);
    assert_eq!(k, hex!("d460ac6531e9743d3829850f"));
}
