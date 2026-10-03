//! Checked expanded-key import follows FIPS 204 Algorithms 6 and 25.

use ml_dsa::{ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey};

#[allow(deprecated)] // Interoperability requires the FIPS 204 expanded encoding.
fn check<P: MlDsaParams>() {
    // Valid expanded keys must preserve the public identity and exact signatures.
    let native = SigningKey::<P>::from_seed(&[0x42; 32].into());
    let encoded = native.expanded_key().to_expanded();
    let decoded = ExpandedSigningKey::<P>::try_from_expanded(&encoded).expect("valid expanded key");
    assert_eq!(decoded, *native.expanded_key());
    assert_eq!(
        decoded
            .sign_deterministic(b"message", b"context")
            .expect("decoded key signs"),
        native
            .expanded_key()
            .sign_deterministic(b"message", b"context")
            .expect("seed-derived key signs")
    );

    // K is an independent secret randomizer, not a public-key-derived field.
    // Expanded-only imports cannot infer a seed or require its original K.
    let mut randomized = encoded.clone();
    randomized[32] ^= 1;
    let randomized = ExpandedSigningKey::<P>::try_from_expanded(&randomized)
        .expect("independent randomizer is valid");
    let signature = randomized
        .sign_deterministic(b"message", b"context")
        .expect("randomized key signs");
    assert!(
        decoded
            .verifying_key()
            .verify_with_context(b"message", b"context", &signature)
    );

    // skDecode's packed secret coefficients have unused bit patterns; these
    // must return an error, rather than reaching BitUnPack's assertion.
    let mut invalid = encoded.clone();
    invalid[128] = 0xff;
    assert!(ExpandedSigningKey::<P>::try_from_expanded(&invalid).is_err());

    // tr and t0 are derived from A*s1+s2, not arbitrary independent fields.
    for offset in [0, 64, 128, encoded.len() - 1] {
        let mut invalid = encoded.clone();
        invalid[offset] ^= 1;
        assert!(ExpandedSigningKey::<P>::try_from_expanded(&invalid).is_err());
    }

    // Checking the first vector alone leaves the second panic path reachable.
    let mut invalid = encoded;
    let (_, _, _, s1, _, _) = P::split_sk(&invalid);
    let s2_offset = 128 + s1.len();
    invalid[s2_offset] = 0xff;
    assert!(ExpandedSigningKey::<P>::try_from_expanded(&invalid).is_err());
}

#[test]
fn checked_ml_dsa44_expanded_import() {
    check::<MlDsa44>();
}

#[test]
fn checked_ml_dsa65_expanded_import() {
    check::<MlDsa65>();
}

#[test]
fn checked_ml_dsa87_expanded_import() {
    check::<MlDsa87>();
}
