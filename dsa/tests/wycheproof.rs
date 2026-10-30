//! Test the DSA verification against the Wycheproof test vectors.
//!
//! The vectors live in the `thirdparty/wycheproof` submodule (the C2SP project).
//! Run `git submodule update --init` to fetch them before running this suite.
//!
//! Only the standard DER-encoded signature groups (`DsaVerify`) are exercised here.
//! The `*_p1363_test.json` files use the raw (r || s) IEEE P1363 signature encoding,
//! which the `dsa` crate does not parse, so they are intentionally not loaded.

#![cfg(feature = "pkcs8")]

use dsa::{Signature, VerifyingKey};
use pkcs8::{DecodePublicKey, der::Decode};
use serde::Deserialize;
use sha2::{Sha224, Sha256};
use signature::{DigestVerifier, hazmat::PrehashVerifier};
use std::fs::File;

#[derive(Deserialize, Debug)]
struct TestFile {
    algorithm: String,
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    /// DER-encoded `SubjectPublicKeyInfo` for the DSA public key.
    #[serde(rename(deserialize = "publicKeyDer"), with = "hex::serde")]
    public_key_der: Vec<u8>,
    /// Hash function used by this group, e.g. `SHA-224` or `SHA-256`.
    sha: String,
    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    id: usize,
    comment: String,
    #[serde(with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(with = "hex::serde")]
    sig: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    /// Wycheproof "acceptable": legal but discouraged inputs (e.g. non-canonical
    /// signature encodings). Implementations are free to accept or reject these,
    /// so the test only requires the call not to panic.
    Acceptable,
}

/// Run a single Wycheproof verification test against the `dsa` crate and assert
/// the observed result matches the expected one. Returns whether the case passed.
fn run_test(vk: &VerifyingKey, hash: &str, test: &Test) -> bool {
    // The `dsa` crate parses signatures from the DER `SEQUENCE { r, s }` encoding.
    // A signature that fails to parse is treated as a verification failure, which
    // is the correct behaviour for the malformed-encoding test cases.
    let signature = match Signature::try_from(test.sig.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            // The signature did not parse as canonical DER `SEQUENCE { r, s }`.
            //
            // The only "acceptable" vectors in these files carry the `MissingZero`
            // flag (a legacy ASN.1 integer for r that drops its leading 0x00 padding
            // byte). The `dsa` crate requires canonical DER integers, so it rejects
            // these. Wycheproof permits either choice for "acceptable", so a parse
            // failure here is conformant. For "invalid" vectors a parse failure is
            // exactly what we want; for "valid" vectors it would be a real bug.
            return test.result != ExpectedResult::Valid;
        }
    };

    let verified = match hash {
        "SHA-224" => vk
            .verify_digest(
                |d: &mut Sha224| {
                    use digest::Update;
                    d.update(&test.msg);
                    Ok(())
                },
                &signature,
            )
            .is_ok(),
        "SHA-256" => vk
            .verify_digest(
                |d: &mut Sha256| {
                    use digest::Update;
                    d.update(&test.msg);
                    Ok(())
                },
                &signature,
            )
            .is_ok(),
        other => panic!("test #{}: unsupported hash {other}", test.id),
    };

    match test.result {
        ExpectedResult::Valid => verified,
        ExpectedResult::Invalid => !verified,
        // An "acceptable" vector that still parsed: Wycheproof allows the
        // implementation to either accept or reject it, so either answer conforms.
        ExpectedResult::Acceptable => true,
    }
}

/// Sanity-check the prehash verification entrypoint against a known-good vector.
fn run_prehash_smoke(vk: &VerifyingKey, hash: &str, test: &Test) {
    if test.result != ExpectedResult::Valid {
        return;
    }

    let Ok(signature) = Signature::try_from(test.sig.as_slice()) else {
        return;
    };

    let prehash = match hash {
        "SHA-224" => {
            use digest::Digest;
            Sha224::digest(&test.msg).to_vec()
        }
        "SHA-256" => {
            use digest::Digest;
            Sha256::digest(&test.msg).to_vec()
        }
        _ => return,
    };

    assert!(
        vk.verify_prehash(&prehash, &signature).is_ok(),
        "test #{}: prehash verification disagreed with digest verification",
        test.id
    );
}

fn run_file(json_file: &str) {
    let path = format!("../thirdparty/wycheproof/testvectors_v1/{json_file}");
    let data_file = File::open(&path)
        .expect("failed to open test vector file (try running `git submodule update --init`)");
    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");
    assert_eq!(tests.algorithm, "DSA");

    let mut passed = 0usize;
    let mut total = 0usize;

    for group in &tests.groups {
        // Decode the DER `SubjectPublicKeyInfo`. A group whose key the crate cannot
        // load means there is nothing to verify against, so flag it loudly rather
        // than silently skipping coverage.
        let spki = pkcs8::SubjectPublicKeyInfoRef::from_der(&group.public_key_der)
            .expect("failed to parse SubjectPublicKeyInfo DER");
        let vk = VerifyingKey::try_from(spki)
            .or_else(|_| VerifyingKey::from_public_key_der(&group.public_key_der))
            .expect("failed to load DSA verifying key from group");

        for test in &group.tests {
            total += 1;
            let ok = run_test(&vk, &group.sha, test);
            assert!(
                ok,
                "{json_file} test #{} ({}): expected {:?} but the crate disagreed",
                test.id, test.comment, test.result
            );
            passed += 1;
            run_prehash_smoke(&vk, &group.sha, test);
        }
    }

    println!("{json_file}: {passed}/{total} vectors matched");
}

#[test]
fn dsa_2048_224_sha224() {
    run_file("dsa_2048_224_sha224_test.json");
}

#[test]
fn dsa_2048_224_sha256() {
    run_file("dsa_2048_224_sha256_test.json");
}

#[test]
fn dsa_2048_256_sha256() {
    run_file("dsa_2048_256_sha256_test.json");
}

#[test]
fn dsa_3072_256_sha256() {
    run_file("dsa_3072_256_sha256_test.json");
}
