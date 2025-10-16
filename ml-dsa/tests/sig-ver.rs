use ml_dsa::*;

use std::{fs::read_to_string, path::PathBuf};

#[test]
fn acvp_sig_ver() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/sig-ver.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: acvp::TestVectorFile = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        for tc in tg.tests.iter() {
            match tg.parameter_set {
                acvp::ParameterSet::MlDsa44 => verify::<MlDsa44>(&tg, tc),
                acvp::ParameterSet::MlDsa65 => verify::<MlDsa65>(&tg, tc),
                acvp::ParameterSet::MlDsa87 => verify::<MlDsa87>(&tg, tc),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tg: &acvp::TestGroup, tc: &acvp::TestCase) {
    // Import the verification key
    let vk_bytes = EncodedVerifyingKey::<P>::try_from(tg.pk.as_slice()).unwrap();
    let vk = VerifyingKey::<P>::decode(&vk_bytes);

    // Import the signature
    let sig_bytes = EncodedSignature::<P>::try_from(tc.signature.as_slice()).unwrap();
    let sig = Signature::<P>::decode(&sig_bytes);

    // Verify the signature if it successfully decoded
    let test_passed = sig
        .map(|sig| vk.verify_internal(&tc.message, &sig))
        .unwrap_or_default();
    assert_eq!(test_passed, tc.test_passed);
}

mod acvp {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub(crate) struct TestVectorFile {
        #[serde(rename = "testGroups")]
        pub(crate) test_groups: Vec<TestGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct TestGroup {
        #[serde(rename = "tgId")]
        pub(crate) id: usize,

        #[serde(rename = "parameterSet")]
        pub(crate) parameter_set: ParameterSet,

        #[serde(with = "hex::serde")]
        pub(crate) pk: Vec<u8>,

        pub(crate) tests: Vec<TestCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) enum ParameterSet {
        #[serde(rename = "ML-DSA-44")]
        MlDsa44,

        #[serde(rename = "ML-DSA-65")]
        MlDsa65,

        #[serde(rename = "ML-DSA-87")]
        MlDsa87,
    }

    #[derive(Deserialize, Serialize)]
    pub(crate) struct TestCase {
        #[serde(rename = "tcId")]
        pub(crate) id: usize,

        #[serde(rename = "testPassed")]
        pub(crate) test_passed: bool,

        pub(crate) reason: String,

        #[serde(with = "hex::serde")]
        pub(crate) message: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub(crate) signature: Vec<u8>,
    }
}
