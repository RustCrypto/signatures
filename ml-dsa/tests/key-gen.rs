use ml_dsa::*;

use hybrid_array::Array;
use std::{fs::read_to_string, path::PathBuf};

#[test]
fn acvp_key_gen() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/key-gen.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: acvp::TestVectorFile = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                acvp::ParameterSet::MlDsa44 => verify::<MlDsa44>(&tc),
                acvp::ParameterSet::MlDsa65 => verify::<MlDsa65>(&tc),
                acvp::ParameterSet::MlDsa87 => verify::<MlDsa87>(&tc),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tc: &acvp::TestCase) {
    // Import test data into the relevant array structures
    let seed = Array::try_from(tc.seed.as_slice()).unwrap();
    let vk_bytes = EncodedVerifyingKey::<P>::try_from(tc.pk.as_slice()).unwrap();
    let sk_bytes = EncodedSigningKey::<P>::try_from(tc.sk.as_slice()).unwrap();

    let kp = P::key_gen_internal(&seed);
    let sk = kp.signing_key;
    let vk = kp.verifying_key;

    // Verify correctness via serialization
    assert_eq!(sk.encode(), sk_bytes);
    assert_eq!(vk.encode(), vk_bytes);

    // Verify correctness via deserialization
    assert!(sk == SigningKey::<P>::decode(&sk_bytes));
    assert!(vk == VerifyingKey::<P>::decode(&vk_bytes));
}

mod acvp {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct TestVectorFile {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<TestGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        pub tests: Vec<TestCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub enum ParameterSet {
        #[serde(rename = "ML-DSA-44")]
        MlDsa44,

        #[serde(rename = "ML-DSA-65")]
        MlDsa65,

        #[serde(rename = "ML-DSA-87")]
        MlDsa87,
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(with = "hex::serde")]
        pub seed: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,
    }
}
