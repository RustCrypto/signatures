use ml_dsa::*;

use std::{fs::read_to_string, path::PathBuf};

#[test]
fn acvp_sig_gen() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/sig-gen.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: acvp::TestVectorFile = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                acvp::ParameterSet::MlDsa44 => verify::<MlDsa44>(&tc, tg.deterministic),
                acvp::ParameterSet::MlDsa65 => verify::<MlDsa65>(&tc, tg.deterministic),
                acvp::ParameterSet::MlDsa87 => verify::<MlDsa87>(&tc, tg.deterministic),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tc: &acvp::TestCase, deterministic: bool) {
    // Import the signing key
    let sk_bytes = EncodedSigningKey::<P>::try_from(tc.sk.as_slice()).unwrap();
    let sk = SigningKey::<P>::decode(&sk_bytes);

    // Verify correctness
    let rnd = if deterministic {
        B32::default()
    } else {
        B32::try_from(tc.rnd.as_slice()).unwrap()
    };
    let sig = sk.sign_internal(&[&tc.message], &rnd);
    let sig_bytes = sig.encode();

    assert_eq!(tc.signature.as_slice(), sig_bytes.as_slice());
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

        pub(crate) deterministic: bool,

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

        #[serde(with = "hex::serde")]
        pub(crate) sk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub(crate) message: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub(crate) signature: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub(crate) rnd: Vec<u8>,
    }
}
