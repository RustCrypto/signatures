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
        if tg.deterministic {
            // TODO(RLB): Implement the ML-DSA deterministic signature mode and use it for these
            // tests
            continue;
        }

        for tc in tg.tests {
            match tg.parameter_set {
                acvp::ParameterSet::MlDsa44 => verify::<MlDsa44>(&tc),
                acvp::ParameterSet::MlDsa65 => verify::<MlDsa65>(&tc),
                acvp::ParameterSet::MlDsa87 => verify::<MlDsa87>(&tc),
            }

            break;
        }

        break;
    }
}

fn verify<P: SigningKeyParams + VerificationKeyParams + SignatureParams>(tc: &acvp::TestCase) {
    // Import the signing key
    let sk_bytes = EncodedSigningKey::<P>::try_from(tc.sk.as_slice()).unwrap();
    let sk = SigningKey::<P>::decode(&sk_bytes);

    // Verify correctness
    let rnd = B32::try_from(tc.rnd.as_slice()).unwrap();
    let sig = sk.sign_internal(&tc.message, &rnd);
    let sig_bytes = sig.encode();

    println!("act: {}", hex::encode(sig_bytes.as_slice()));
    println!("exp: {}", hex::encode(tc.signature.as_slice()));
    //assert_eq!(tc.signature.as_slice(), sig_bytes.as_slice());
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

        pub deterministic: bool,

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
        pub sk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub message: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub signature: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub rnd: Vec<u8>,
    }
}
