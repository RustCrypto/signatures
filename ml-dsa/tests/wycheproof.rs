//! Test against the Wycheproof test vectors.

// Implementation is based in part on `rsa` which is in turn based on Graviola.

use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
use serde::Deserialize;
use signature::{SignatureEncoding, Signer};
use std::fs::File;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
    header: Vec<String>,
    algorithm: String,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[allow(dead_code)]
    #[serde(rename(deserialize = "type"))]
    type_: String,

    #[serde(default, rename(deserialize = "privateSeed"), with = "hex::serde")]
    private_seed: Vec<u8>,

    #[serde(default, rename(deserialize = "publicKey"), with = "hex::serde")]
    #[allow(dead_code)]
    public_key: Vec<u8>,

    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    id: usize,
    comment: String,
    #[serde(with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ctx: Vec<u8>,
    #[serde(with = "hex::serde")]
    sig: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

macro_rules! mldsa_sign_from_seed_test {
    ($name:ident, $json_file:expr, $keypair:ident) => {
        #[test]
        fn $name() {
            let path = format!("../thirdparty/wycheproof/testvectors_v1/{}", $json_file);
            let data_file = File::open(&path)
                .expect("failed to open data file (try running `git submodule update --init`)");

            println!("Loading file: {path}");

            let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");
            println!("{}:\n{}\n", tests.algorithm, tests.header.join(""));

            for group in tests.groups {
                let sk = $keypair::from_seed(&group.private_seed.as_slice().try_into().unwrap());

                for test in &group.tests {
                    println!("Test #{}: {} ({:?})", test.id, &test.comment, &test.result);

                    if test.ctx.is_empty() {
                        let sig = sk.sign(&test.msg);
                        assert_eq!(&*sig.to_bytes(), test.sig.as_slice());
                    } else {
                        let result = sk.signing_key().sign_deterministic(&test.msg, &test.ctx);

                        match test.result {
                            ExpectedResult::Valid => {
                                assert_eq!(&*result.unwrap().to_bytes(), test.sig.as_slice());
                            }
                            ExpectedResult::Invalid => {
                                assert!(result.is_err());
                            }
                            other => todo!("{:?}", other),
                        }
                    }
                }
            }
        }
    };
}

mldsa_sign_from_seed_test!(
    mldsa_44_sign_seed_test,
    "mldsa_44_sign_seed_test.json",
    MlDsa44
);
mldsa_sign_from_seed_test!(
    mldsa_65_sign_seed_test,
    "mldsa_65_sign_seed_test.json",
    MlDsa65
);
mldsa_sign_from_seed_test!(
    mldsa_87_sign_seed_test,
    "mldsa_87_sign_seed_test.json",
    MlDsa87
);
