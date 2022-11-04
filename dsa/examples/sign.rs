use digest::Digest;
use dsa::{Components, KeySize, SigningKey};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use sha1::Sha1;
use signature::{RandomizedDigestSigner, SignatureEncoding};
use std::{fs::File, io::Write};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, KeySize::DSA_2048_256);
    let signing_key = SigningKey::generate(&mut rng, components);
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign_digest_with_rng(
        &mut rand::thread_rng(),
        Sha1::new().chain_update(b"hello world"),
    );

    let signing_key_bytes = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let verifying_key_bytes = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create("public.pem").unwrap();
    file.write_all(verifying_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();

    let mut file = File::create("signature.der").unwrap();
    file.write_all(&signature.to_bytes()).unwrap();
    file.flush().unwrap();

    let mut file = File::create("private.pem").unwrap();
    file.write_all(signing_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();
}
