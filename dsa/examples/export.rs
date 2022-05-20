use dsa::{Components, KeySize, SigningKey};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use std::{fs::File, io::Write};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, KeySize::DSA_2048_256);
    let signing_key = SigningKey::generate(&mut rng, components);
    let verifying_key = signing_key.verifying_key();

    let signing_key_bytes = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let verifying_key_bytes = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create("public.pem").unwrap();
    file.write_all(verifying_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();

    let mut file = File::create("private.pem").unwrap();
    file.write_all(signing_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();
}
