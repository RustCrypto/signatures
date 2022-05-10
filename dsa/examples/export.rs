use dsa::{consts::DSA_2048_256, Components, PrivateKey};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use std::{fs::File, io::Write};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_2048_256);
    let private_key = PrivateKey::generate(&mut rng, components);
    let public_key = private_key.public_key();

    let private_key_bytes = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let public_key_bytes = public_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create("public.pem").unwrap();
    file.write_all(public_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();

    let mut file = File::create("private.pem").unwrap();
    file.write_all(private_key_bytes.as_bytes()).unwrap();
    file.flush().unwrap();
}
