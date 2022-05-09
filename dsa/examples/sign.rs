use dsa::{consts::DSA_2048_256, Components, PrivateKey};
use pkcs8::{der::Encode, EncodePrivateKey, EncodePublicKey, LineEnding};
use sha1::Sha1;
use std::{fs::File, io::Write};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_2048_256);
    let private_key = PrivateKey::generate(&mut rng, components);
    let public_key = private_key.public_key();
    let signature = private_key
        .sign::<_, Sha1>(&mut rng, b"hello world")
        .unwrap();

    let mut file = File::create("public.pem").unwrap();
    file.write_all(
        public_key
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    file.flush().unwrap();

    let mut file = File::create("signature.der").unwrap();
    file.write_all(signature.to_vec().unwrap().as_ref())
        .unwrap();
    file.flush().unwrap();

    let mut file = File::create("private.pem").unwrap();
    file.write_all(private_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    file.flush().unwrap();
}
