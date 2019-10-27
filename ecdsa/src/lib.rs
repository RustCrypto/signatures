//! Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! [FIPS 186-4] (Digital Signature Standard)

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/ecdsa/0.0.0"
)]

pub mod curve;
