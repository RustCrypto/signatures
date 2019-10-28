//! ECDSA test vectors

pub mod nistp256;
pub mod nistp384;
pub mod secp256k1;

/// ECDSA test vector
pub struct TestVector {
    /// Secret key
    pub sk: &'static [u8],

    /// Public key
    pub pk: &'static [u8],

    /// Nonce (i.e. ECDSA `k` value)
    pub nonce: Option<&'static [u8]>,

    /// Message
    pub msg: &'static [u8],

    /// Signature
    pub sig: &'static [u8],
}
