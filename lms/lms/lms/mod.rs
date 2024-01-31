//! Everything related to LMS (and not LM-OTS)

mod keypair;
pub(crate) mod modes;
mod private;
mod public;
pub mod signature;

pub use modes::{
    LmsMode, LmsSha256M32H10, LmsSha256M32H15, LmsSha256M32H20, LmsSha256M32H25, LmsSha256M32H5,
};
pub use private::PrivateKey;
pub use public::PublicKey;
pub use signature::Signature;

#[cfg(test)]
mod tests {
    use ::signature::{RandomizedSignerMut, Verifier};

    use super::*;

    use crate::{lms::PrivateKey, ots::LmsOtsSha256N32W4};

    fn test_sign_and_verify<Mode: LmsMode>() {
        let mut rng = rand::thread_rng();

        // Generate a fresh keypair
        let mut sk = PrivateKey::<Mode>::new(&mut rng);
        let pk = sk.public();

        let msg = "this is a test message".as_bytes();

        // Sign the message
        let sig = sk.try_sign_with_rng(&mut rng, msg);
        let sig = sig.unwrap();

        // Verify the signature
        assert!(pk.verify(msg, &sig).is_ok());
    }

    // TODO: macro-generate these exhaustively
    #[test]
    fn test_sign_and_verify_lms_sha256_m32_h5_lmsots_sha256_n32_w4() {
        test_sign_and_verify::<LmsSha256M32H5<LmsOtsSha256N32W4>>();
    }
}
