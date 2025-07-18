//! Everything related to LMS (and not LM-OTS)

pub mod error;
mod keypair;
pub(crate) mod modes;
mod private;
mod public;
pub mod signature;

pub use modes::{
    LmsMode, LmsSha256M32H5, LmsSha256M32H10, LmsSha256M32H15, LmsSha256M32H20, LmsSha256M32H25,
};
pub use private::SigningKey;
pub use public::VerifyingKey;
pub use signature::Signature;

#[cfg(test)]
mod tests {
    use ::signature::{RandomizedSignerMut, Verifier};

    use super::*;

    use crate::ots::{
        LmsOtsSha256N32W1, LmsOtsSha256N32W2, LmsOtsSha256N32W4, LmsOtsSha256N32W8,
    };

    fn test_sign_and_verify<Mode: LmsMode>() {
        let mut rng = rand::rng();

        // Generate a fresh keypair
        let mut sk = SigningKey::<Mode>::new(&mut rng);
        let pk = sk.public();

        let msg = "this is a test message".as_bytes();

        // Sign the message
        let sig = sk.try_sign_with_rng(&mut rng, msg);
        let sig = sig.unwrap();

        // Verify the signature
        assert!(pk.verify(msg, &sig).is_ok());
    }

    // Macro to generate exhaustive tests for all LMS and OTS mode combinations
    macro_rules! generate_lms_tests {
        (
            $(($lms_mode:ident, $ots_mode:ident)),+ $(,)?
        ) => {
            $(
                paste::paste! {
                    #[test]
                    fn [<test_sign_and_verify_ $lms_mode:snake _ $ots_mode:snake>]() {
                        test_sign_and_verify::<$lms_mode<$ots_mode>>();
                    }
                }
            )+
        };
    }

    // Generate tests for all feasible combinations of LMS and OTS modes
    // Note: H15, H20, H25 modes are excluded as they use too much memory and overflow the stack
    generate_lms_tests! {
        (LmsSha256M32H5, LmsOtsSha256N32W1),
        (LmsSha256M32H5, LmsOtsSha256N32W2),
        (LmsSha256M32H5, LmsOtsSha256N32W4),
        (LmsSha256M32H5, LmsOtsSha256N32W8),
        
        (LmsSha256M32H10, LmsOtsSha256N32W1),
        (LmsSha256M32H10, LmsOtsSha256N32W2),
        (LmsSha256M32H10, LmsOtsSha256N32W4),
        (LmsSha256M32H10, LmsOtsSha256N32W8),
    }
}
