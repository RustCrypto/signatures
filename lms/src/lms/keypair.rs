use crate::lms::modes::LmsMode;
use crate::lms::private::SigningKey;
use crate::lms::public::VerifyingKey;
use signature::Keypair;

// implements the Keypair trait for PrivateKey
impl<Mode: LmsMode> Keypair for SigningKey<Mode> {
    type VerifyingKey = VerifyingKey<Mode>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.public()
    }
}
