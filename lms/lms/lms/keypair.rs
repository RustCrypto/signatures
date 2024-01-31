use crate::lms::modes::LmsMode;
use crate::lms::private::PrivateKey;
use crate::lms::public::PublicKey;
use signature::Keypair;

// implements the Keypair trait for PrivateKey
impl<Mode: LmsMode> Keypair for PrivateKey<Mode> {
    type VerifyingKey = PublicKey<Mode>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.public()
    }
}
