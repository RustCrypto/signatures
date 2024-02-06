use crate::ots::modes::LmsOtsMode;
use crate::ots::private::SigningKey;
use crate::ots::public::VerifyingKey;
use signature::Keypair;

// implements the Keypair trait for PrivateKey
impl<Mode: LmsOtsMode> Keypair for SigningKey<Mode> {
    type VerifyingKey = VerifyingKey<Mode>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.public()
    }
}
