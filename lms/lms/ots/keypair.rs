use crate::ots::modes::LmsOtsMode;
use crate::ots::private::PrivateKey;
use crate::ots::public::PublicKey;
use signature::Keypair;

// implements the Keypair trait for PrivateKey
impl<Mode: LmsOtsMode> Keypair for PrivateKey<Mode> {
    type VerifyingKey = PublicKey<Mode>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.public()
    }
}
