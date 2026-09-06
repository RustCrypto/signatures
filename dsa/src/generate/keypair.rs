#![cfg(feature = "hazmat")]
//!
//! Generate a DSA keypair
//!

use crate::{Components, VerifyingKey, generate::components, signing_key::SigningKey};
use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use signature::rand_core::TryCryptoRng;

/// Generate a new signing keypair.
#[inline]
pub(crate) fn signing_keypair<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    components: Components,
) -> Result<SigningKey, R::Error> {
    #[inline]
    fn find_non_zero_x<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
        components: &Components,
    ) -> Result<NonZero<BoxedUint>, R::Error> {
        loop {
            let x = BoxedUint::try_random_mod_vartime(rng, components.q())?;
            if let Some(x) = NonZero::new(x).into() {
                return Ok(x);
            }
        }
    }

    #[inline]
    fn find_components<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
        components: &Components,
    ) -> Result<(NonZero<BoxedUint>, NonZero<BoxedUint>), R::Error> {
        loop {
            let x = find_non_zero_x(rng, components)?;

            if let Some(y) = components::public(components, &x).into_option() {
                return Ok((x, y));
            }
        }
    }

    let (x, y) = find_components(rng, &components)?;

    Ok(VerifyingKey::from_components(components, y.get())
        .and_then(|verifying_key| SigningKey::from_components(verifying_key, x.get()))
        .expect("[Bug] Newly generated keypair considered invalid"))
}
