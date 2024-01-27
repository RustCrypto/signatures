use crate::two;
use crypto_bigint::BoxedUint;
use signature::rand_core::CryptoRngCore;

mod components;
mod keypair;
mod secret_number;

pub use self::components::{common as common_components, public as public_component};
pub use self::secret_number::{secret_number, secret_number_rfc6979};

#[cfg(feature = "hazmat")]
pub use self::keypair::keypair;

/// Calculate the upper and lower bounds for generating values like p or q
#[inline]
fn calculate_bounds(size: u32) -> (BoxedUint, BoxedUint) {
    let lower = two().shl(size - 1);
    let upper = two().shl(size);

    (lower, upper)
}

/// Generate a prime number using a cryptographically secure pseudo-random number generator
///
/// This wrapper function mainly exists to enforce the [`CryptoRng`](rand::CryptoRng) requirement (I might otherwise forget it)
#[inline]
fn generate_prime(bit_length: u32, rng: &mut impl CryptoRngCore) -> BoxedUint {
    crypto_primes::generate_prime_with_rng(rng, bit_length)
}
