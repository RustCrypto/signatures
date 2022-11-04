use crate::two;
use num_bigint::{BigUint, RandPrime};
use num_traits::Pow;
use signature::rand_core::CryptoRngCore;

mod components;
mod keypair;
mod secret_number;

pub use self::components::{common as common_components, public as public_component};
pub use self::keypair::keypair;
pub use self::secret_number::{secret_number, secret_number_rfc6979};

/// Calculate the upper and lower bounds for generating values like p or q
#[inline]
fn calculate_bounds(size: u32) -> (BigUint, BigUint) {
    let lower = two().pow(size - 1);
    let upper = two().pow(size);

    (lower, upper)
}

/// Generate a prime number using a cryptographically secure pseudo-random number generator
///
/// This wrapper function mainly exists to enforce the [`CryptoRng`](rand::CryptoRng) requirement (I might otherwise forget it)
#[inline]
fn generate_prime(bit_length: usize, rng: &mut impl CryptoRngCore) -> BigUint {
    rng.gen_prime(bit_length)
}
