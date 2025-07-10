use crypto_bigint::{BoxedUint, NonZero, Resize};
use crypto_primes::{Flavor, random_prime};
use signature::rand_core::CryptoRng;

mod components;
mod keypair;
#[cfg(feature = "hazmat")]
mod secret_number;

pub use self::components::common as common_components;
#[cfg(feature = "hazmat")]
pub use self::secret_number::{secret_number, secret_number_rfc6979};

#[cfg(feature = "hazmat")]
pub use self::keypair::keypair;

#[cfg(all(feature = "hazmat", feature = "pkcs8"))]
pub use self::components::public as public_component;

/// Calculate the upper and lower bounds for generating values like p or q
#[inline]
fn calculate_bounds(size: u32) -> (NonZero<BoxedUint>, NonZero<BoxedUint>) {
    let lower = BoxedUint::one().resize(size + 1).shl(size - 1);
    let upper = BoxedUint::one().resize(size + 1).shl(size);

    let lower = NonZero::new(lower).expect("[bug] shl can't go backward");
    let upper = NonZero::new(upper).expect("[bug] shl can't go backward");

    (lower, upper)
}

/// Generate a prime number using a cryptographically secure pseudo-random number generator
///
/// This wrapper function mainly exists to enforce the [`CryptoRng`](rand::CryptoRng) requirement (I might otherwise forget it)
#[inline]
fn generate_prime<R: CryptoRng + ?Sized>(bit_length: u32, rng: &mut R) -> BoxedUint {
    random_prime(rng, Flavor::Any, bit_length)
}
