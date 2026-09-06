//!
//! Generate a per-message secret number
//!

use crate::{Components, signing_key::SigningKey};
use alloc::vec;
use core::cmp::min;
use crypto_bigint::{BoxedUint, NonZero, NonZeroBoxedUint, RandomBits, Resize};
use digest::{Digest, common::BlockSizeUser};
use signature::rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// Generate a per-message secret number k deterministically using the method described in RFC 6979
///
/// # Returns
///
/// Secret number k and its modular multiplicative inverse with q
#[inline]
pub(crate) fn secret_number_rfc6979<D>(
    signing_key: &SigningKey,
    hash: &[u8],
) -> (BoxedUint, BoxedUint)
where
    D: BlockSizeUser + Digest,
{
    let q = signing_key.verifying_key().components().q();
    let mut kgen = init_kgen::<D>(signing_key.x(), hash, q);
    let mut buffer = vec![0; qlen(q)];

    loop {
        kgen.fill_next_k(&mut buffer);
        let k = bytes2uint(&buffer, q);
        if let Some(inv_k) = k.invert_mod(q).into() {
            if bool::from(k.is_nonzero()) && k < **q {
                return (k, inv_k);
            }
        }
    }
}

/// Initialize `KGenerator` from a `hash`, `q`, and the
fn init_kgen<'a, D: BlockSizeUser + Digest>(
    x: &NonZeroBoxedUint,
    z: &[u8],
    q: &'a NonZeroBoxedUint,
) -> rfc6979::KGenerator<'a, D, BoxedUint> {
    // Truncate to the right `size` most bytes
    fn truncate(b: &[u8], size: usize) -> &[u8] {
        &b[(b.len() - size)..]
    }

    // Truncate hash and reduce mod q
    let size = qlen(q);
    let z = bytes2uint(&z[..min(size, z.len())], q);
    let z = (z % q).to_be_bytes();
    let z = truncate(&z, size);

    let x = Zeroizing::new(x.to_be_bytes());
    let x = truncate(&x, size);

    rfc6979::KGenerator::<D, BoxedUint>::new(x, z, &[], q)
}

fn bytes2uint(b: &[u8], q: &NonZeroBoxedUint) -> BoxedUint {
    BoxedUint::from_be_slice_truncated(b, q.bits_precision())
}

#[allow(clippy::as_conversions)]
fn qlen(q: &NonZeroBoxedUint) -> usize {
    q.bits().div_ceil(8) as usize
}

/// Generate a per-message secret number k according to Appendix B.2.1
///
/// # Returns
///
/// Secret number k and its modular multiplicative inverse with q
#[inline]
pub(crate) fn secret_number<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    components: &Components,
) -> Result<Option<(BoxedUint, BoxedUint)>, signature::Error> {
    let q = components.q();
    let n = q.bits();
    let q = q.resize(n + 64);
    let q = &q;

    // Attempt to try a fitting secret number
    // Give up after 4096 tries
    for _ in 0..4096 {
        let c = BoxedUint::try_random_bits(rng, n + 64).map_err(|_| signature::Error::new())?;
        let rem = NonZero::new((&**q - &BoxedUint::one()).resize(c.bits_precision()))
            .expect("[bug] minimum size for q is to 2^(160 - 1)");
        let k = (c % rem) + BoxedUint::one();

        if let Some(inv_k) = k.invert_mod(q).into() {
            // `k` and `k^-1` both have to be in the range `[1, q-1]`
            if (inv_k > BoxedUint::zero() && inv_k < **q) && (k > BoxedUint::zero() && k < **q) {
                return Ok(Some((k, inv_k)));
            }
        }
    }

    Ok(None)
}
