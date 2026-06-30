//!
//! Generate a per-message secret number
//!

use crate::{Components, signing_key::SigningKey};
use alloc::vec;
use core::cmp::min;
use crypto_bigint::{BoxedUint, NonZero, RandomBits, Resize};
use digest::{Digest, common::BlockSizeUser};
use signature::rand_core::TryCryptoRng;
use zeroize::Zeroizing;

fn truncate_hash(hash: &[u8], desired_size: usize) -> &[u8] {
    &hash[(hash.len() - desired_size)..]
}

/// Generate a per-message secret number k deterministically using the method described in RFC 6979
///
/// # Returns
///
/// Secret number k and its modular multiplicative inverse with q
#[inline]
pub(crate) fn secret_number_rfc6979<D>(
    signing_key: &SigningKey,
    hash: &[u8],
) -> Result<(BoxedUint, BoxedUint), signature::Error>
where
    D: BlockSizeUser + Digest,
{
    let q = signing_key.verifying_key().components().q();
    let size = (q.bits() / 8) as usize;

    // Truncate hash and reduce mod q
    // TODO(tarcieri): `rfc6979` now truncates and reduces mod q. some of this may be redundant?
    let hash = BoxedUint::from_be_slice(&hash[..min(size, hash.len())], q.bits_precision())
        .map_err(|_| signature::Error::new())?;
    let hash = (hash % q).to_be_bytes();
    let hash = truncate_hash(&hash, size);

    let x_bytes = Zeroizing::new(signing_key.x().to_be_bytes());
    let x_bytes = truncate_hash(&x_bytes, size);

    let mut kgen = rfc6979::KGenerator::<D, BoxedUint>::new(x_bytes, hash, &[], q);

    let mut buffer = vec![0; size];
    loop {
        kgen.fill_next_k(&mut buffer);

        let k = BoxedUint::from_be_slice(&buffer, q.bits_precision())
            .map_err(|_| signature::Error::new())?;
        if let Some(inv_k) = k.invert_mod(q).into() {
            if (bool::from(k.is_nonzero())) && (k < **q) {
                return Ok((k, inv_k));
            }
        }
    }
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
