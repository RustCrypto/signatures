//! Support for computing deterministic ECDSA ephemeral scalar (`k`) using
//! the method described in RFC 6979 rules (Section 3.2):
//! <https://tools.ietf.org/html/rfc6979#section-3>

use elliptic_curve::{
    digest::{BlockInput, FixedOutput, Reset, Update},
    generic_array::GenericArray,
    ops::Invert,
    scalar::NonZeroScalar,
    zeroize::{Zeroize, Zeroizing},
    Arithmetic, ElementBytes, FromBytes, FromDigest,
};
use hmac::{Hmac, Mac, NewMac};

/// Generate ephemeral scalar `k` from the secret scalar and a digest of the
/// input message.
pub(super) fn generate_k<C, D>(
    secret_scalar: &NonZeroScalar<C>,
    msg_digest: D,
    additional_data: &[u8],
) -> Zeroizing<NonZeroScalar<C>>
where
    C: Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + Zeroize,
    D: BlockInput<BlockSize = C::ElementSize>
        + FixedOutput<OutputSize = C::ElementSize>
        + Clone
        + Default
        + Reset
        + Update,
    ElementBytes<C>: Zeroize,
{
    let x = Zeroizing::new(secret_scalar.to_bytes());
    let h1: ElementBytes<C> = C::Scalar::from_digest(msg_digest).into();
    let mut hmac_drbg = HmacDrbg::<D>::new(&*x, &h1, additional_data);

    loop {
        let k = NonZeroScalar::from_bytes(&hmac_drbg.next());

        if k.is_some().into() {
            return Zeroizing::new(k.unwrap());
        }
    }
}

/// Internal implementation of `HMAC_DRBG` as described in NIST SP800-90A:
/// <https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final>
///
/// This is a HMAC-based deterministic random bit generator used internally
/// to compute a deterministic ECDSA ephemeral scalar `k`.
// TODO(tarcieri): use `hmac-drbg` crate when sorpaas/rust-hmac-drbg#3 is merged
struct HmacDrbg<D>
where
    D: BlockInput<BlockSize = <D as FixedOutput>::OutputSize>
        + FixedOutput
        + Clone
        + Default
        + Reset
        + Update,
{
    /// HMAC key `K` (see RFC 6979 Section 3.2.c)
    k: Hmac<D>,

    /// Chaining value `V` (see RFC 6979 Section 3.2.c)
    v: GenericArray<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: BlockInput<BlockSize = <D as FixedOutput>::OutputSize>
        + FixedOutput
        + Clone
        + Default
        + Reset
        + Update,
{
    /// Initialize `HMAC_DRBG`
    pub fn new(entropy_input: &[u8], nonce: &[u8], additional_data: &[u8]) -> Self {
        let mut k = Hmac::new(&Default::default());
        let mut v = GenericArray::default();

        for b in &mut v {
            *b = 0x01;
        }

        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(entropy_input);
            k.update(nonce);
            k.update(additional_data);
            k = Hmac::new(&k.finalize().into_bytes());

            // Steps 3.2.e,g: v = HMAC_k(v)
            k.update(&v);
            v = k.finalize_reset().into_bytes();
        }

        Self { k, v }
    }

    /// Get the next `HMAC_DRBG` output
    pub fn next(&mut self) -> GenericArray<u8, D::OutputSize> {
        self.k.update(&self.v);
        let t = self.k.finalize_reset().into_bytes();

        self.k.update(&t);
        self.k.update(&[0x00]);
        self.k = Hmac::new(&self.k.finalize_reset().into_bytes());
        self.k.update(&t);
        self.v = self.k.finalize_reset().into_bytes();

        t
    }
}
