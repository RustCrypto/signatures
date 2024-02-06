use crate::ots::util::coefs;
use crate::types::Typecode;
use digest::{Digest, Output};
use generic_array::{ArrayLength, GenericArray};
use sha2::Sha256;
use static_assertions::const_assert_eq;
use std::marker::PhantomData;
use typenum::consts::{U133, U265, U34, U67};
use typenum::Unsigned;

/// The basic trait that must be implemented by any OTS mode.
pub trait LmsOtsMode: Typecode {
    /// The underlying hash function
    type Hasher: Digest;
    /// The length of the hash function output as a type
    type NLen: ArrayLength<u8>;
    /// The value of P as a type
    type PLen: ArrayLength<Output<Self::Hasher>> + ArrayLength<u8>;
    /// The length of the hash function output as a [usize]
    const N: usize;
    /// The Winternitz window, which should be a value that divides 8
    const W: usize;
    /// The number of `W` bit fields required to contain the hash of the message
    const U: usize; // internal value calculated as https://datatracker.ietf.org/doc/html/rfc8554#appendix-B
    /// The number of `W` bit fields required to contain the checksum
    const V: usize; // see above
    /// Computed as `U` + `V`
    const P: usize;
    /// The left shift required to get the checksum bits
    const LS: usize;
    /// The total length of the signature
    const SIG_LEN: usize;

    /// Expands a message into its Winternitz coefficients and checksum
    fn expand(message: &Output<Self::Hasher>) -> GenericArray<u8, Self::PLen> {
        // Returns an array containing Coefs(message, w, U) || Coefs(checksum, w, V)
        // where Coefs(M, w, L) is an array containing coef(M, i, w) for each i in 0..L
        // See RFC 8554 section 3.1.3.

        // Expand the message into its coefficients
        // Immediately allocates full expanded length, but only the first U coefficients are used
        // in this step
        let mut arr: GenericArray<u8, <Self as LmsOtsMode>::PLen> = GenericArray::default();
        for (i, c) in coefs(message, Self::W).enumerate().take(Self::U) {
            arr[i] = c;
        }

        // Compute the checksum as described in RFC 8554 section 4.4
        // The checksum is the sum of all "negated" chunks
        // This means that if every chunk of message `a` is <= each corresponding chunk of message ``b``,
        // then the checksum of `a` is greater than the checksum of `b`

        // The negation is done by subtracting the chunk value from 2^W - 1
        let cksum = (&arr)
            .into_iter()
            .take(Self::U)
            .map(|&x| ((1u16 << Self::W) - 1 - (x as u16)))
            .sum::<u16>()
            << Self::LS;

        // The checksum itself in then expanded into its coefficients and appended to the message coefficients
        let cksum_bytes = cksum.to_be_bytes();
        let cksum_chunks = coefs(&cksum_bytes, Self::W).take(Self::V);

        for (i, c) in cksum_chunks.enumerate() {
            arr[Self::U + i] = c;
        }
        arr
    }
}

#[derive(Debug)]
pub struct LmsOtsModeInternal<
    Hasher: Digest,
    const W: usize,
    PP: ArrayLength<GenericArray<u8, Hasher::OutputSize>> + ArrayLength<u8>,
    const TC: u32,
> {
    _phantomdata: PhantomData<(Hasher, PP)>,
}

impl<
        Hasher: Digest,
        const W: usize,
        PP: ArrayLength<GenericArray<u8, Hasher::OutputSize>> + ArrayLength<u8>,
        const TC: u32,
    > Typecode for LmsOtsModeInternal<Hasher, W, PP, TC>
{
    const TYPECODE: u32 = TC;
}

/// because trait associated consts cannot be used as generic values, we work around this by passing in an additional
/// type representing the array length P used for private keys, which gets checked via some static asserts
///
/// NLen and N are calculated using the associated OutputSize of the given Digest, as specified by
/// https://datatracker.ietf.org/doc/html/rfc8554#section-4.1
impl<
        Hasher: Digest,
        const W: usize,
        PP: ArrayLength<GenericArray<u8, Hasher::OutputSize>> + ArrayLength<u8>,
        const TC: u32,
    > LmsOtsMode for LmsOtsModeInternal<Hasher, W, PP, TC>
{
    type Hasher = Hasher;
    type NLen = Hasher::OutputSize;
    type PLen = PP;
    const N: usize = Hasher::OutputSize::USIZE;
    const W: usize = W;
    const U: usize = (8 * Self::N + W - 1) / W;
    const V: usize = ((((1 << W) - 1) * Self::U).ilog2() as usize / W) + 1;
    const P: usize = Self::U + Self::V;
    const LS: usize = 16 - Self::V * W;
    const SIG_LEN: usize = 4 + Self::N * (Self::P + 1);
}

/// `LMOTS_SHA256_N32_W1`
pub type LmsOtsSha256N32W1 = LmsOtsModeInternal<Sha256, 1, U265, 1>;
/// `LMOTS_SHA256_N32_W2`
pub type LmsOtsSha256N32W2 = LmsOtsModeInternal<Sha256, 2, U133, 2>;
/// `LMOTS_SHA256_N32_W4`
pub type LmsOtsSha256N32W4 = LmsOtsModeInternal<Sha256, 4, U67, 3>;
/// `LMOTS_SHA256_N32_W8`
pub type LmsOtsSha256N32W8 = LmsOtsModeInternal<Sha256, 8, U34, 4>;

// make sure that the auto generated N, P, LS, SIG_LEN values are correct
const_assert_eq!(
    <LmsOtsSha256N32W1 as LmsOtsMode>::NLen::USIZE,
    LmsOtsSha256N32W1::N
);
const_assert_eq!(
    <LmsOtsSha256N32W1 as LmsOtsMode>::PLen::USIZE,
    LmsOtsSha256N32W1::P
);
const_assert_eq!(LmsOtsSha256N32W1::N, 32);
const_assert_eq!(LmsOtsSha256N32W1::P, 265);
const_assert_eq!(LmsOtsSha256N32W1::LS, 7);
const_assert_eq!(LmsOtsSha256N32W1::SIG_LEN, 8516);

const_assert_eq!(
    <LmsOtsSha256N32W2 as LmsOtsMode>::NLen::USIZE,
    LmsOtsSha256N32W2::N
);
const_assert_eq!(
    <LmsOtsSha256N32W2 as LmsOtsMode>::PLen::USIZE,
    LmsOtsSha256N32W2::P
);
const_assert_eq!(LmsOtsSha256N32W2::N, 32);
const_assert_eq!(LmsOtsSha256N32W2::P, 133);
const_assert_eq!(LmsOtsSha256N32W2::LS, 6);
const_assert_eq!(LmsOtsSha256N32W2::SIG_LEN, 4292);

const_assert_eq!(
    <LmsOtsSha256N32W4 as LmsOtsMode>::NLen::USIZE,
    LmsOtsSha256N32W4::N
);
const_assert_eq!(
    <LmsOtsSha256N32W4 as LmsOtsMode>::PLen::USIZE,
    LmsOtsSha256N32W4::P
);
const_assert_eq!(LmsOtsSha256N32W4::N, 32);
const_assert_eq!(LmsOtsSha256N32W4::P, 67);
const_assert_eq!(LmsOtsSha256N32W4::LS, 4);
const_assert_eq!(LmsOtsSha256N32W4::SIG_LEN, 2180);

const_assert_eq!(
    <LmsOtsSha256N32W8 as LmsOtsMode>::NLen::USIZE,
    LmsOtsSha256N32W8::N
);
const_assert_eq!(
    <LmsOtsSha256N32W8 as LmsOtsMode>::PLen::USIZE,
    LmsOtsSha256N32W8::P
);
const_assert_eq!(LmsOtsSha256N32W8::N, 32);
const_assert_eq!(LmsOtsSha256N32W8::P, 34);
const_assert_eq!(LmsOtsSha256N32W8::LS, 0);
const_assert_eq!(LmsOtsSha256N32W8::SIG_LEN, 1124);

#[cfg(test)]
mod test {
    use generic_array::GenericArray;

    use super::LmsOtsMode;
    #[test]
    fn test_checksum_zero_w1() {
        let arr = [0u8; super::LmsOtsSha256N32W1::N];
        let cksm = super::LmsOtsSha256N32W1::expand(GenericArray::from_slice(&arr));
        assert_eq!(
            &cksm[super::LmsOtsSha256N32W1::U..],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_checksum_ones_w1() {
        let arr = [255u8; super::LmsOtsSha256N32W1::N];
        let cksm = super::LmsOtsSha256N32W1::expand(GenericArray::from_slice(&arr));
        assert_eq!(
            &cksm[super::LmsOtsSha256N32W1::U..],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_checksum_ten_w4() {
        let arr = [0xaa; super::LmsOtsSha256N32W4::N];
        let cksm = super::LmsOtsSha256N32W4::expand(GenericArray::from_slice(&arr));
        assert_eq!(&cksm[super::LmsOtsSha256N32W4::U..], &[0x01, 0x04, 0x00]);
    }

    #[test]
    fn test_expand_zero_w8() {
        let arr = [0u8; super::LmsOtsSha256N32W8::N];
        let expanded = super::LmsOtsSha256N32W8::expand(GenericArray::from_slice(&arr));
        let mut expected = [0u8; super::LmsOtsSha256N32W8::P];
        expected[super::LmsOtsSha256N32W8::U] = 0x1f;
        expected[super::LmsOtsSha256N32W8::U + 1] = 0xe0;
        assert_eq!(&expanded.as_slice(), &expected);
    }
}
