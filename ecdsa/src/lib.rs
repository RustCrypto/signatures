//! Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! [FIPS 186-4][1] (Digital Signature Standard)
//!
//! ## About
//!
//! This crate provides generic ECDSA support which can be used in the
//! following ways:
//!
//! - Generic implementation of ECDSA usable with the following crates:
//!   - [`k256`] (secp256k1)
//!   - [`p256`] (NIST P-256)
//! - ECDSA signature types alone which can be used to provide interoperability
//!   between other crates that provide an ECDSA implementation:
//!   - [`p384`] (NIST P-384)
//! - Other crates which provide their own complete implementations of ECDSA can
//!   also leverage the types from this crate to export ECDSA functionality in a
//!   generic, interoperable way by leveraging the [`Signature`] type with the
//!   [`signature::Signer`] and [`signature::Verifier`] traits.
//!
//! [1]: https://csrc.nist.gov/publications/detail/fips/186/4/final
//! [`k256`]: https://docs.rs/k256
//! [`p256`]: https://docs.rs/p256
//! [`p384`]: https://docs.rs/p384

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/ecdsa/0.8.5"
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod asn1;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "hazmat")]
#[cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]
pub mod hazmat;

#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub mod rfc6979;

#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub mod sign;

#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
pub mod verify;

// Re-export the `elliptic-curve` crate (and select types)
pub use elliptic_curve::{self, generic_array, sec1::EncodedPoint, weierstrass::Curve};

// Re-export the `signature` crate (and select types)
pub use signature::{self, Error};

#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub use sign::SigningKey;

#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
pub use verify::VerifyKey;

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub use elliptic_curve::SecretKey;

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::Add,
};
use elliptic_curve::FieldBytes;
use generic_array::{sequence::Concat, typenum::Unsigned, ArrayLength, GenericArray};

#[cfg(feature = "arithmetic")]
use elliptic_curve::{
    ff::PrimeField,
    scalar::{NonZeroScalar, Scalar},
    ProjectiveArithmetic,
};

/// Size of a fixed sized signature for the given elliptic curve.
pub type SignatureSize<C> = <<C as elliptic_curve::Curve>::FieldSize as Add>::Output;

/// Fixed-size byte array containing an ECDSA signature
pub type SignatureBytes<C> = GenericArray<u8, SignatureSize<C>>;

/// ECDSA signatures (fixed-size).
///
/// Generic over elliptic curve types.
///
/// These signatures are serialized as fixed-sized big endian scalar values
/// with no additional framing:
///
/// - `r`: field element size for the given curve, big-endian
/// - `s`: field element size for the given curve, big-endian
///
/// For example, in a curve with a 256-bit modulus like NIST P-256 or
/// secp256k1, `r` and `s` will both be 32-bytes, resulting in a signature
/// with a total of 64-bytes.
///
/// ASN.1 is also supported via the [`Signature::from_asn1`] and
/// [`Signature::to_asn1`] methods.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature<C: Curve + CheckSignatureBytes>
where
    SignatureSize<C>: ArrayLength<u8>,
{
    bytes: SignatureBytes<C>,
}

impl<C> Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Create a [`Signature`] from the serialized `r` and `s` scalar values
    /// which comprise the signature.
    pub fn from_scalars(
        r: impl Into<FieldBytes<C>>,
        s: impl Into<FieldBytes<C>>,
    ) -> Result<Self, Error> {
        Self::try_from(r.into().concat(s.into()).as_slice())
    }

    /// Parse a signature from ASN.1 DER
    pub fn from_asn1(bytes: &[u8]) -> Result<Self, Error>
    where
        C::FieldSize: Add + ArrayLength<u8>,
        asn1::MaxSize<C>: ArrayLength<u8>,
        <C::FieldSize as Add>::Output: Add<asn1::MaxOverhead> + ArrayLength<u8>,
    {
        asn1::Signature::<C>::try_from(bytes).and_then(TryInto::try_into)
    }

    /// Serialize this signature as ASN.1 DER
    pub fn to_asn1(&self) -> asn1::Signature<C>
    where
        C::FieldSize: Add + ArrayLength<u8>,
        asn1::MaxSize<C>: ArrayLength<u8>,
        <C::FieldSize as Add>::Output: Add<asn1::MaxOverhead> + ArrayLength<u8>,
    {
        let (r, s) = self.bytes.split_at(C::FieldSize::to_usize());
        asn1::Signature::from_scalar_bytes(r, s)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> Signature<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    <Scalar<C> as PrimeField>::Repr: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Get the `r` component of this signature
    pub fn r(&self) -> NonZeroScalar<C> {
        let r_bytes = GenericArray::clone_from_slice(&self.bytes[..C::FieldSize::to_usize()]);
        NonZeroScalar::from_repr(r_bytes)
            .unwrap_or_else(|| unreachable!("r-component ensured valid in constructor"))
    }

    /// Get the `s` component of this signature
    pub fn s(&self) -> NonZeroScalar<C> {
        let s_bytes = GenericArray::clone_from_slice(&self.bytes[C::FieldSize::to_usize()..]);
        NonZeroScalar::from_repr(s_bytes)
            .unwrap_or_else(|| unreachable!("r-component ensured valid in constructor"))
    }

    /// Normalize signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    pub fn normalize_s(&mut self) -> Result<bool, Error>
    where
        Scalar<C>: NormalizeLow,
    {
        let s_bytes = GenericArray::from_mut_slice(&mut self.bytes[C::FieldSize::to_usize()..]);
        Scalar::<C>::from_repr(s_bytes.clone())
            .map(|s| {
                let (s_low, was_high) = s.normalize_low();

                if was_high {
                    s_bytes.copy_from_slice(&s_low.to_repr());
                }

                was_high
            })
            .ok_or_else(Error::new)
    }
}

impl<C> signature::Signature for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes)
    }
}

impl<C> AsRef<[u8]> for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<C> Copy for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
    <SignatureSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Debug for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ecdsa::Signature<{:?}>({:?})",
            C::default(),
            self.as_ref()
        )
    }
}

impl<C> TryFrom<&[u8]> for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != <SignatureSize<C>>::to_usize() {
            return Err(Error::new());
        }

        let bytes = GenericArray::clone_from_slice(bytes);
        C::check_signature_bytes(&bytes)?;

        Ok(Self { bytes })
    }
}

impl<C> TryFrom<asn1::Signature<C>> for Signature<C>
where
    C: Curve + CheckSignatureBytes,
    C::FieldSize: Add + ArrayLength<u8>,
    asn1::MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<asn1::MaxOverhead> + ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(doc: asn1::Signature<C>) -> Result<Signature<C>, Error> {
        let mut bytes = GenericArray::default();
        let scalar_size = C::FieldSize::to_usize();
        let r_begin = scalar_size.checked_sub(doc.r().len()).unwrap();
        let s_begin = bytes.len().checked_sub(doc.s().len()).unwrap();

        bytes[r_begin..scalar_size].copy_from_slice(doc.r());
        bytes[s_begin..].copy_from_slice(doc.s());

        C::check_signature_bytes(&bytes)?;
        Ok(Signature { bytes })
    }
}

/// Ensure a signature is well-formed.
pub trait CheckSignatureBytes: Curve
where
    SignatureSize<Self>: ArrayLength<u8>,
{
    /// Validate that the given signature is well-formed.
    ///
    /// This trait is auto-impl'd for curves which impl the
    /// `elliptic_curve::ProjectiveArithmetic` trait, which validates that the
    /// `r` and `s` components of the signature are in range of the
    /// scalar field.
    ///
    /// Note that this trait is not for verifying a signature, but allows for
    /// asserting properties of it which allow infallible conversions
    /// (e.g. accessors for the `r` and `s` components)
    fn check_signature_bytes(bytes: &SignatureBytes<Self>) -> Result<(), Error> {
        // Ensure `r` and `s` are both non-zero
        // TODO(tarcieri): check that `r` and `s` are in range of the curve's order
        for scalar_bytes in bytes.chunks(Self::FieldSize::to_usize()) {
            if scalar_bytes.iter().all(|&b| b == 0) {
                return Err(Error::new());
            }
        }

        Ok(())
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> CheckSignatureBytes for C
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// When curve arithmetic is available, check that the scalar components
    /// of the signature are in range.
    fn check_signature_bytes(bytes: &SignatureBytes<C>) -> Result<(), Error> {
        let (r, s) = bytes.split_at(C::FieldSize::to_usize());
        let r_ok = NonZeroScalar::<C>::from_repr(GenericArray::clone_from_slice(r)).is_some();
        let s_ok = NonZeroScalar::<C>::from_repr(GenericArray::clone_from_slice(s)).is_some();

        if r_ok && s_ok {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

/// Normalize a scalar (i.e. ECDSA S) to the lower half the field, as described
/// in [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub trait NormalizeLow: Sized {
    /// Normalize scalar to the lower half of the field (i.e. negate it if it's
    /// larger than half the curve's order).
    /// Returns a tuple with the new scalar and a boolean indicating whether the given scalar
    /// was in the higher half.
    ///
    /// May be implemented to work in variable time.
    fn normalize_low(&self) -> (Self, bool);
}
