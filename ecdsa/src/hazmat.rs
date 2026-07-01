//! Low-level ECDSA primitives.
//!
//! <div class="warning">
//! <b>Security️ Warning: Hazardous Materials!</b>
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces.
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures including
//! FULL PRIVATE KEY RECOVERY!
//! </div>

use crate::{EcdsaCurve, Error, RecoveryId, Result, Signature};
use elliptic_curve::{
    CurveArithmetic, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
    bigint::{BitOps, Encoding},
    ff::PrimeField,
    group::{Curve as _, Group},
    ops::{Invert, MulByGeneratorVartime, Reduce},
    point::AffineCoordinates,
    scalar::IsHigh,
};

#[cfg(feature = "digest")]
use digest::{Digest, block_api::BlockSizeUser};

/// Sign a prehashed message digest using the provided secret scalar and
/// ephemeral scalar, returning an ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `d`: signing key. MUST BE UNIFORMLY RANDOM!!!
/// - `k`: ephemeral scalar value. MUST BE UNIFORMLY RANDOM!!!
/// - `z`: message digest to be signed. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY
///   SECURE DIGEST ALGORITHM!!!
///
/// # Low-S Normalization
///
/// This function will apply low-S normalization if `<C as EcdsaCurve>::NORMALIZE_S` is true.
///
/// # Returns
///
/// ECDSA [`Signature`] and a [`RecoveryId`] which can be used to recover the verifying key for a
/// given signature.
///
/// # Errors
///
/// This will return an error if a zero-scalar was generated. It can be tried again with a
/// different `k`.
#[allow(non_snake_case)]
pub fn sign_prehashed<C>(
    d: &NonZeroScalar<C>,
    k: &NonZeroScalar<C>,
    z: &[u8],
) -> Result<(Signature<C>, RecoveryId)>
where
    C: EcdsaCurve + CurveArithmetic,
{
    let z = bytes2scalar::<C>(z);

    // Compute scalar inversion of 𝑘.
    let k_inv = k.invert();

    // Compute 𝑹 = 𝑘×𝑮.
    let R = ProjectivePoint::<C>::mul_by_generator(k).to_affine();

    // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
    // integer, then reduce it into an element of the scalar field.
    let r = bytes2scalar::<C>(&R.x());

    // Compute 𝒔 as a signature over 𝒓 and 𝒛.
    let s = *k_inv * (z + (r * d.as_ref()));

    // NOTE: `Signature::from_scalars` checks that both `r` and `s` are non-zero.
    let mut signature = Signature::from_scalars(r, s)?;

    // Compute recovery ID.
    let x_is_reduced = r.to_repr() != R.x();
    let y_is_odd = R.y_is_odd();
    let mut recovery_id = RecoveryId::new(y_is_odd.into(), x_is_reduced);

    // Apply low-S normalization if the curve is configured for it
    if C::NORMALIZE_S {
        recovery_id.0 ^= s.is_high().unwrap_u8();
        signature = signature.normalize_s();
    }

    Ok((signature, recovery_id))
}

/// Try to sign the given message digest deterministically using the method
/// described in [RFC6979] for computing ECDSA ephemeral scalar `k`.
///
/// Accepts the following parameters:
/// - `d`: signing key. MUST BE UNIFORMLY RANDOM!!!
/// - `z`: message digest to be signed, i.e. `H(m)`. Does not have to be reduced in advance.
/// - `ad`: optional additional data, e.g. added entropy from an RNG
///
/// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
pub fn sign_prehashed_rfc6979<C, D>(
    d: &NonZeroScalar<C>,
    z: &[u8],
    ad: &[u8],
) -> (Signature<C>, RecoveryId)
where
    C: EcdsaCurve + CurveArithmetic,
    D: Digest + BlockSizeUser,
{
    let order = C::ORDER;
    let mut kgen = rfc6979::KGenerator::<D, C::Uint>::new(&d.to_repr(), z, ad, &order);

    loop {
        let mut k_bytes = FieldBytes::<C>::default();
        kgen.fill_next_k(&mut k_bytes);

        if let Some(k) = NonZeroScalar::<C>::from_repr(k_bytes).into_option() {
            if let Ok(ret) = sign_prehashed(d, &k, z) {
                return ret;
            }
        }
    }
}

/// Verify the prehashed message against the provided ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `q`: public key with which to verify the signature.
/// - `z`: message digest to be verified. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY SECURE DIGEST
///   ALGORITHM!!!
/// - `sig`: signature to be verified against the key and message.
pub fn verify_prehashed<C>(q: &ProjectivePoint<C>, z: &[u8], sig: &Signature<C>) -> Result<()>
where
    C: EcdsaCurve + CurveArithmetic,
{
    if C::NORMALIZE_S && sig.s().is_high().into() {
        return Err(Error::new());
    }

    let z = bytes2scalar::<C>(z);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let x = ProjectivePoint::<C>::mul_by_generator_and_mul_add_vartime(&u1, &u2, q)
        .to_affine()
        .x();

    if *r == bytes2scalar::<C>(&x) {
        Ok(())
    } else {
        Err(Error::new())
    }
}

/// Convert the provided bytestring into a `Scalar` for the given curve, interpreting it as big
/// endian, zero-padding or truncating it to the bit length of `n` (curve order) if necessary,
/// and then reducing it mod `n`.
pub(crate) fn bytes2scalar<C: EcdsaCurve + CurveArithmetic>(mut bytes: &[u8]) -> Scalar<C> {
    // Compute number of bytes in `n` (curve order)
    let n_bits = C::ORDER.bits();
    let n_bytes = n_bits.div_ceil(8) as usize;
    if bytes.len() > n_bytes {
        bytes = &bytes[..n_bytes];
    }

    <Scalar<C> as Reduce<C::Uint>>::reduce(&C::Uint::from_be_slice_truncated(bytes, n_bits))
}
