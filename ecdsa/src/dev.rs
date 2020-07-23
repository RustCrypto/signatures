//! Development-related functionality

// TODO(tarcieri): implement full set of tests from ECDSA2VS
// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss2/ecdsa2vs.pdf>

/// ECDSA test vector
pub struct TestVector {
    /// Private scalar
    pub d: &'static [u8],

    /// Public key x-coordinate (`Qx`)
    pub q_x: &'static [u8],

    /// Public key y-coordinate (`Qy`)
    pub q_y: &'static [u8],

    /// Ephemeral scalar (a.k.a. nonce)
    pub k: &'static [u8],

    /// Message digest (prehashed)
    pub m: &'static [u8],

    /// Signature `r` component
    pub r: &'static [u8],

    /// Signature `s` component
    pub s: &'static [u8],
}

/// Define ECDSA signing test
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_signing_test {
    ($vectors:expr) => {
        use core::convert::TryInto;
        use $crate::{elliptic_curve::weierstrass::UncompressedPoint, generic_array::GenericArray};

        #[test]
        fn ecdsa_signing() {
            for vector in $vectors {
                let d = Scalar::from_bytes(vector.d.try_into().unwrap()).unwrap();
                let k = Scalar::from_bytes(vector.k.try_into().unwrap()).unwrap();
                let sig = d
                    .try_sign_prehashed(&k, None, GenericArray::from_slice(vector.m))
                    .unwrap();

                assert_eq!(vector.r, sig.r().as_slice());
                assert_eq!(vector.s, sig.s().as_slice());
            }
        }
    };
}

/// Define ECDSA verification test
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_verification_test {
    ($vectors:expr) => {
        #[test]
        fn ecdsa_verify_success() {
            for vector in $vectors {
                let q_raw = UncompressedPoint::from_affine_coords(
                    GenericArray::from_slice(vector.q_x),
                    GenericArray::from_slice(vector.q_y),
                );

                let q = AffinePoint::from_uncompressed_point(&q_raw).unwrap();

                let sig = Signature::from_scalars(
                    GenericArray::from_slice(vector.r),
                    GenericArray::from_slice(vector.s),
                );

                let result = q.verify_prehashed(GenericArray::from_slice(vector.m), &sig);

                assert!(result.is_ok());
            }
        }

        #[test]
        fn ecdsa_verify_invalid_s() {
            for vector in $vectors {
                let q_raw = UncompressedPoint::from_affine_coords(
                    GenericArray::from_slice(vector.q_x),
                    GenericArray::from_slice(vector.q_y),
                );

                let q = AffinePoint::from_uncompressed_point(&q_raw).unwrap();

                // Flip a bit in `s`
                let mut s_tweaked = GenericArray::clone_from_slice(vector.s);
                s_tweaked[0] ^= 1;

                let sig = Signature::from_scalars(GenericArray::from_slice(vector.r), &s_tweaked);

                let result = q.verify_prehashed(GenericArray::from_slice(vector.m), &sig);

                assert!(result.is_err());
            }
        }

        // TODO(tarcieri): test invalid q, invalid r, invalid m
    };
}
