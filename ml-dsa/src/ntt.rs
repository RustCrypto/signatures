use crate::module_lattice::algebra::Field;
use crate::module_lattice::encode::ArraySize;
use core::ops::Mul;

use crate::algebra::{BaseField, Elem, NttPolynomial, NttVector, Polynomial, Vector};

// Since the powers of zeta used in the NTT and MultiplyNTTs are fixed, we use pre-computed tables
// to avoid the need to compute the exponetiations at runtime.
//
//   ZETA_POW_BITREV[i] = zeta^{BitRev_8(i)}
//
// Note that the const environment here imposes some annoying conditions.  Because operator
// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
// are forbidden in `const` functions, we do them manually with `while` loops.
//
// The values computed here match those provided in Appendix B of FIPS 204.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::as_conversions)]
#[allow(clippy::integer_division_remainder_used)]
const ZETA_POW_BITREV: [Elem; 256] = {
    const ZETA: u64 = 1753;
    const fn bitrev8(x: usize) -> usize {
        (x as u8).reverse_bits() as usize
    }

    // Compute the powers of zeta
    let mut pow = [Elem::new(0); 256];
    let mut i = 0;
    let mut curr = 1u64;
    while i < 256 {
        pow[i] = Elem::new(curr as u32);
        i += 1;
        curr = (curr * ZETA) % BaseField::QL;
    }

    // Reorder the powers according to bitrev8
    // Note that entry 0 is left as zero, in order to match the `zetas` array in the
    // specification.
    let mut pow_bitrev = [Elem::new(0); 256];
    let mut i = 1;
    while i < 256 {
        pow_bitrev[i] = pow[bitrev8(i)];
        i += 1;
    }
    pow_bitrev
};

pub(crate) trait Ntt {
    type Output;
    fn ntt(&self) -> Self::Output;
}

impl Ntt for Polynomial {
    type Output = NttPolynomial;

    // Algorithm 41 NTT
    fn ntt(&self) -> Self::Output {
        let mut w = self.0.clone();

        let mut m = 0;
        for len in [128, 64, 32, 16, 8, 4, 2, 1] {
            for start in (0..256).step_by(2 * len) {
                m += 1;
                let z = ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = z * w[j + len];
                    w[j + len] = w[j] - t;
                    w[j] = w[j] + t;
                }
            }
        }

        NttPolynomial::new(w)
    }
}

impl<K: ArraySize> Ntt for Vector<K> {
    type Output = NttVector<K>;

    fn ntt(&self) -> Self::Output {
        NttVector::new(self.0.iter().map(Polynomial::ntt).collect())
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) trait NttInverse {
    type Output;
    fn ntt_inverse(&self) -> Self::Output;
}

impl NttInverse for NttPolynomial {
    type Output = Polynomial;

    // Algorithm 42 NTT^{−1}
    fn ntt_inverse(&self) -> Self::Output {
        const INVERSE_256: Elem = Elem::new(8_347_681);

        let mut w = self.0.clone();

        let mut m = 256;
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2 * len) {
                m -= 1;
                let z = -ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = w[j];
                    w[j] = t + w[j + len];
                    w[j + len] = z * (t - w[j + len]);
                }
            }
        }

        INVERSE_256 * &Polynomial::new(w)
    }
}

impl<K: ArraySize> NttInverse for NttVector<K> {
    type Output = Vector<K>;

    fn ntt_inverse(&self) -> Self::Output {
        Vector::new(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

impl Mul<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    // Algorithm 45 MultiplyNTT
    fn mul(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial::new(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x * y)
                .collect(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::as_conversions)]
#[allow(clippy::cast_possible_truncation)]
mod test {
    use super::*;
    use hybrid_array::{
        Array,
        typenum::{U2, U3},
    };

    use crate::algebra::*;

    // Multiplication in R_q, modulo X^256 + 1
    impl Mul<&Polynomial> for &Polynomial {
        type Output = Polynomial;

        fn mul(self, rhs: &Polynomial) -> Self::Output {
            let mut out = Self::Output::default();
            for (i, x) in self.0.iter().enumerate() {
                for (j, y) in rhs.0.iter().enumerate() {
                    let (sign, index) = if i + j < 256 {
                        (Elem::new(1), i + j)
                    } else {
                        (Elem::new(BaseField::Q - 1), i + j - 256)
                    };

                    out.0[index] = out.0[index] + (sign * *x * *y);
                }
            }
            out
        }
    }

    // A polynomial with only a scalar component, to make simple test cases
    fn const_ntt(x: Int) -> NttPolynomial {
        let mut p = Polynomial::default();
        p.0[0] = Elem::new(x);
        p.ntt()
    }

    #[test]
    fn ntt() {
        let f = Polynomial::new(Array::from_fn(|i| Elem::new(i as Int)));
        let g = Polynomial::new(Array::from_fn(|i| Elem::new((2 * i) as Int)));
        let f_hat = f.ntt();
        let g_hat = g.ntt();

        // Verify that NTT and NTT^-1 are actually inverses
        let f_unhat = f_hat.ntt_inverse();
        assert_eq!(f, f_unhat);

        // Verify that NTT is a homomorphism with regard to addition
        let fg = &f + &g;
        let f_hat_g_hat = &f_hat + &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);

        // Verify that NTT is a homomorphism with regard to multiplication
        let fg = &f * &g;
        let f_hat_g_hat = &f_hat * &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);
    }

    #[test]
    fn ntt_vector() {
        // Verify vector addition
        let v1: NttVector<U3> = NttVector::new(Array([const_ntt(1), const_ntt(1), const_ntt(1)]));
        let v2: NttVector<U3> = NttVector::new(Array([const_ntt(2), const_ntt(2), const_ntt(2)]));
        let v3: NttVector<U3> = NttVector::new(Array([const_ntt(3), const_ntt(3), const_ntt(3)]));
        assert_eq!((&v1 + &v2), v3);

        // Verify dot product
        assert_eq!((&v1 * &v2), const_ntt(6));
        assert_eq!((&v1 * &v3), const_ntt(9));
        assert_eq!((&v2 * &v3), const_ntt(18));
    }

    #[test]
    fn ntt_matrix() {
        // Verify matrix multiplication by a vector
        let a: NttMatrix<U3, U2> = NttMatrix::new(Array([
            NttVector::new(Array([const_ntt(1), const_ntt(2)])),
            NttVector::new(Array([const_ntt(3), const_ntt(4)])),
            NttVector::new(Array([const_ntt(5), const_ntt(6)])),
        ]));
        let v_in: NttVector<U2> = NttVector::new(Array([const_ntt(1), const_ntt(2)]));
        let v_out: NttVector<U3> =
            NttVector::new(Array([const_ntt(5), const_ntt(11), const_ntt(17)]));
        assert_eq!(&a * &v_in, v_out);
    }
}
