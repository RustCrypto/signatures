use crate::module_lattice::encode::ArraySize;
use crate::module_lattice::util::Truncate;
use hybrid_array::Array;

use crate::algebra::{
    BaseField, Elem, Field, Int, NttMatrix, NttPolynomial, NttVector, Polynomial, Vector,
};
use crate::crypto::{G, H};
use crate::param::{Eta, MaskSamplingSize};

// Algorithm 13 BytesToBits
fn bit_set(z: &[u8], i: usize) -> bool {
    let bit_index = i & 0x07;
    let byte_index = i >> 3;
    z[byte_index] & (1 << bit_index) != 0
}

// Algorithm 14 CoeffFromThreeBytes
fn coeff_from_three_bytes(b: [u8; 3]) -> Option<Elem> {
    let b0: Int = b[0].into();
    let b1: Int = b[1].into();
    let b2: Int = b[2].into();

    let b2p = if b2 > 127 { b2 - 128 } else { b2 };

    let z = (b2p << 16) + (b1 << 8) + b0;
    (z < BaseField::Q).then_some(Elem::new(z))
}

// Algorithm 15 CoeffFromHalfByte
fn coeff_from_half_byte(b: u8, eta: Eta) -> Option<Elem> {
    match eta {
        Eta::Two if b < 15 => {
            let b = Int::from(match b {
                b if b < 5 => b,
                b if b < 10 => b - 5,
                _ => b - 10,
            });

            if b <= 2 {
                Some(Elem::new(2 - b))
            } else {
                Some(-Elem::new(b - 2))
            }
        }
        Eta::Four if b < 9 => {
            let b = Int::from(b);
            if b <= 4 {
                Some(Elem::new(4 - b))
            } else {
                Some(-Elem::new(b - 4))
            }
        }
        _ => None,
    }
}

fn coeffs_from_byte(z: u8, eta: Eta) -> (Option<Elem>, Option<Elem>) {
    (
        coeff_from_half_byte(z & 0x0F, eta),
        coeff_from_half_byte(z >> 4, eta),
    )
}

// Algorithm 29 SampleInBall
pub(crate) fn sample_in_ball(rho: &[u8], tau: usize) -> Polynomial {
    const ONE: Elem = Elem::new(1);
    const MINUS_ONE: Elem = Elem::new(BaseField::Q - 1);

    let mut c = Polynomial::default();
    let mut ctx = H::default().absorb(rho);

    let mut s = [0u8; 8];
    ctx.squeeze(&mut s);

    // h = bytes_to_bits(s)
    let mut j = [0u8];
    for i in (256 - tau)..256 {
        ctx.squeeze(&mut j);
        while usize::from(j[0]) > i {
            ctx.squeeze(&mut j);
        }

        let j = usize::from(j[0]);
        c.0[i] = c.0[j];
        c.0[j] = if bit_set(&s, i + tau - 256) {
            MINUS_ONE
        } else {
            ONE
        };
    }

    c
}

// Algorithm 30 RejNTTPoly
fn rej_ntt_poly(rho: &[u8], r: u8, s: u8) -> NttPolynomial {
    let mut j = 0;
    let mut ctx = G::default().absorb(rho).absorb(&[s]).absorb(&[r]);

    let mut a = NttPolynomial::default();
    let mut s = [0u8; 3];
    while j < 256 {
        ctx.squeeze(&mut s);
        if let Some(x) = coeff_from_three_bytes(s) {
            a.0[j] = x;
            j += 1;
        }
    }

    a
}

// Algorithm 31 RejBoundedPoly
fn rej_bounded_poly(rho: &[u8], eta: Eta, r: u16) -> Polynomial {
    let mut j = 0;
    let mut ctx = H::default().absorb(rho).absorb(&r.to_le_bytes());

    let mut a = Polynomial::default();
    let mut z = [0u8];
    while j < 256 {
        ctx.squeeze(&mut z);
        let (z0, z1) = coeffs_from_byte(z[0], eta);

        if let Some(z) = z0 {
            a.0[j] = z;
            j += 1;
        }

        if j == 256 {
            break;
        }

        if let Some(z) = z1 {
            a.0[j] = z;
            j += 1;
        }
    }

    a
}

// Algorithm 32 ExpandA
pub(crate) fn expand_a<K: ArraySize, L: ArraySize>(rho: &[u8]) -> NttMatrix<K, L> {
    NttMatrix::new(Array::from_fn(|r| {
        NttVector::new(Array::from_fn(|s| {
            rej_ntt_poly(rho, Truncate::truncate(r), Truncate::truncate(s))
        }))
    }))
}

// Algorithm 33 ExpandS
//
// We only do half of the algorithm here, because it's inconvenient to return two vectors of
// different sizes.  So the caller has to call twice:
//
//    let s1 = Vector::<K>::expand_s(rho, 0);
//    let s2 = Vector::<L>::expand_s(rho, L::USIZE);
pub(crate) fn expand_s<K: ArraySize>(rho: &[u8], eta: Eta, base: usize) -> Vector<K> {
    Vector::new(Array::from_fn(|r| {
        let r = Truncate::truncate(r + base);
        rej_bounded_poly(rho, eta, r)
    }))
}

// Algorithm 34 ExpandMask
pub(crate) fn expand_mask<K, Gamma1>(rho: &[u8], mu: u16) -> Vector<K>
where
    K: ArraySize,
    Gamma1: MaskSamplingSize,
{
    Vector::new(Array::from_fn(|r| {
        let r: u16 = Truncate::truncate(r);
        let v = H::default()
            .absorb(rho)
            .absorb(&(mu + r).to_le_bytes())
            .squeeze_new::<Gamma1::SampleSize>();

        Gamma1::unpack(&v)
    }))
}

#[cfg(test)]
#[allow(clippy::as_conversions)]
#[allow(clippy::cast_possible_truncation)]
mod test {
    use super::*;
    use hybrid_array::typenum::{U16, U256};

    fn max_abs_1(p: &Polynomial) -> bool {
        p.0.iter()
            .all(|x| x.0 == 0 || x.0 == 1 || x.0 == BaseField::Q - 1)
    }

    fn hamming_weight(p: &Polynomial) -> usize {
        p.0.iter().filter(|x| x.0 != 0).count()
    }

    // Verify that SampleInBall returns a polynomial with the following properties:
    //   a. All coefficients are from {-1, 0, 1}
    //   b. Hamming weight is exactly tau
    //
    // We test 256 samples for each value of
    #[test]
    fn test_sample_in_ball() {
        for tau in 1..65 {
            for seed in 0_usize..255 {
                let rho = ((tau as u16) << 8) + (seed as u16);
                let p = sample_in_ball(&rho.to_be_bytes(), tau);
                assert_eq!(hamming_weight(&p), tau);
                assert!(max_abs_1(&p));
            }
        }
    }

    // Verify that RejNTTPoly produces samples that are in the proper range, and roughly uniform.
    // For the "roughly uniform" criterion,
    #[test]
    fn test_rej_ntt_poly() {
        let sample: Array<Array<Elem, U256>, U16> = Array::from_fn(|i| {
            let i = i as u8;
            let rho = [i; 32];
            rej_ntt_poly(&rho, i, i + 1).0
        });

        let sample = sample.as_flattened();

        let all_in_range = sample.iter().all(|x| x.0 < BaseField::Q);
        assert!(all_in_range);

        // TODO measure uniformity
    }

    #[test]
    fn test_sample_cbd() {
        let rho = [0; 32];

        // Eta = 2
        let sample = rej_bounded_poly(&rho, Eta::Two, 0).0;
        let all_in_range = sample.iter().map(|x| *x + Elem::new(2)).all(|x| x.0 < 5);
        assert!(all_in_range);
        // TODO measure uniformity

        // Eta = 4
        let sample = rej_bounded_poly(&rho, Eta::Four, 0).0;
        let all_in_range = sample.iter().map(|x| *x + Elem::new(4)).all(|x| x.0 < 9);
        assert!(all_in_range);
        // TODO measure uniformity
    }
}
