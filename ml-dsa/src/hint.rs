use hybrid_array::{
    Array,
    typenum::{U256, Unsigned},
};
use module_lattice::utils::Truncate;

use crate::algebra::{AlgebraExt, BaseField, Decompose, Elem, Field, Polynomial, Vector};
use crate::param::{EncodedHint, SignatureParams};

/// Algorithm 39 `MakeHint`: computes hint bit indicating whether adding `z` to `r` alters the high
/// bits of `r`.
fn make_hint<TwoGamma2: Unsigned>(z: Elem, r: Elem) -> bool {
    let r1 = r.high_bits::<TwoGamma2>();
    let v1 = (r + z).high_bits::<TwoGamma2>();
    r1 != v1
}

/// Algorithm 40 `UseHint`: returns the high bits of `r` adjusted according to hint `h`.
#[allow(clippy::integer_division_remainder_used, reason = "params are public")]
fn use_hint<TwoGamma2: Unsigned>(h: bool, r: Elem) -> Elem {
    let m: u32 = (BaseField::Q - 1) / TwoGamma2::U32;
    let (r1, r0) = r.decompose::<TwoGamma2>();
    let gamma2 = TwoGamma2::U32 / 2;

    if h {
        if r0.0 > 0 && r0.0 <= gamma2 {
            Elem::new((r1.0 + 1) % m)
        } else if (r0.0 == 0) || (r0.0 >= BaseField::Q - gamma2) {
            Elem::new((r1.0 + m - 1) % m)
        } else {
            // We use the Elem encoding even for signed integers.  Since r0 is computed
            // mod+- 2*gamma2 (possibly minus 1), it is guaranteed to be in [-gamma2, gamma2].
            unreachable!();
        }
    } else {
        r1
    }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Hint<P>(pub Array<Array<bool, U256>, P::K>)
where
    P: SignatureParams;

impl<P> Default for Hint<P>
where
    P: SignatureParams,
{
    fn default() -> Self {
        Self(Array::default())
    }
}

impl<P> Hint<P>
where
    P: SignatureParams,
{
    pub(crate) fn new(z: &Vector<P::K>, r: &Vector<P::K>) -> Self {
        let zi = z.0.iter();
        let ri = r.0.iter();

        Self(
            zi.zip(ri)
                .map(|(zv, rv)| {
                    let zvi = zv.0.iter();
                    let rvi = rv.0.iter();

                    zvi.zip(rvi)
                        .map(|(&z, &r)| make_hint::<P::TwoGamma2>(z, r))
                        .collect()
                })
                .collect(),
        )
    }

    pub(crate) fn hamming_weight(&self) -> usize {
        self.0
            .iter()
            .map(|x| x.iter().filter(|x| **x).count())
            .sum()
    }

    pub(crate) fn use_hint(&self, r: &Vector<P::K>) -> Vector<P::K> {
        let hi = self.0.iter();
        let ri = r.0.iter();

        Vector::new(
            hi.zip(ri)
                .map(|(hv, rv)| {
                    let hvi = hv.iter();
                    let rvi = rv.0.iter();

                    Polynomial::new(
                        hvi.zip(rvi)
                            .map(|(&h, &r)| use_hint::<P::TwoGamma2>(h, r))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    pub(crate) fn bit_pack(&self) -> EncodedHint<P> {
        let mut y: EncodedHint<P> = Array::default();
        let mut index = 0;
        let omega = P::Omega::USIZE;
        for i in 0..P::K::U8 {
            let i_usize: usize = i.into();
            for j in 0..256 {
                if self.0[i_usize][j] {
                    y[index] = Truncate::truncate(j);
                    index += 1;
                }
            }

            y[omega + i_usize] = Truncate::truncate(index);
        }

        y
    }

    pub(crate) fn bit_unpack(y: &EncodedHint<P>) -> Option<Self> {
        let (indices, cuts) = P::split_hint(y);
        let cuts: Array<usize, P::K> = cuts.iter().map(|x| usize::from(*x)).collect();

        let indices: Array<usize, P::Omega> = indices.iter().map(|x| usize::from(*x)).collect();
        let max_cut: usize = cuts.iter().copied().max().unwrap();

        // cuts must be monotonic but can repeat
        if !cuts.windows(2).all(|w| w[0] <= w[1])
            || max_cut > indices.len()
            || indices[max_cut..].iter().copied().max().unwrap_or(0) > 0
        {
            return None;
        }

        let mut h = Self::default();
        let mut start = 0;
        for (i, &end) in cuts.iter().enumerate() {
            let indices = &indices[start..end];

            // indices must be strictly increasing
            if !indices.windows(2).all(|w| w[0] < w[1]) {
                return None;
            }

            for &j in indices {
                h.0[i][j] = true;
            }

            start = end;
        }

        Some(h)
    }
}

#[cfg(test)]
#[allow(clippy::integer_division_remainder_used)]
mod test {
    use super::*;
    use crate::{MlDsa44, MlDsa65, ParameterSet};

    #[test]
    fn use_hint_arithmetic() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;
        let gamma2 = TwoGamma2::U32 / 2;
        let m = (BaseField::Q - 1) / TwoGamma2::U32;

        // h=false returns r1 unchanged
        let r = Elem::new(1000);
        let (expected_r1, _) = r.decompose::<TwoGamma2>();
        assert_eq!(use_hint::<TwoGamma2>(false, r), expected_r1);

        // h=true with positive r0: increment r1 mod m
        for test_r in 1..TwoGamma2::U32 {
            let r = Elem::new(test_r);
            let (r1, r0) = r.decompose::<TwoGamma2>();
            if r0.0 > 0 && r0.0 <= gamma2 {
                let result = use_hint::<TwoGamma2>(true, r);
                assert_eq!(result, Elem::new((r1.0 + 1) % m));
                break;
            }
        }

        // h=true with negative r0: decrement r1
        for test_r in (BaseField::Q - TwoGamma2::U32)..BaseField::Q {
            let r = Elem::new(test_r);
            let (r1, r0) = r.decompose::<TwoGamma2>();
            if r0.0 >= BaseField::Q - gamma2 {
                let result = use_hint::<TwoGamma2>(true, r);
                assert_eq!(result, Elem::new((r1.0 + m - 1) % m));
                break;
            }
        }

        // Test modular wrapping at m-1
        let r_at_max = Elem::new(TwoGamma2::U32 * (m - 1) + 1);
        let (r1_max, r0_max) = r_at_max.decompose::<TwoGamma2>();
        if r1_max.0 == m - 1 && r0_max.0 > 0 && r0_max.0 <= gamma2 {
            assert_eq!(use_hint::<TwoGamma2>(true, r_at_max).0, 0);
        }

        // Test with r=1
        let r_one = Elem::new(1);
        let (r1_one, _) = r_one.decompose::<TwoGamma2>();
        assert_eq!(use_hint::<TwoGamma2>(true, r_one).0, (r1_one.0 + 1) % m);

        // Test with r=Q-1
        let r_qm1 = Elem::new(BaseField::Q - 1);
        let (r1_qm1, r0_qm1) = r_qm1.decompose::<TwoGamma2>();
        if r0_qm1.0 >= BaseField::Q - gamma2 {
            assert_eq!(use_hint::<TwoGamma2>(true, r_qm1).0, (r1_qm1.0 + m - 1) % m);
        }
    }

    #[test]
    fn use_hint_m_wraparound() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;
        let m = (BaseField::Q - 1) / TwoGamma2::U32;

        let r_base = TwoGamma2::U32 * (m - 1);
        for offset in 1..100 {
            let r = Elem::new(r_base + offset);
            let (r1, r0) = r.decompose::<TwoGamma2>();
            if r1.0 == m - 1 && r0.0 > 0 && r0.0 <= TwoGamma2::U32 / 2 {
                assert_eq!(use_hint::<TwoGamma2>(true, r).0, 0);
                return;
            }
        }
        panic!("Could not find suitable test value");
    }

    #[test]
    fn use_hint_r0_is_zero() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;
        let m = (BaseField::Q - 1) / TwoGamma2::U32;
        let r = Elem::new(0);
        let (r1, r0) = r.decompose::<TwoGamma2>();
        assert_eq!(r0.0, 0);

        let result = use_hint::<TwoGamma2>(true, r);
        assert_eq!(result, Elem::new((r1.0 + m - 1) % m));
    }

    #[test]
    fn use_hint_threshold() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;
        let gamma2 = TwoGamma2::U32 / 2;
        let m = (BaseField::Q - 1) / TwoGamma2::U32;

        let threshold = BaseField::Q - gamma2;
        for test_r in (threshold - 100)..(threshold + 100) {
            if test_r >= BaseField::Q {
                continue;
            }
            let r = Elem::new(test_r);
            let (r1, r0) = r.decompose::<TwoGamma2>();
            if r0.0 == threshold {
                let expected = (r1.0 + m - 1) % m;
                assert_eq!(use_hint::<TwoGamma2>(true, r).0, expected);
                return;
            }
        }
    }

    #[test]
    fn decompose_produces_valid_r0() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;
        let gamma2 = TwoGamma2::U32 / 2;

        for test_r in [
            0,
            1000,
            BaseField::Q / 2,
            BaseField::Q - 1000,
            BaseField::Q - 1,
        ] {
            let r = Elem::new(test_r);
            let (r1, r0) = r.decompose::<TwoGamma2>();

            let in_positive_range = r0.0 <= gamma2;
            let in_negative_range = r0.0 >= BaseField::Q - gamma2;
            assert!(in_positive_range || in_negative_range);

            let reconstructed = TwoGamma2::U32 * r1.0 + r0.0;
            assert_eq!(reconstructed % BaseField::Q, test_r % BaseField::Q);
        }
    }

    #[test]
    fn make_hint_correctness() {
        type TwoGamma2 = <MlDsa65 as ParameterSet>::TwoGamma2;

        for test_r in [0, 1000, BaseField::Q / 2, BaseField::Q - 1] {
            let r = Elem::new(test_r);
            let r1 = r.high_bits::<TwoGamma2>();

            assert!(!make_hint::<TwoGamma2>(Elem::new(0), r));

            for test_z in [0, 1, TwoGamma2::U32 / 2, TwoGamma2::U32] {
                let z = Elem::new(test_z);
                let h = make_hint::<TwoGamma2>(z, r);
                let v1 = (r + z).high_bits::<TwoGamma2>();
                assert_eq!(h, r1 != v1);
            }
        }
    }

    #[test]
    fn hint_round_trip() {
        fn test<P: SignatureParams + PartialEq + core::fmt::Debug>() {
            let mut h = Hint::<P>::default();
            for i in 0..P::K::USIZE {
                if i < h.0.len() {
                    h.0[i][0] = true;
                    h.0[i][10] = true;
                    if i > 0 {
                        h.0[i][i * 5] = true;
                    }
                }
            }
            let packed = h.bit_pack();
            let unpacked = Hint::<P>::bit_unpack(&packed).unwrap();
            assert_eq!(h, unpacked);
        }
        test::<MlDsa44>();
        test::<MlDsa65>();
    }
}
