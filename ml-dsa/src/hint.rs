use crate::module_lattice::util::Truncate;
use hybrid_array::{
    Array,
    typenum::{U256, Unsigned},
};

use crate::algebra::{AlgebraExt, BaseField, Decompose, Elem, Field, Polynomial, Vector};
use crate::param::{EncodedHint, SignatureParams};

fn make_hint<TwoGamma2: Unsigned>(z: Elem, r: Elem) -> bool {
    let r1 = r.high_bits::<TwoGamma2>();
    let v1 = (r + z).high_bits::<TwoGamma2>();
    r1 != v1
}

// The method only deals with public data, so we don't need to worry that / and % are not
// constant-time.
#[allow(clippy::integer_division_remainder_used)]
fn use_hint<TwoGamma2: Unsigned>(h: bool, r: Elem) -> Elem {
    let m: u32 = (BaseField::Q - 1) / TwoGamma2::U32;
    let (r1, r0) = r.decompose::<TwoGamma2>();
    let gamma2 = TwoGamma2::U32 / 2;
    if h && r0.0 <= gamma2 {
        Elem::new((r1.0 + 1) % m)
    } else if h && r0.0 >= BaseField::Q - gamma2 {
        Elem::new((r1.0 + m - 1) % m)
    } else if h {
        // We use the Elem encoding even for signed integers.  Since r0 is computed
        // mod+- 2*gamma2 (possibly minus 1), it is guaranteed to be in [-gamma2, gamma2].
        unreachable!();
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

    fn monotonic(a: &[usize]) -> bool {
        a.iter().enumerate().all(|(i, x)| i == 0 || a[i - 1] <= *x)
    }

    pub(crate) fn bit_unpack(y: &EncodedHint<P>) -> Option<Self> {
        let (indices, cuts) = P::split_hint(y);
        let cuts: Array<usize, P::K> = cuts.iter().map(|x| usize::from(*x)).collect();

        let indices: Array<usize, P::Omega> = indices.iter().map(|x| usize::from(*x)).collect();
        let max_cut: usize = cuts.iter().copied().max().unwrap();
        if !Self::monotonic(&cuts)
            || max_cut > indices.len()
            || indices[max_cut..].iter().copied().max().unwrap_or(0) > 0
        {
            return None;
        }

        let mut h = Self::default();
        let mut start = 0;
        for (i, &end) in cuts.iter().enumerate() {
            let indices = &indices[start..end];

            if !Self::monotonic(indices) {
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
