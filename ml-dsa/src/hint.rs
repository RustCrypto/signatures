use hybrid_array::{
    typenum::{Unsigned, U256},
    Array,
};

use crate::algebra::*;
use crate::param::*;
use crate::util::Truncate;

fn make_hint<Gamma2: Unsigned>(z: FieldElement, r: FieldElement) -> bool {
    // XXX(RLB): Maybe propagate the Gamma2 into these methods
    let r1 = r.high_bits::<Gamma2>();
    let v1 = (r + z).high_bits::<Gamma2>();
    r1 != v1
}

fn use_hint<Gamma2: Unsigned>(h: bool, r: FieldElement) -> FieldElement {
    // XXX(RLB) Can we make this const?
    let m: u32 = (FieldElement::Q - 1) / (2 * Gamma2::U32);
    let (r1, r0) = r.decompose::<Gamma2>();
    if h && r0.0 <= Gamma2::U32 {
        FieldElement((r1.0 + 1) % m)
    } else if h && r0.0 > FieldElement::Q - Gamma2::U32 {
        FieldElement((r1.0 + m - 1) % m)
    } else if h {
        // We use the FieldElement encoding even for signed integers.  Since r0 is computed
        // mod+- 2*gamma2, it is guaranteed to be in (gamma2, gamma2].
        unreachable!();
    } else {
        r1
    }
}

#[derive(Clone, PartialEq)]
pub struct Hint<P>(pub Array<Array<bool, U256>, P::K>)
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
    pub fn new(z: PolynomialVector<P::K>, r: PolynomialVector<P::K>) -> Self {
        let zi = z.0.iter();
        let ri = r.0.iter();

        Self(
            zi.zip(ri)
                .map(|(zv, rv)| {
                    let zvi = zv.0.iter();
                    let rvi = rv.0.iter();

                    zvi.zip(rvi)
                        .map(|(&z, &r)| make_hint::<P::Gamma2>(z, r))
                        .collect()
                })
                .collect(),
        )
    }

    pub fn hamming_weight(&self) -> usize {
        self.0
            .iter()
            .map(|x| x.iter().filter(|x| **x).count())
            .sum()
    }

    pub fn use_hint(&self, r: &PolynomialVector<P::K>) -> PolynomialVector<P::K> {
        let hi = self.0.iter();
        let ri = r.0.iter();

        PolynomialVector(
            hi.zip(ri)
                .map(|(hv, rv)| {
                    let hvi = hv.iter();
                    let rvi = rv.0.iter();

                    Polynomial(
                        hvi.zip(rvi)
                            .map(|(&h, &r)| use_hint::<P::Gamma2>(h, r))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    pub fn bit_pack(&self) -> EncodedHint<P> {
        let mut y: EncodedHint<P> = Default::default();
        let mut index = 0;
        let omega = P::Omega::USIZE;

        for i in 0..P::K::U8 {
            let i_usize: usize = i.into();
            for j in 0..256 {
                if self.0[i_usize][j] {
                    y[index] = j.truncate();
                    index += 1
                }
            }

            y[omega + i_usize] = index.truncate();
        }

        y
    }

    pub fn bit_unpack(y: &EncodedHint<P>) -> Option<Self> {
        let mut h = Self::default();
        let mut index = 0;
        let omega = P::Omega::USIZE;

        for i in 0..P::K::U8 {
            let i_usize: usize = i.into();
            let end: usize = y[omega + i_usize].into();
            if end < index || end > omega {
                return None;
            }

            let start = index;
            while index < end {
                if index > start && y[index - 1] >= y[index] {
                    return None;
                }

                let j: usize = y[index].into();
                h.0[i_usize][j] = true;
                index += 1;
            }
        }

        if y[index..omega].iter().any(|x| *x != 0) {
            return None;
        }

        Some(h)
    }
}
