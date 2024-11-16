use core::ops::Mul;
use hybrid_array::{
    typenum::{Prod, U32},
    Array,
};

use crate::algebra::*;
use crate::param::*;

pub struct Hint<P>(Array<bool, P::HintSize>)
where
    P: SignatureParams;

impl<P> Hint<P>
where
    P: SignatureParams,
{
    pub fn new(z: PolynomialVector<P::K>, r: PolynomialVector<P::K>) -> Self {
        todo!();
    }

    pub fn hamming_weight(&self) -> usize {
        self.0.iter().filter(|x| **x).count()
    }

    pub fn use_hint(&self, w_approx: &PolynomialVector<P::K>) -> PolynomialVector<P::K> {
        todo!();
    }
}
