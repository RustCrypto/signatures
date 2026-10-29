//! Adapt the library's parameter sets to the source-included parameter traits.
use crate::param::{MaskSamplingSize, ParameterSet, SamplingSize};
use core::marker::PhantomData;

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Params<P>(PhantomData<P>);

impl<P> ParameterSet for Params<P>
where
    P: ml_dsa::MlDsaParams,
    P::Eta: SamplingSize,
    P::Gamma1: MaskSamplingSize,
{
    type K = P::K;
    type L = P::L;
    type Eta = P::Eta;
    type Gamma1 = P::Gamma1;
    type Gamma2 = P::Gamma2;
    type TwoGamma2 = P::TwoGamma2;
    type W1Bits = P::W1Bits;
    type Lambda = P::Lambda;
    type Omega = P::Omega;
    const TAU: usize = P::TAU;
}
