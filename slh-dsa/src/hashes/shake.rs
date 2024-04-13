use core::fmt::Debug;

use crate::address::Address;
use crate::fors::ForsParams;
use crate::hashes::HashSuite;
use crate::hypertree::HypertreeParams;
use crate::wots::WotsParams;
use crate::xmss::XmssParams;
use crate::{ParameterSet, PkSeed, SkPrf, SkSeed};
use digest::{ExtendableOutput, Update};
use hybrid_array::typenum::consts::{U16, U30, U32};
use hybrid_array::typenum::{U24, U34, U39, U42, U47, U49};
use hybrid_array::{Array, ArraySize};
use sha3::Shake256;
use typenum::U;

/// Implementation of the component hash functions using SHAKE256
///
/// Follows section 10.1 of FIPS-205
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shake<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Shake<N, M>
where
    N: Debug + Clone + PartialEq + Eq,
    M: Debug + Clone + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: impl AsRef<[u8]>,
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(sk_prf.as_ref());
        hasher.update(opt_rand.as_slice());
        hasher.update(msg.as_ref());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: impl AsRef<[u8]>,
    ) -> Array<u8, Self::M> {
        let mut hasher = Shake256::default();
        hasher.update(rand.as_slice());
        hasher.update(pk_seed.as_ref());
        hasher.update(pk_root.as_ref());
        hasher.update(msg.as_ref());
        let mut output = Array::<u8, Self::M>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn prf_sk(
        pk_seed: &PkSeed<Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &impl Address,
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(sk_seed.as_ref());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn t<L: ArraySize>(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed.as_ref());
        hasher.update(adrs.as_ref());
        for i in 0..L::USIZE {
            hasher.update(m[i].as_slice());
        }
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn h(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(m1.as_slice());
        hasher.update(m2.as_slice());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }

    fn f(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(m.as_slice());
        let mut output = Array::<u8, Self::N>::default();
        hasher.finalize_xof_into(&mut output);
        output
    }
}

// TODO: Consolidate parameters between Shake and SHA2 instances

/// SHAKE256 at L1 security with small signatures
pub type Shake128s = Shake<U16, U30>;
impl WotsParams for Shake128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Shake128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Shake128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Shake128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14 + 7) / 8 }>;
}
impl ParameterSet for Shake128s {
    const NAME: &'static str = "SLH-DSA-SHAKE-128s";
}

/// SHAKE256 at L1 security with fast signatures
pub type Shake128f = Shake<U16, U34>;
impl WotsParams for Shake128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Shake128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Shake128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Shake128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Shake128f {
    const NAME: &'static str = "SLH-DSA-SHAKE-128f";
}

/// SHAKE256 at L3 security with small signatures
pub type Shake192s = Shake<U24, U39>;
impl WotsParams for Shake192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Shake192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Shake192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Shake192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17 + 7) / 8 }>;
}
impl ParameterSet for Shake192s {
    const NAME: &'static str = "SLH-DSA-SHAKE-192s";
}

/// SHAKE256 at L3 security with fast signatures
pub type Shake192f = Shake<U24, U42>;
impl WotsParams for Shake192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Shake192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Shake192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Shake192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8 + 7) / 8 }>;
}
impl ParameterSet for Shake192f {
    const NAME: &'static str = "SLH-DSA-SHAKE-192f";
}

/// SHAKE256 at L5 security with small signatures
pub type Shake256s = Shake<U32, U47>;
impl WotsParams for Shake256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Shake256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Shake256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Shake256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22 + 7) / 8 }>;
}
impl ParameterSet for Shake256s {
    const NAME: &'static str = "SLH-DSA-SHAKE-256s";
}

/// SHAKE256 at L5 security with fast signatures
pub type Shake256f = Shake<U32, U49>;
impl WotsParams for Shake256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Shake256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Shake256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Shake256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9 + 7) / 8 }>;
}
impl ParameterSet for Shake256f {
    const NAME: &'static str = "SLH-DSA-SHAKE-256f";
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    fn prf_msg<H: HashSuite>() {
        let sk_prf = SkPrf(Array::<u8, H::N>::from_fn(|_| 0));
        let opt_rand = Array::<u8, H::N>::from_fn(|_| 1);
        let msg = [2u8; 32];

        let expected = hex!("bc5c062307df0a41aeeae19ad655f7b2");

        let result = H::prf_msg(&sk_prf, &opt_rand, msg);

        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn prf_msg_16_30() {
        prf_msg::<Shake128f>();
    }
}
