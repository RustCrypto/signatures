use crate::address::{ForsTree, WotsHash};
use crate::signature_encoding::Signature;
use crate::util::split_digest;
use crate::verifying_key::VerifyingKey;
use crate::{ParameterSet, PkSeed, Sha2L1, Sha2L35, Shake, VerifyingKeyLen};
use ::signature::{Error, KeypairRef, RandomizedSigner, Signer};
use hybrid_array::{Array, ArraySize};
use typenum::{Unsigned, U, U16, U24, U32};

// NewTypes for ensuring hash argument order correctness
#[derive(Clone)]
pub(crate) struct SkSeed<N: ArraySize>(pub(crate) Array<u8, N>);
impl<N: ArraySize> AsRef<[u8]> for SkSeed<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<N: ArraySize> From<&[u8]> for SkSeed<N> {
    fn from(slice: &[u8]) -> Self {
        Self(Array::clone_from_slice(slice))
    }
}
impl<N: ArraySize> SkPrf<N> {
    pub(crate) fn new(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut bytes = Array::<u8, N>::default();
        rng.fill_bytes(bytes.as_mut_slice());
        Self(bytes)
    }
}

#[derive(Clone)]
pub(crate) struct SkPrf<N: ArraySize>(pub(crate) Array<u8, N>);
impl<N: ArraySize> AsRef<[u8]> for SkPrf<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<N: ArraySize> From<&[u8]> for SkPrf<N> {
    fn from(slice: &[u8]) -> Self {
        Self(Array::clone_from_slice(slice))
    }
}
impl<N: ArraySize> SkSeed<N> {
    pub(crate) fn new(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut bytes = Array::<u8, N>::default();
        rng.fill_bytes(bytes.as_mut_slice());
        Self(bytes)
    }
}

/// A `SigningKey` allows signing messages with a fixed parameter set
#[derive(Clone)]
pub struct SigningKey<P: ParameterSet> {
    pub(crate) sk_seed: SkSeed<P::N>,
    pub(crate) sk_prf: SkPrf<P::N>,
    pub(crate) verifying_key: VerifyingKey<P>,
}

/// A trait specifying the length of a serialized signing key for a given parameter set
pub trait SigningKeyLen: VerifyingKeyLen {
    /// The length of the serialized signing key in bytes
    type SkLen: ArraySize;
}

impl<P: ParameterSet> SigningKey<P> {
    /// Create a new `SigningKey` from a cryptographic random number generator
    pub fn new(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let sk_seed = SkSeed::new(rng);
        let sk_prf = SkPrf::new(rng);
        let pk_seed = PkSeed::new(rng);
        let mut adrs = WotsHash::default();
        adrs.layer_adrs.set(P::D::U32 - 1);

        let pk_root = P::xmss_node(&sk_seed, 0, P::HPrime::U32, &pk_seed, &adrs);
        let verifying_key = VerifyingKey { pk_seed, pk_root };
        SigningKey {
            sk_seed,
            sk_prf,
            verifying_key,
        }
    }

    /// Serialize the signing key to a new stack-allocated array
    ///
    /// This clones the underlying fields
    pub fn to_bytes(&self) -> Array<u8, P::SkLen> {
        let mut bytes = Array::<u8, P::SkLen>::default();
        bytes[..P::N::USIZE].copy_from_slice(&self.sk_seed.0);
        bytes[P::N::USIZE..2 * P::N::USIZE].copy_from_slice(&self.sk_prf.0);
        bytes[2 * P::N::USIZE..].copy_from_slice(&self.verifying_key.to_bytes());
        bytes
    }

    /// Serialize the signing key to a new heap-allocated vector
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8>
    where
        P: VerifyingKeyLen,
    {
        self.to_bytes().to_vec()
    }
}

fn sign_with_opt_rng<P: ParameterSet>(
    sk: &SigningKey<P>,
    msg: &[u8],
    opt_rand: &Array<u8, P::N>,
) -> Signature<P> {
    let sk_seed = &sk.sk_seed;
    let pk_seed = &sk.verifying_key.pk_seed;

    let randomizer = P::prf_msg(&sk.sk_prf, opt_rand, msg);

    let digest = P::h_msg(&randomizer, pk_seed, &sk.verifying_key.pk_root, msg);
    let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest);
    let adrs = ForsTree::new(idx_tree, idx_leaf);
    let fors_sig = P::fors_sign(md, sk_seed, pk_seed, &adrs);

    let fors_pk = P::fors_pk_from_sig(&fors_sig, md, pk_seed, &adrs);
    let ht_sig = P::ht_sign(&fors_pk, sk_seed, pk_seed, idx_tree, idx_leaf);

    Signature {
        randomizer,
        fors_sig,
        ht_sig,
    }
}

impl<P: ParameterSet> Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        Ok(sign_with_opt_rng(self, msg, &self.verifying_key.pk_seed.0))
    }
}

impl<P: ParameterSet> RandomizedSigner<Signature<P>> for SigningKey<P> {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl signature::rand_core::CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature<P>, signature::Error> {
        let mut randomizer = Array::<u8, P::N>::default();
        rng.fill_bytes(randomizer.as_mut_slice());
        Ok(sign_with_opt_rng(self, msg, &randomizer))
    }
}

impl<P: ParameterSet> AsRef<VerifyingKey<P>> for SigningKey<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

impl<P: ParameterSet> KeypairRef for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;
}

impl<M> SigningKeyLen for Sha2L1<U16, M> {
    type SkLen = U<{ 4 * 16 }>;
}

impl<M> SigningKeyLen for Sha2L35<U24, M> {
    type SkLen = U<{ 4 * 24 }>;
}
impl<M> SigningKeyLen for Sha2L35<U32, M> {
    type SkLen = U<{ 4 * 32 }>;
}

impl<M> SigningKeyLen for Shake<U16, M> {
    type SkLen = U<{ 4 * 16 }>;
}
impl<M> SigningKeyLen for Shake<U24, M> {
    type SkLen = U<{ 4 * 24 }>;
}
impl<M> SigningKeyLen for Shake<U32, M> {
    type SkLen = U<{ 4 * 32 }>;
}
