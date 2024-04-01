use crate::address::ForsTree;
use crate::signature_encoding::Signature;
use crate::util::split_digest;
use crate::ParameterSet;
use crate::Sha2L1;
use crate::Sha2L35;
use crate::Shake;
use ::signature::{Error, Verifier};
use hybrid_array::{Array, ArraySize};
use typenum::{Unsigned, U, U16, U24, U32};

/// A trait specifying the length of a serialized verifying key for a given parameter set
pub trait VerifyingKeyLen {
    /// The length of the serialized verifying key in bytes
    type VkLen: ArraySize;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PkSeed<N: ArraySize>(pub(crate) Array<u8, N>);
impl<N: ArraySize> AsRef<[u8]> for PkSeed<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<N: ArraySize> From<&[u8]> for PkSeed<N> {
    fn from(slice: &[u8]) -> Self {
        Self(Array::clone_from_slice(slice))
    }
}
impl<N: ArraySize> PkSeed<N> {
    pub(crate) fn new(rng: &mut impl rand_core::RngCore) -> Self {
        let mut bytes = Array::<u8, N>::default();
        rng.fill_bytes(bytes.as_mut_slice());
        Self(bytes)
    }
}

/// A `VerifyingKey` is an SLH-DSA public key, allowing
/// verification of signatures created with the corresponding
/// `SigningKey`
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyingKey<P: ParameterSet> {
    pub(crate) pk_seed: PkSeed<P::N>,
    pub(crate) pk_root: Array<u8, P::N>,
}

impl<P: ParameterSet + VerifyingKeyLen> VerifyingKey<P> {
    /// Serialize the verifying key to a new stack-allocated array
    ///
    /// This clones the underlying fields
    pub fn to_bytes(&self) -> Array<u8, P::VkLen> {
        let mut bytes = Array::<u8, P::VkLen>::default();
        debug_assert!(P::N::USIZE * 2 == P::VkLen::USIZE);
        bytes[..P::N::USIZE].copy_from_slice(&self.pk_seed.0);
        bytes[P::N::USIZE..].copy_from_slice(&self.pk_root);
        bytes
    }

    /// Serialize the verifying key to a new heap-allocated vector
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl<P: ParameterSet> Clone for VerifyingKey<P> {
    fn clone(&self) -> Self {
        VerifyingKey {
            pk_seed: self.pk_seed.clone(),
            pk_root: self.pk_root.clone(),
        }
    }
}

impl<P: ParameterSet> From<&VerifyingKey<P>> for Array<u8, P::VkLen> {
    fn from(vk: &VerifyingKey<P>) -> Array<u8, P::VkLen> {
        vk.to_bytes()
    }
}

impl<P: ParameterSet> From<Array<u8, P::VkLen>> for VerifyingKey<P> {
    fn from(bytes: Array<u8, P::VkLen>) -> VerifyingKey<P> {
        debug_assert!(P::VkLen::USIZE == 2 * P::N::USIZE);
        let pk_seed = PkSeed(Array::clone_from_slice(&bytes[..P::N::USIZE]));
        let pk_root = Array::clone_from_slice(&bytes[P::N::USIZE..]);
        VerifyingKey { pk_seed, pk_root }
    }
}

impl<P: ParameterSet> TryFrom<&[u8]> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::N::USIZE * 2 {
            return Err(Error::new());
        }
        let pk_seed = PkSeed(Array::clone_from_slice(&bytes[..P::N::USIZE]));
        let pk_root = Array::clone_from_slice(&bytes[P::N::USIZE..]);
        Ok(VerifyingKey { pk_seed, pk_root })
    }
}

impl<P: ParameterSet> Verifier<Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), Error> {
        let pk_seed = &self.pk_seed;
        let randomizer = &signature.randomizer;
        let fors_sig = &signature.fors_sig;
        let ht_sig = &signature.ht_sig;

        let digest = P::h_msg(randomizer, pk_seed, &self.pk_root, msg);
        let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest);

        let adrs = ForsTree::new(idx_tree, idx_leaf);
        let fors_pk = P::fors_pk_from_sig(fors_sig, md, pk_seed, &adrs);
        P::ht_verify(&fors_pk, ht_sig, pk_seed, idx_tree, idx_leaf, &self.pk_root)
            .then_some(())
            .ok_or(Error::new())
    }
}

impl<M> VerifyingKeyLen for Sha2L1<U16, M> {
    type VkLen = U<32>;
}

impl<M> VerifyingKeyLen for Sha2L35<U24, M> {
    type VkLen = U<48>;
}
impl<M> VerifyingKeyLen for Sha2L35<U32, M> {
    type VkLen = U<64>;
}

impl<M> VerifyingKeyLen for Shake<U16, M> {
    type VkLen = U<32>;
}
impl<M> VerifyingKeyLen for Shake<U24, M> {
    type VkLen = U<48>;
}
impl<M> VerifyingKeyLen for Shake<U32, M> {
    type VkLen = U<64>;
}

#[cfg(test)]
mod tests {
    use crate::*;
    use hybrid_array::Array;
    use signature::*;
    #[test]
    fn test_vk_serialize_deserialize() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();
        let vk_bytes: Array<u8, _> = (&vk).into();
        let vk2 = VerifyingKey::<Shake128f>::try_from(vk_bytes.as_slice()).unwrap();
        assert_eq!(vk, vk2);
    }
}
