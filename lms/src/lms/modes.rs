//! LMS modes
use crate::ots::modes::LmsOtsMode;
use crate::types::Typecode;
use digest::Digest;
use digest::Output;
use generic_array::ArrayLength;
use std::ops::Add;
use std::{
    marker::PhantomData,
    ops::{Shl, Sub},
};
use typenum::{bit::B1, Add1, Shleft, Sub1, U1, U10, U15, U20, U25, U5};

/// The basic trait that must be implemented for any valid LMS mode
pub trait LmsMode: Typecode + Clone {
    /// The underlying hash function
    type Hasher: Digest;
    /// The underlying LM-OTS mode
    type OtsMode: LmsOtsMode;
    /// Length of the internal Merkle tree, computed as `2^(h+1)-1`
    type TreeLen: ArrayLength<Output<Self::Hasher>>;
    /// `h` as a type
    type HLen: ArrayLength<Output<Self::Hasher>>;
    /// The length of the hash function output as a type
    const M: usize;
    /// `h` as a [usize]
    const H: usize;
    /// The number of leaves as a [u32], computed as `2^h`
    const LEAVES: u32; // precomputed
    /// `TreeLen` as a [u32], `2^(h+1)-1`
    const TREE_NODES: u32; // precomputed
}

#[derive(Debug)]
pub struct LmsModeInternal<
    OtsMode: LmsOtsMode,
    Hasher: Digest,
    HLen: ArrayLength<Output<Hasher>>,
    const M: usize,
    const H: usize,
    const TC: u32,
> {
    _ots_mode: PhantomData<OtsMode>,
    _hasher: PhantomData<Hasher>,
    _h_len: PhantomData<HLen>,
}

impl<
        OtsMode: LmsOtsMode,
        Hasher: Digest,
        TreeLen: ArrayLength<Output<Hasher>>,
        const M: usize,
        const H: usize,
        const TC: u32,
    > Clone for LmsModeInternal<OtsMode, Hasher, TreeLen, M, H, TC>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
        OtsMode: LmsOtsMode,
        Hasher: Digest,
        TreeLen: ArrayLength<Output<Hasher>>,
        const M: usize,
        const H: usize,
        const TC: u32,
    > Copy for LmsModeInternal<OtsMode, Hasher, TreeLen, M, H, TC>
{
}

impl<
        OtsMode: LmsOtsMode,
        Hasher: Digest,
        HLen: ArrayLength<Output<Hasher>>,
        const M: usize,
        const H: usize,
        const TC: u32,
    > LmsMode for LmsModeInternal<OtsMode, Hasher, HLen, M, H, TC>
where
    HLen: Add<typenum::B1>,
    U1: Shl<<HLen as Add<B1>>::Output>,
    Shleft<U1, <HLen as Add<B1>>::Output>: Sub<B1>,
    Sub1<Shleft<U1, <HLen as Add<B1>>::Output>>: ArrayLength<Output<Hasher>>,
{
    type OtsMode = OtsMode;
    type Hasher = Hasher;
    type TreeLen = Sub1<Shleft<U1, Add1<HLen>>>;
    type HLen = HLen;
    const M: usize = M;
    const H: usize = H;
    const LEAVES: u32 = 1 << H; // precomputed as 2 to the H power
    const TREE_NODES: u32 = (1 << (H + 1)) - 1; // 2^(H+1)-1
}

impl<
        Hasher: Digest,
        OtsMode: LmsOtsMode,
        TreeLen: ArrayLength<Output<Hasher>>,
        const M: usize,
        const H: usize,
        const TC: u32,
    > Typecode for LmsModeInternal<OtsMode, Hasher, TreeLen, M, H, TC>
{
    const TYPECODE: u32 = TC;
}

/// LMS_SHA256_M32_H5
pub type LmsSha256M32H5<OtsMode> = LmsModeInternal<OtsMode, sha2::Sha256, U5, 32, 5, 5>;
/// LMS_SHA256_M32_H10
pub type LmsSha256M32H10<OtsMode> = LmsModeInternal<OtsMode, sha2::Sha256, U10, 32, 10, 6>;
/// LMS_SHA256_M32_H15
pub type LmsSha256M32H15<OtsMode> = LmsModeInternal<OtsMode, sha2::Sha256, U15, 32, 15, 7>;
/// LMS_SHA256_M32_H20
pub type LmsSha256M32H20<OtsMode> = LmsModeInternal<OtsMode, sha2::Sha256, U20, 32, 20, 8>;
/// LMS_SHA256_M32_H25
pub type LmsSha256M32H25<OtsMode> = LmsModeInternal<OtsMode, sha2::Sha256, U25, 32, 25, 9>;
