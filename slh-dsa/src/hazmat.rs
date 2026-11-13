//! Hazardous-materials access to FIPS 205 components: the XMSS layer
//! (Algorithms 9–11, with WOTS+ at its leaves) and the message hashes
//! `PRF_msg` and `H_msg`, for building other schemes on them.
//!
//! These functions are not SLH-DSA, and using them safely is the caller's
//! responsibility:
//!
//! - A WOTS+ key pair (an XMSS leaf) must never sign two different messages.
//! - Never pass the seeds of an SLH-DSA [`SigningKey`](crate::SigningKey):
//!   its hypertree's XMSS leaves are the same WOTS+ key pairs, so signing with
//!   them here reuses keys that SLH-DSA signing also uses, and breaks the
//!   SLH-DSA key.
//!
//! With the `zeroize` feature, the copies of `SK.seed` and `SK.prf` made here
//! are cleared after use. A slice of the wrong length is a caller bug and
//! panics, except for the signature passed to [`xmss_pk_from_sig`], which
//! may come from anyone and is rejected with an error.

use hybrid_array::{Array, ArraySize};
use typenum::Unsigned;

use signature::Error;

use crate::{ParameterSet, PkSeed, SkPrf, SkSeed, address::WotsHash, xmss::XmssSig};

/// Hash length `n`, in bytes.
#[must_use]
pub fn n<P: ParameterSet>() -> usize {
    P::N::USIZE
}

/// Length of the `H_msg` output `m`, in bytes.
#[must_use]
pub fn m<P: ParameterSet>() -> usize {
    P::M::USIZE
}

/// XMSS tree height `h'`; a tree has `2^h'` leaves.
#[must_use]
pub fn tree_height<P: ParameterSet>() -> u32 {
    P::HPrime::U32
}

/// Length of an XMSS signature (WOTS+ signature, then authentication path), in bytes.
#[must_use]
pub fn xmss_sig_len<P: ParameterSet>() -> usize {
    XmssSig::<P>::SIZE
}

/// Root of the XMSS tree at `layer` and `tree` (FIPS 205 Algorithm 9 at height `h'`).
///
/// `sk_seed`, `pk_seed` and `root` are `n` bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn xmss_root<P: ParameterSet>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    root: &mut [u8],
) {
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let mut sk_seed = SkSeed(array(sk_seed));
    let node = suite.xmss_node(&sk_seed, 0, P::HPrime::U32, &adrs(layer, tree));
    wipe(&mut sk_seed.0);
    root.copy_from_slice(&node);
}

/// Signs the `n`-byte `msg` with leaf `idx` of the XMSS tree at `layer` and `tree`
/// (FIPS 205 Algorithm 10).
///
/// `sk_seed` and `pk_seed` are `n` bytes, `sig` is [`xmss_sig_len`] bytes, and `idx` is below
/// `2^h'`.
///
/// # Panics
///
/// If a slice has the wrong length, or `idx` is out of range.
pub fn xmss_sign<P: ParameterSet>(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    idx: u32,
    sig: &mut [u8],
) {
    assert!(idx < 1 << P::HPrime::U32, "XMSS leaf index out of range");
    assert_eq!(
        sig.len(),
        xmss_sig_len::<P>(),
        "XMSS signature length mismatch"
    );
    let msg = array(msg);
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let mut sk_seed = SkSeed(array(sk_seed));
    let xmss_sig = suite.xmss_sign(&msg, &sk_seed, idx, &adrs(layer, tree));
    wipe(&mut sk_seed.0);
    xmss_sig.write_to(sig);
}

/// Writes to `root` the XMSS root implied by `sig` over the `n`-byte `msg` at leaf `idx` of
/// the tree at `layer` and `tree` (FIPS 205 Algorithm 11). A signature is valid if this equals
/// the tree's root.
///
/// `pk_seed` and `root` are `n` bytes.
///
/// # Errors
///
/// If `sig` is not [`xmss_sig_len`] bytes or `idx` is not below `2^h'`, leaving `root`
/// unchanged.
///
/// # Panics
///
/// If `msg`, `pk_seed` or `root` has the wrong length.
pub fn xmss_pk_from_sig<P: ParameterSet>(
    idx: u32,
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    root: &mut [u8],
) -> Result<(), Error> {
    if idx >= 1 << P::HPrime::U32 {
        return Err(Error::new());
    }
    let xmss_sig = XmssSig::<P>::try_from(sig).map_err(|()| Error::new())?;
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let node = suite.xmss_pk_from_sig(idx, &xmss_sig, &array(msg), &adrs(layer, tree));
    root.copy_from_slice(&node);
    Ok(())
}

/// `PRF_msg(SK.prf, opt_rand, msg)`, the randomizer `R` (FIPS 205 §4.1).
///
/// `sk_prf`, `opt_rand` and `out` are `n` bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn prf_msg<P: ParameterSet>(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]) {
    let opt_rand = array(opt_rand);
    let mut sk_prf = SkPrf(array(sk_prf));
    let r = P::prf_msg(&sk_prf, &opt_rand, &[&[msg]]);
    wipe(&mut sk_prf.0);
    out.copy_from_slice(&r);
}

/// `H_msg(R, PK.seed, PK.root, msg)` (FIPS 205 §4.1).
///
/// `r`, `pk_seed` and `pk_root` are `n` bytes, and `out` is [`m`] bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn h_msg<P: ParameterSet>(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let digest = P::h_msg(
        &array(r),
        &PkSeed(array(pk_seed)),
        &array(pk_root),
        &[&[msg]],
    );
    out.copy_from_slice(&digest);
}

fn adrs(layer: u32, tree: u64) -> WotsHash {
    let mut adrs = WotsHash::default();
    adrs.layer_adrs.set(layer);
    adrs.tree_adrs_low.set(tree);
    adrs
}

/// Clears a secret copy (with the `zeroize` feature).
#[cfg(feature = "zeroize")]
fn wipe<N: ArraySize>(secret: &mut Array<u8, N>) {
    zeroize::Zeroize::zeroize(secret);
}

#[cfg(not(feature = "zeroize"))]
fn wipe<N: ArraySize>(_secret: &mut Array<u8, N>) {}

fn array<N: ArraySize>(bytes: &[u8]) -> Array<u8, N> {
    Array::try_from(bytes).expect("length mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha2_128f, SigningKey};
    use hex_literal::hex;
    use hybrid_array::typenum::Unsigned;

    type P = Sha2_128f;

    const SK_SEED: [u8; 16] = [1; 16];
    const SK_PRF: [u8; 16] = [2; 16];
    const PK_SEED: [u8; 16] = [3; 16];

    #[test]
    fn sizes_match_sha2_128f() {
        assert_eq!(n::<P>(), 16);
        assert_eq!(m::<P>(), 34);
        assert_eq!(tree_height::<P>(), 3);
        assert_eq!(xmss_sig_len::<P>(), 35 * 16 + 3 * 16);
    }

    /// The top-layer tree's root is SLH-DSA's public root.
    #[test]
    fn top_layer_root_is_the_slh_dsa_root() {
        let sk = SigningKey::<P>::slh_keygen_internal(&SK_SEED, &SK_PRF, &PK_SEED);
        let vk = sk.as_ref().to_bytes();
        let top = <P as crate::hypertree::HypertreeParams>::D::U32 - 1;
        let mut root = [0; 16];
        xmss_root::<P>(&SK_SEED, &PK_SEED, top, 0, &mut root);
        assert_eq!(&vk[..16], &PK_SEED);
        assert_eq!(&vk[16..], &root);
    }

    #[test]
    fn every_leaf_signs_and_verifies() {
        let mut root = [0; 16];
        xmss_root::<P>(&SK_SEED, &PK_SEED, 0, 0, &mut root);
        let msg = [7; 16];
        for idx in 0..8 {
            let mut sig = [0; 35 * 16 + 3 * 16];
            xmss_sign::<P>(&msg, &SK_SEED, &PK_SEED, 0, 0, idx, &mut sig);
            let mut recovered = [0; 16];
            xmss_pk_from_sig::<P>(idx, &sig, &msg, &PK_SEED, 0, 0, &mut recovered).unwrap();
            assert_eq!(recovered, root);

            let mut wrong = [0; 16];
            xmss_pk_from_sig::<P>(idx, &sig, &[8; 16], &PK_SEED, 0, 0, &mut wrong).unwrap();
            assert_ne!(wrong, root);

            let mut other_leaf = [0; 16];
            xmss_pk_from_sig::<P>(idx ^ 1, &sig, &msg, &PK_SEED, 0, 0, &mut other_leaf).unwrap();
            assert_ne!(other_leaf, root);
        }
    }

    /// Same vectors as the `xmss` tests (generated by slh-dsa-py).
    #[test]
    fn xmss_matches_the_reference_vectors() {
        type S = crate::Shake128f;
        let mut root = [0; 16];
        xmss_root::<S>(&[1; 16], &[2; 16], 0, 0, &mut root);
        assert_eq!(root, hex!("94e24679fb2460b97332db131c38bec9"));

        let mut sig = [0; 35 * 16 + 3 * 16];
        xmss_sign::<S>(&[3; 16], &[1; 16], &[2; 16], 0, 0, 3, &mut sig);
        let expected = hex!(
            "
        a77a0b07e558b023f653a954d886ac66ded67b313f9db7fd93da00686be66a3f
        2e2d3e841292bf5a4060d88509e9a2a51e0bbae6835482bceabce76c5653546d
        08c2f5f78e7491f755f35380d965598891131bdd4c57df2397eed8062a1038fb
        10c758bb30c6ea3859db4eb6296269d170d86cc67804dc63a61e5f30af709aad
        2407624eb81549e87c326c2a646c2b995dfad81cc007286b6f50b56f61352fa2
        752a30aa4f63cc367a7a1c57140a086cc43387ce5f530d84538d0c503d051be2
        9c0040486c2953d34e3817bfcb6f198e545476ddd93930af48333b4e7e0eba03
        3bdbc1badca23875d2f4345699075558a68c8f53865c0b2151208a7a5a4b0c7d
        270b71d5688c6d727525e3fd9c75b9656e13394777faee925fe8cda6e2b7c52a
        684f218679a48b942127f89ffaa069db21659a09266e9304ce870c16094bf585
        6ed93c0748b9479a95d4309c74c2da26b2cf2e5f2090f02601b80c3373b14666
        f0bd973d10c7eb649966d1ffd3e87979899812fef1e23f5703a99924001d9ba9
        522ea93575ad20143eeeeff77b8d192870932b1583459271f634a65441fe1907
        370f71e4d9312b930a66e1b85cba8f4a404c703c7c38ada5c6b95824c2c0ff87
        b1e3f258189d949430c516d2c2192ffbb8d687b10228d7ecf47f86c1299825a8
        b6ee7c560f4bd1720aabdca41c8a5569e9917f906efca17d5f080e65e5a16386
        c9bb4f1ad49404340df212e94d77ff5a25b8649b725e1993dc66f37a89058499
        107bb57a4f699688406e89a44776b95bd1af01290496fb4f3abba58eb407eff9
        c1dfd1362d169170f8b7364c6aa8e6507f049484e5d9b934e86d61b1d3155b5a"
        );
        assert_eq!(sig, expected);
    }

    #[test]
    #[should_panic(expected = "XMSS leaf index out of range")]
    fn leaf_index_out_of_range_panics() {
        let mut sig = [0; 35 * 16 + 3 * 16];
        xmss_sign::<P>(&[0; 16], &SK_SEED, &PK_SEED, 0, 0, 8, &mut sig);
    }

    #[test]
    #[should_panic(expected = "XMSS signature length mismatch")]
    fn signing_into_a_short_buffer_panics() {
        let mut sig = [0; 35 * 16 + 3 * 16 - 1];
        xmss_sign::<P>(&[0; 16], &SK_SEED, &PK_SEED, 0, 0, 0, &mut sig);
    }

    #[test]
    #[should_panic(expected = "XMSS signature length mismatch")]
    fn signing_into_a_long_buffer_panics() {
        let mut sig = [0; 35 * 16 + 3 * 16 + 1];
        xmss_sign::<P>(&[0; 16], &SK_SEED, &PK_SEED, 0, 0, 0, &mut sig);
    }

    #[test]
    fn a_malformed_signature_is_an_error() {
        let mut sig = [0; 35 * 16 + 3 * 16];
        xmss_sign::<P>(&[0; 16], &SK_SEED, &PK_SEED, 0, 0, 0, &mut sig);
        let mut root = [9; 16];
        for bad_len in [0, sig.len() - 1, sig.len() + 1] {
            let bad = [0; 35 * 16 + 3 * 16 + 1];
            assert!(
                xmss_pk_from_sig::<P>(0, &bad[..bad_len], &[0; 16], &PK_SEED, 0, 0, &mut root)
                    .is_err()
            );
        }
        assert!(xmss_pk_from_sig::<P>(8, &sig, &[0; 16], &PK_SEED, 0, 0, &mut root).is_err());
        assert!(
            xmss_pk_from_sig::<P>(u32::MAX, &sig, &[0; 16], &PK_SEED, 0, 0, &mut root).is_err()
        );
        assert_eq!(root, [9; 16]);
    }

    /// Same vectors as the `hashes` tests.
    #[test]
    fn message_hashes_match_the_suite() {
        let mut r = [0; 16];
        prf_msg::<P>(&[0; 16], &[1; 16], &[2; 32], &mut r);
        assert_eq!(r, hex!("6a4b5cf23911d4f3a6591d7003445316"));

        let mut digest = [0; 34];
        h_msg::<P>(&[0; 16], &[1; 16], &[2; 16], &[3; 32], &mut digest);
        assert_eq!(
            digest,
            hex!("56658221f675d907a309255e8faef639d11e6a1118fa05d3bbd26179a7e0a54a7f5b")
        );
    }
}
