use subtle::ConstantTimeEq;

use crate::error::{Error, XmssResult};
use crate::hash::{hash_message, thash_h};
use crate::hash_address::*;
use crate::params::XmssParams;
use crate::utils::bytes_to_ull;
use crate::wots::{wots_pk_from_sig, wots_pkgen};

/// Computes a leaf node from a WOTS public key using an L-tree.
/// Note that this destroys the used WOTS public key.
fn l_tree(
    params: &XmssParams,
    leaf: &mut [u8],
    wots_pk: &mut [u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut l = params.wots_len as usize;
    let mut height: u32 = 0;

    set_tree_height(addr, height);

    while l > 1 {
        let parent_nodes = l >> 1;
        for i in 0..parent_nodes {
            #[allow(clippy::cast_possible_truncation)]
            set_tree_index(addr, i as u32);
            let mut tmp = vec![0u8; 2 * n];
            tmp.copy_from_slice(&wots_pk[i * 2 * n..(i * 2 + 2) * n]);
            thash_h(
                params,
                &mut wots_pk[i * n..(i + 1) * n],
                &tmp,
                pub_seed,
                addr,
            )?;
        }
        if l & 1 != 0 {
            let src_start = (l - 1) * n;
            let dst_start = (l >> 1) * n;
            let mut tmp = vec![0u8; n];
            tmp.copy_from_slice(&wots_pk[src_start..src_start + n]);
            wots_pk[dst_start..dst_start + n].copy_from_slice(&tmp);
            l = (l >> 1) + 1;
        } else {
            l >>= 1;
        }
        height += 1;
        set_tree_height(addr, height);
    }
    leaf[..n].copy_from_slice(&wots_pk[..n]);
    Ok(())
}

/// Computes a root node given a leaf and an auth path.
fn compute_root(
    params: &XmssParams,
    root: &mut [u8],
    leaf: &[u8],
    mut leafidx: u32,
    auth_path: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut buffer = vec![0u8; 2 * n];
    let mut auth_offset = 0usize;

    if leafidx & 1 != 0 {
        buffer[n..2 * n].copy_from_slice(&leaf[..n]);
        buffer[..n].copy_from_slice(&auth_path[..n]);
    } else {
        buffer[..n].copy_from_slice(&leaf[..n]);
        buffer[n..2 * n].copy_from_slice(&auth_path[..n]);
    }
    auth_offset += n;

    for i in 0..params.tree_height - 1 {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx);

        if leafidx & 1 != 0 {
            let tmp = buffer.clone();
            thash_h(params, &mut buffer[n..2 * n], &tmp, pub_seed, addr)?;
            buffer[..n].copy_from_slice(&auth_path[auth_offset..auth_offset + n]);
        } else {
            let tmp = buffer.clone();
            thash_h(params, &mut buffer[..n], &tmp, pub_seed, addr)?;
            buffer[n..2 * n].copy_from_slice(&auth_path[auth_offset..auth_offset + n]);
        }
        auth_offset += n;
    }

    set_tree_height(addr, params.tree_height - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx);
    thash_h(params, root, &buffer, pub_seed, addr)
}

/// Computes the leaf at a given address. First generates the WOTS key pair,
/// then computes leaf using l_tree.
pub fn gen_leaf_wots(
    params: &XmssParams,
    leaf: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    ltree_addr: &mut [u32; 8],
    ots_addr: &mut [u32; 8],
) -> XmssResult<()> {
    let mut pk = vec![0u8; params.wots_sig_bytes as usize];

    wots_pkgen(params, &mut pk, sk_seed, pub_seed, ots_addr)?;
    l_tree(params, leaf, &mut pk, pub_seed, ltree_addr)
}

/// Verifies a given message signature pair under a given public key.
/// Note that this assumes a pk without an OID, i.e. [root || PUB_SEED].
pub fn xmssmt_core_sign_open(
    params: &XmssParams,
    m: &mut Vec<u8>,
    sm: &[u8],
    pk: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let pub_root = &pk[..n];
    let pub_seed = &pk[n..2 * n];

    let smlen = sm.len();
    if smlen < params.sig_bytes as usize {
        return Err(Error::VerificationFailed);
    }
    let mlen = smlen - params.sig_bytes as usize;

    let mut wots_pk = vec![0u8; params.wots_sig_bytes as usize];
    let mut leaf = vec![0u8; n];
    let mut root = vec![0u8; n];

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    let idx = bytes_to_ull(&sm[..params.index_bytes as usize]);

    let prefix_len = params.padding_len as usize + 3 * n;
    m.resize(params.sig_bytes as usize + mlen, 0);
    m[params.sig_bytes as usize..].copy_from_slice(&sm[params.sig_bytes as usize..]);

    let mhash = &mut root;
    let prefix_start = params.sig_bytes as usize - prefix_len;
    hash_message(
        params,
        mhash,
        &sm[params.index_bytes as usize..],
        pk,
        idx,
        &mut m[prefix_start..],
        mlen as u64,
    )?;

    let mut sm_offset = params.index_bytes as usize + n;

    for i in 0..params.d {
        #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
        let idx_leaf =
            ((idx >> (params.tree_height * i)) & ((1u64 << params.tree_height) - 1)) as u32;
        let tree_idx = idx >> (params.tree_height * (i + 1));

        set_layer_addr(&mut ots_addr, i);
        set_layer_addr(&mut ltree_addr, i);
        set_layer_addr(&mut node_addr, i);

        set_tree_addr(&mut ltree_addr, tree_idx);
        set_tree_addr(&mut ots_addr, tree_idx);
        set_tree_addr(&mut node_addr, tree_idx);

        set_ots_addr(&mut ots_addr, idx_leaf);
        wots_pk_from_sig(
            params,
            &mut wots_pk,
            &sm[sm_offset..],
            &root,
            pub_seed,
            &mut ots_addr,
        )?;
        sm_offset += params.wots_sig_bytes as usize;

        set_ltree_addr(&mut ltree_addr, idx_leaf);
        l_tree(params, &mut leaf, &mut wots_pk, pub_seed, &mut ltree_addr)?;

        compute_root(
            params,
            &mut root,
            &leaf,
            idx_leaf,
            &sm[sm_offset..],
            pub_seed,
            &mut node_addr,
        )?;
        sm_offset += params.tree_height as usize * n;
    }

    if !bool::from(root.ct_eq(pub_root)) {
        m.clear();
        return Err(Error::VerificationFailed);
    }

    let msg = sm[params.sig_bytes as usize..].to_vec();
    *m = msg;

    Ok(())
}
