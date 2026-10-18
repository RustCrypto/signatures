use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, XmssResult};
use crate::hash::{hash_message, prf, thash_h};
use crate::hash_address::*;
use crate::params::XmssParams;
use crate::utils::{bytes_to_ull, ull_to_bytes};
use crate::wots::wots_sign;
use crate::xmss_commons::{compute_root, gen_leaf_wots};

pub(crate) struct XmssState<'a> {
    auth_path: &'a mut [u8],
    kept_nodes: &'a mut [u8],
    precompute: &'a mut [u8],
    stack: &'a mut [u8],
    stack_heights: &'a mut [u32],
    stack_offset: &'a mut usize,
    next_leaf: &'a mut [u64],
    stack_usage: &'a mut [u32],
    completed: &'a mut [bool],
    cached_root_signature: &'a mut [u8],
}

/// One layer's BDS state; `XmssState` borrows it.
#[derive(Clone)]
struct StateStorage {
    auth_path: Vec<u8>,
    kept_nodes: Vec<u8>,
    precompute: Vec<u8>,
    stack: Vec<u8>,
    stack_heights: Vec<u32>,
    stack_offset: usize,
    next_leaf: Vec<u64>,
    stack_usage: Vec<u32>,
    completed: Vec<bool>,
    /// WOTS signature of the current root one layer below. Unused on layer 0.
    cached_root_signature: Vec<u8>,
}

/// BDS state for every layer.
#[derive(Clone)]
pub(crate) struct XmssStateStorage {
    layers: Vec<StateStorage>,
}

impl XmssStateStorage {
    pub(crate) fn new(params: &XmssParams) -> Self {
        Self {
            layers: (0..params.d).map(|_| StateStorage::new(params)).collect(),
        }
    }
}

impl StateStorage {
    fn new(params: &XmssParams) -> Self {
        let n = params.n as usize;
        let tree_height = params.tree_height as usize;
        Self {
            auth_path: vec![0u8; tree_height * n],
            kept_nodes: vec![0u8; tree_height * n],
            precompute: vec![0u8; tree_height * n],
            stack: vec![0u8; (tree_height + 1) * n],
            stack_heights: vec![0u32; tree_height + 1],
            stack_offset: 0,
            next_leaf: vec![0u64; tree_height],
            stack_usage: vec![0u32; tree_height],
            completed: vec![true; tree_height],
            cached_root_signature: vec![0u8; params.wots_sig_bytes as usize],
        }
    }

    fn state(&mut self) -> XmssState<'_> {
        XmssState {
            auth_path: &mut self.auth_path,
            kept_nodes: &mut self.kept_nodes,
            precompute: &mut self.precompute,
            stack: &mut self.stack,
            stack_heights: &mut self.stack_heights,
            stack_offset: &mut self.stack_offset,
            next_leaf: &mut self.next_leaf,
            stack_usage: &mut self.stack_usage,
            completed: &mut self.completed,
            cached_root_signature: &mut self.cached_root_signature,
        }
    }
}

impl Zeroize for StateStorage {
    fn zeroize(&mut self) {
        self.auth_path.zeroize();
        self.kept_nodes.zeroize();
        self.precompute.zeroize();
        self.stack.zeroize();
        self.cached_root_signature.zeroize();
    }
}

impl Zeroize for XmssStateStorage {
    fn zeroize(&mut self) {
        for layer in self.layers.iter_mut() {
            layer.zeroize();
        }
    }
}

/// For a given leaf index, computes the authentication path and the resulting
/// root node using Merkle's treehash algorithm.
fn treehash(
    params: &XmssParams,
    root: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_idx: u32,
    subtree_addr: &[u32; 8],
    xmss_state: &mut XmssState,
) -> XmssResult<()> {
    let n = params.n as usize;
    let tree_height = params.tree_height as usize;
    let mut stack = vec![0u8; (tree_height + 1) * n];
    let mut heights = vec![0u32; tree_height + 1];
    let mut offset: usize = 0;

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    copy_subtree_addr(&mut ots_addr, subtree_addr);
    copy_subtree_addr(&mut ltree_addr, subtree_addr);
    copy_subtree_addr(&mut node_addr, subtree_addr);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    let num_leaves: u32 = 1 << params.tree_height;
    for idx in 0..num_leaves {
        set_ltree_addr(&mut ltree_addr, idx);
        set_ots_addr(&mut ots_addr, idx);
        gen_leaf_wots(
            params,
            &mut stack[offset * n..(offset + 1) * n],
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;
        offset += 1;
        heights[offset - 1] = 0;

        if (leaf_idx ^ 0x1) == idx {
            xmss_state.auth_path[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        // Saving precompute future right nodes
        if idx == ((leaf_idx >> 1) << 1) + 3 {
            xmss_state.precompute[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        // kept: the old right node that bds_move would have saved.
        if idx == leaf_idx && leaf_idx & 3 == 1 {
            xmss_state.kept_nodes[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let tree_idx = idx >> (heights[offset - 1] + 1);

            set_tree_height(&mut node_addr, heights[offset - 1]);
            set_tree_index(&mut node_addr, tree_idx);
            let tmp = stack[(offset - 2) * n..offset * n].to_vec();
            thash_h(
                params,
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &tmp,
                pub_seed,
                &mut node_addr,
            )?;

            // The new parent is one height above its children.
            let parent_height = heights[offset - 1] + 1;
            let parent_height_idx = parent_height as usize;

            if tree_idx == ((leaf_idx >> (parent_height + 1)) << 1) + 3 {
                xmss_state.precompute[parent_height_idx * n..(parent_height_idx + 1) * n]
                    .copy_from_slice(&stack[(offset - 2) * n..(offset - 1) * n]);
            }

            if tree_idx == leaf_idx >> parent_height && tree_idx & 3 == 1 {
                xmss_state.kept_nodes[parent_height_idx * n..(parent_height_idx + 1) * n]
                    .copy_from_slice(&stack[(offset - 2) * n..(offset - 1) * n]);
            }

            offset -= 1;
            heights[offset - 1] += 1;

            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx {
                let h = heights[offset - 1] as usize;
                xmss_state.auth_path[h * n..(h + 1) * n]
                    .copy_from_slice(&stack[(offset - 1) * n..offset * n]);
            }
        }
    }
    root[..n].copy_from_slice(&stack[..n]);
    Ok(())
}

/// Runs up to `updates` job steps that build future right nodes into
/// `precompute`. Leaf indices span all trees of `layer`, so jobs can reach
/// into the next tree.
fn bds_precompute_future_nodes(
    params: &XmssParams,
    xmss_state: &mut XmssState,
    sk_seed: &[u8],
    pub_seed: &[u8],
    layer: u32,
    updates: usize,
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    set_layer_addr(&mut ots_addr, layer);
    set_layer_addr(&mut ltree_addr, layer);
    set_layer_addr(&mut node_addr, layer);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    // Pick the lowest height that needs to be precomputed as it is the most urgent
    let tree_height = params.tree_height as usize;
    for _ in 0..updates {
        let mut lowest_found_height = params.tree_height;
        let mut chosen_height = tree_height;
        for height in 0..params.tree_height {
            let height_idx = height as usize;
            if xmss_state.completed[height_idx] {
                continue;
            }

            let mut job_lowest_height = height;
            let job_stack_entries = xmss_state.stack_usage[height_idx] as usize;

            if job_stack_entries > 0 {
                job_lowest_height = params.tree_height;
                let stack_offset = *xmss_state.stack_offset;

                for stack_entry in stack_offset - job_stack_entries..stack_offset {
                    job_lowest_height =
                        job_lowest_height.min(xmss_state.stack_heights[stack_entry]);
                }
            }

            if job_lowest_height < lowest_found_height {
                lowest_found_height = job_lowest_height;
                chosen_height = height_idx;
            }
        }

        if chosen_height == tree_height {
            break;
        }

        // generate the needed node's next leaf, then merge it
        // with that height's own nodes on top of the shared stack.
        let job_leaf_idx = xmss_state.next_leaf[chosen_height];
        let job_tree = job_leaf_idx >> params.tree_height;
        #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
        let job_tree_leaf = (job_leaf_idx & ((1u64 << params.tree_height) - 1)) as u32;
        let mut job_node = vec![0u8; n];
        let mut job_node_height: u32 = 0;

        set_tree_addr(&mut ltree_addr, job_tree);
        set_tree_addr(&mut ots_addr, job_tree);
        set_tree_addr(&mut node_addr, job_tree);
        set_ltree_addr(&mut ltree_addr, job_tree_leaf);
        set_ots_addr(&mut ots_addr, job_tree_leaf);
        gen_leaf_wots(
            params,
            &mut job_node,
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;

        while xmss_state.stack_usage[chosen_height] > 0
            && xmss_state.stack_heights[*xmss_state.stack_offset - 1] == job_node_height
        {
            let top_entry = *xmss_state.stack_offset - 1;
            let mut pair = vec![0u8; 2 * n];
            pair[..n].copy_from_slice(&xmss_state.stack[top_entry * n..(top_entry + 1) * n]);
            pair[n..].copy_from_slice(&job_node);

            set_tree_height(&mut node_addr, job_node_height);
            set_tree_index(&mut node_addr, job_tree_leaf >> (job_node_height + 1));
            thash_h(params, &mut job_node, &pair, pub_seed, &mut node_addr)?;

            job_node_height += 1;
            xmss_state.stack_usage[chosen_height] -= 1;
            *xmss_state.stack_offset -= 1;
        }

        if job_node_height as usize == chosen_height {
            // Finished: this is the next right node for this height.
            xmss_state.precompute[chosen_height * n..(chosen_height + 1) * n]
                .copy_from_slice(&job_node);
            xmss_state.completed[chosen_height] = true;
        } else {
            // Not finished: leave the node on the stack for a later step.
            let new_entry = *xmss_state.stack_offset;
            xmss_state.stack[new_entry * n..(new_entry + 1) * n].copy_from_slice(&job_node);
            xmss_state.stack_heights[new_entry] = job_node_height;
            *xmss_state.stack_offset += 1;
            xmss_state.stack_usage[chosen_height] += 1;
            xmss_state.next_leaf[chosen_height] += 1;
        }
    }

    Ok(())
}

/// Moves `layer`'s state to `leaf_idx`, indexed across all trees of the layer.
fn bds_move(
    params: &XmssParams,
    xmss_state: &mut XmssState,
    sk_seed: &[u8],
    pub_seed: &[u8],
    layer: u32,
    leaf_idx: u64,
) -> XmssResult<()> {
    let n = params.n as usize;
    let tree_height = params.tree_height as usize;
    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    set_layer_addr(&mut ots_addr, layer);
    set_layer_addr(&mut ltree_addr, layer);
    set_layer_addr(&mut node_addr, layer);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    bds_precompute_future_nodes(
        params,
        xmss_state,
        sk_seed,
        pub_seed,
        layer,
        tree_height.div_ceil(2),
    )?;
    let auth_path = &mut xmss_state.auth_path;

    // Lowest height whose auth node changes when moving to leaf_idx. It becomes
    // a left node; every height below it gets a new right node. 
    let changed_height = leaf_idx.trailing_zeros().min(params.tree_height);
    let changed_height_idx = changed_height as usize;

    // The new left node is built from the auth node and the kept node one
    // height below. Read them before either is overwritten.
    let mut left_pair = vec![0u8; 2 * n];
    if changed_height_idx > 0 && changed_height_idx < tree_height {
        left_pair[..n]
            .copy_from_slice(&auth_path[(changed_height_idx - 1) * n..changed_height_idx * n]);
        left_pair[n..].copy_from_slice(
            &xmss_state.kept_nodes[(changed_height_idx - 1) * n..changed_height_idx * n],
        );
    }

    // keep the current right node being replaced.
    // It will be needed to make the left node one height up
    if (leaf_idx >> (changed_height + 1)) & 1 == 0 && changed_height_idx < tree_height - 1 {
        xmss_state.kept_nodes[changed_height_idx * n..(changed_height_idx + 1) * n]
            .copy_from_slice(&auth_path[changed_height_idx * n..(changed_height_idx + 1) * n]);
    }

    // The leaf just signed.
    let prev_leaf_idx = leaf_idx - 1;
    let prev_tree = prev_leaf_idx >> params.tree_height;
    #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
    let prev_tree_leaf = (prev_leaf_idx & ((1u64 << params.tree_height) - 1)) as u32;
    set_tree_addr(&mut ltree_addr, prev_tree);
    set_tree_addr(&mut ots_addr, prev_tree);
    set_tree_addr(&mut node_addr, prev_tree);

    if leaf_idx % 2 != 0 {
        let mut prev_leaf = vec![0u8; n];

        set_ltree_addr(&mut ltree_addr, prev_tree_leaf);
        set_ots_addr(&mut ots_addr, prev_tree_leaf);
        gen_leaf_wots(
            params,
            &mut prev_leaf,
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;

        auth_path[..n].copy_from_slice(&prev_leaf);

        return Ok(());
    }

    // The new left node at changed_height covers the leaves just signed.
    if changed_height_idx < tree_height {
        set_tree_height(&mut node_addr, changed_height - 1);
        set_tree_index(&mut node_addr, prev_tree_leaf >> changed_height);
        thash_h(
            params,
            &mut auth_path[changed_height_idx * n..(changed_height_idx + 1) * n],
            &left_pair,
            pub_seed,
            &mut node_addr,
        )?;
    }

    // Every height below changed_height takes its next right node from precompute.
    for height_idx in 0..changed_height_idx {
        auth_path[height_idx * n..(height_idx + 1) * n]
            .copy_from_slice(&xmss_state.precompute[height_idx * n..(height_idx + 1) * n]);
    }

    // Set up the precompute data for next turn
    let num_leaves: u64 = 1 << (params.full_height - params.tree_height * layer);
    for height in 0..params.tree_height {
        let node_leaves: u64 = 1 << height;

        // step j at auth path only changes if current node is the first leaf
        // of the subtree j+1
        if leaf_idx == 0 || leaf_idx % (2 * node_leaves) != 0 {
            break;
        }

        // leaf_idx is under node (leaf_idx >> height) at this height, and its
        // right sibling (leaf_idx >> height) + 1 is the auth node now. The next
        // right node this height needs is 2 nodes further down the same level
        // i.e. node (leaf_idx >> height) + 3.
        let next_right_idx = (leaf_idx >> height) + 3;
        let job_first_leaf = next_right_idx * node_leaves;

        if job_first_leaf >= num_leaves {
            continue;
        }

        // Start building that node from its first leaf.
        let height_idx = height as usize;
        xmss_state.next_leaf[height_idx] = job_first_leaf;
        xmss_state.stack_usage[height_idx] = 0;
        xmss_state.completed[height_idx] = false;
    }

    Ok(())
}

/// Builds `layer`'s state at `leaf_idx` and writes its tree's root to `root`.
fn bds_init(
    params: &XmssParams,
    root: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    layer: u32,
    leaf_idx: u64,
    xmss_state: &mut XmssState,
) -> XmssResult<()> {
    let tree_idx = leaf_idx >> params.tree_height;
    #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
    let tree_leaf = (leaf_idx & ((1u64 << params.tree_height) - 1)) as u32;
    let mut subtree_addr = [0u32; 8];
    set_layer_addr(&mut subtree_addr, layer);
    set_tree_addr(&mut subtree_addr, tree_idx);

    // No precompute jobs are running and the shared stack is empty.
    *xmss_state.stack_offset = 0;
    xmss_state.stack_usage.fill(0);
    xmss_state.completed.fill(true);

    treehash(
        params,
        root,
        sk_seed,
        pub_seed,
        tree_leaf,
        &subtree_addr,
        xmss_state,
    )?;

    // Next right nodes in the next tree: run their jobs to completion.
    let num_leaves: u64 = 1 << (params.full_height - params.tree_height * layer);
    for height in 0..params.tree_height {
        let next_right_first_leaf = (u64::from(tree_leaf >> (height + 1)) * 2 + 3) << height;
        let job_first_leaf = (tree_idx << params.tree_height) + next_right_first_leaf;
        if next_right_first_leaf < 1 << params.tree_height || job_first_leaf >= num_leaves {
            continue;
        }

        let height_idx = height as usize;
        xmss_state.next_leaf[height_idx] = job_first_leaf;
        xmss_state.completed[height_idx] = false;
    }
    bds_precompute_future_nodes(params, xmss_state, sk_seed, pub_seed, layer, usize::MAX)
}

/// WOTS-signs `root` with `layer`'s leaf at `leaf_idx`.
fn layer_wots_sign(
    params: &XmssParams,
    wots_sig: &mut [u8],
    root: &[u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    layer: u32,
    leaf_idx: u64,
) -> XmssResult<()> {
    let mut ots_addr = [0u32; 8];
    #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
    let tree_leaf = (leaf_idx & ((1u64 << params.tree_height) - 1)) as u32;

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_layer_addr(&mut ots_addr, layer);
    set_tree_addr(&mut ots_addr, leaf_idx >> params.tree_height);
    set_ots_addr(&mut ots_addr, tree_leaf);

    wots_sign(params, wots_sig, root, sk_seed, pub_seed, &mut ots_addr)
}

/// Root of `layer`'s current tree, from the leaf at `leaf_idx` and its auth path.
fn layer_root(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &[u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    layer: u32,
    leaf_idx: u64,
) -> XmssResult<()> {
    let n = params.n as usize;
    let tree_idx = leaf_idx >> params.tree_height;
    #[allow(clippy::cast_possible_truncation)] // masked to tree_height bits, always fits u32
    let tree_leaf = (leaf_idx & ((1u64 << params.tree_height) - 1)) as u32;
    let mut leaf = vec![0u8; n];
    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    set_layer_addr(&mut ots_addr, layer);
    set_layer_addr(&mut ltree_addr, layer);
    set_layer_addr(&mut node_addr, layer);

    set_tree_addr(&mut ots_addr, tree_idx);
    set_tree_addr(&mut ltree_addr, tree_idx);
    set_tree_addr(&mut node_addr, tree_idx);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    set_ots_addr(&mut ots_addr, tree_leaf);
    set_ltree_addr(&mut ltree_addr, tree_leaf);

    gen_leaf_wots(
        params,
        &mut leaf,
        sk_seed,
        pub_seed,
        &mut ltree_addr,
        &mut ots_addr,
    )?;
    compute_root(
        params,
        root,
        &leaf,
        tree_leaf,
        auth_path,
        pub_seed,
        &mut node_addr,
    )
}

/// Builds every layer's state for `idx`. `root` ends as the top tree's root.
fn bds_init_layers(
    params: &XmssParams,
    root: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    idx: u64,
    storage: &mut XmssStateStorage,
) -> XmssResult<()> {
    for layer in 0..params.d {
        let leaf_idx = idx >> (params.tree_height * layer);
        let mut layer_state = storage.layers[layer as usize].state();

        // root is the root one layer below.
        if layer > 0 {
            layer_wots_sign(
                params,
                layer_state.cached_root_signature,
                root,
                sk_seed,
                pub_seed,
                layer,
                leaf_idx,
            )?;
        }
        bds_init(
            params,
            root,
            sk_seed,
            pub_seed,
            layer,
            leaf_idx,
            &mut layer_state,
        )?;
    }
    Ok(())
}

/// Given a set of parameters, this function returns the size of the secret key.
pub fn xmss_xmssmt_core_sk_bytes(params: &XmssParams) -> u64 {
    params.index_bytes as u64 + 4 * params.n as u64
}

/// Derives a XMSSMT key pair from a given seed.
/// Seed must be 3*n long.
/// Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
/// Format pk: [root || PUB_SEED] omitting algorithm OID.
pub fn xmssmt_core_seed_keypair(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8],
    storage: &mut XmssStateStorage,
) -> XmssResult<()> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;

    for b in sk[..idx_bytes].iter_mut() {
        *b = 0;
    }

    sk[idx_bytes..idx_bytes + 2 * n].copy_from_slice(&seed[..2 * n]);

    sk[idx_bytes + 3 * n..idx_bytes + 4 * n].copy_from_slice(&seed[2 * n..3 * n]);
    pk[n..2 * n].copy_from_slice(&sk[idx_bytes + 3 * n..idx_bytes + 4 * n]);

    // Copy pub_seed since pk is mutably borrowed by treehash.
    let pub_seed_copy = pk[n..2 * n].to_vec();
    bds_init_layers(
        params,
        &mut pk[..n],
        &sk[idx_bytes..idx_bytes + n],
        &pub_seed_copy,
        0,
        storage,
    )?;
    sk[idx_bytes + 2 * n..idx_bytes + 3 * n].copy_from_slice(&pk[..n]);

    Ok(())
}

/// Generates a XMSSMT key pair for a given parameter set.
/// Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
/// Format pk: [root || PUB_SEED] omitting algorithm OID.
pub fn xmssmt_core_keypair<R: rand::CryptoRng>(
    params: &XmssParams,
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    storage: &mut XmssStateStorage,
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut seed = vec![0u8; 3 * n];

    rng.fill_bytes(&mut seed[..]);
    let result = xmssmt_core_seed_keypair(params, pk, sk, &seed, storage);
    seed.zeroize();
    result
}

/// Rebuilds the BDS state for the key's current index, for a signing key
/// that was loaded from bytes. Costs one tree build per layer, like keygen.
pub fn xmssmt_core_restore_state(
    params: &XmssParams,
    sk: &[u8],
    storage: &mut XmssStateStorage,
) -> XmssResult<()> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let idx = bytes_to_ull(&sk[..idx_bytes]);
    let max_idx = if params.full_height >= 64 {
        u64::MAX
    } else {
        (1u64 << params.full_height) - 1
    };

    // An exhausted key has nothing left to sign.
    if idx > max_idx {
        return Ok(());
    }

    let mut root = vec![0u8; n];
    bds_init_layers(
        params,
        &mut root,
        &sk[idx_bytes..idx_bytes + n],
        &sk[idx_bytes + 3 * n..idx_bytes + 4 * n],
        idx,
        storage,
    )
}

/// Signs a message. Returns the signature followed by the message
/// and an updated secret key.
pub fn xmssmt_core_sign(
    params: &XmssParams,
    sk: &mut [u8],
    m: &[u8],
    storage: &mut XmssStateStorage,
) -> XmssResult<Vec<u8>> {
    let n = params.n as usize;
    let idx_bytes = params.index_bytes as usize;
    let mlen = m.len();
    let sig_bytes = params.sig_bytes as usize;

    let sk_seed_start = idx_bytes;
    let sk_prf_start = idx_bytes + n;
    let pub_root_start = idx_bytes + 2 * n;
    let pub_seed_start = idx_bytes + 3 * n;

    let idx = bytes_to_ull(&sk[..idx_bytes]);

    // Check if key is exhausted before doing anything.
    let max_idx = if params.full_height >= 64 {
        u64::MAX
    } else {
        (1u64 << params.full_height) - 1
    };

    if idx > max_idx {
        return Err(Error::KeyExhausted);
    }

    // Copy secret values out before mutating sk. Wiped on drop, on every path.
    let sk_seed = Zeroizing::new(sk[sk_seed_start..sk_seed_start + n].to_vec());
    let sk_prf = Zeroizing::new(sk[sk_prf_start..sk_prf_start + n].to_vec());
    let pub_root = sk[pub_root_start..pub_root_start + n].to_vec();
    let pub_seed = sk[pub_seed_start..pub_seed_start + n].to_vec();

    let mut sm = vec![0u8; sig_bytes + mlen];

    sm[sig_bytes..].copy_from_slice(m);

    // Write index into signature.
    sm[..idx_bytes].copy_from_slice(&sk[..idx_bytes]);

    // Compute R (randomness for message hashing).
    let mut idx_bytes_32 = [0u8; 32];
    ull_to_bytes(&mut idx_bytes_32, idx);
    prf(
        params,
        &mut sm[idx_bytes..idx_bytes + n],
        &idx_bytes_32,
        &sk_prf,
    )?;

    let mut root = vec![0u8; n];
    let prefix_len = params.padding_len as usize + 3 * n;
    let prefix_start = sig_bytes - prefix_len;
    // Copy R out to avoid borrow conflict (sm is both read for R and mutated for prefix).
    let r_val = sm[idx_bytes..idx_bytes + n].to_vec();
    hash_message(
        params,
        &mut root,
        &r_val,
        &pub_root,
        idx,
        &mut sm[prefix_start..],
        mlen as u64,
    )?;

    let mut sm_offset = idx_bytes + n;
    let wots_sig_bytes = params.wots_sig_bytes as usize;
    let auth_bytes = params.tree_height as usize * n;

    for layer in 0..params.d {
        let layer_storage = &storage.layers[layer as usize];

        if layer == 0 {
            // Layer 0 signs the message digest.
            layer_wots_sign(
                params,
                &mut sm[sm_offset..],
                &root,
                &sk_seed,
                &pub_seed,
                0,
                idx,
            )?;
        } else {
            // Cached: the root below only changes with its tree.
            sm[sm_offset..sm_offset + wots_sig_bytes]
                .copy_from_slice(&layer_storage.cached_root_signature);
        }
        sm_offset += wots_sig_bytes;

        // The signature carries the auth path of the current leaf.
        sm[sm_offset..sm_offset + auth_bytes].copy_from_slice(&layer_storage.auth_path);
        sm_offset += auth_bytes;
    }

    // Move the state to the next leaf, ready for the next signature.
    // A layer moves only when the layer below starts a new tree.
    if idx < max_idx {
        let next_idx = idx + 1;
        let mut root_below = vec![0u8; n];
        // Moved on a copy, so a failure leaves the state unchanged.
        let mut next_storage = storage.clone();

        for layer in 0..params.d {
            let leaf_idx = next_idx >> (params.tree_height * layer);
            let mut layer_state = next_storage.layers[layer as usize].state();

            bds_move(
                params,
                &mut layer_state,
                &sk_seed,
                &pub_seed,
                layer,
                leaf_idx,
            )?;

            if layer > 0 {
                layer_wots_sign(
                    params,
                    layer_state.cached_root_signature,
                    &root_below,
                    &sk_seed,
                    &pub_seed,
                    layer,
                    leaf_idx,
                )?;
            }

            if layer + 1 == params.d || leaf_idx & ((1u64 << params.tree_height) - 1) != 0 {
                break;
            }
            
            layer_root(
                params,
                &mut root_below,
                layer_state.auth_path,
                &sk_seed,
                &pub_seed,
                layer,
                leaf_idx,
            )?;
        }
        *storage = next_storage;
    }

    // Nothing below can fail, so the key only changes on success.
    // Advance the index in sk.
    if idx == max_idx {
        // Last valid index — mark as exhausted for next call.
        for b in sk[..idx_bytes].iter_mut() {
            *b = 0xFF;
        }
    } else {
        ull_to_bytes(&mut sk[..idx_bytes], idx + 1);
    }

    // If this was the last valid index, zero the secret key material in sk.
    if idx == max_idx {
        #[allow(clippy::cast_possible_truncation)]
        let sk_bytes_len = params.sk_bytes as usize;
        for b in sk[idx_bytes..sk_bytes_len].iter_mut() {
            *b = 0;
        }
    }

    Ok(sm)
}
