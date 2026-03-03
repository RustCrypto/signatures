pub const XMSS_ADDR_TYPE_OTS: u32 = 0;
pub const XMSS_ADDR_TYPE_LTREE: u32 = 1;
pub const XMSS_ADDR_TYPE_HASHTREE: u32 = 2;

#[inline]
pub fn set_layer_addr(addr: &mut [u32; 8], layer: u32) {
    addr[0] = layer;
}

#[inline]
pub fn set_tree_addr(addr: &mut [u32; 8], tree: u64) {
    addr[1] = (tree >> 32) as u32;
    #[allow(clippy::cast_possible_truncation)]
    {
        addr[2] = tree as u32;
    }
}

#[inline]
pub fn set_type(addr: &mut [u32; 8], type_val: u32) {
    addr[3] = type_val;
}

#[inline]
pub fn set_key_and_mask(addr: &mut [u32; 8], key_and_mask: u32) {
    addr[7] = key_and_mask;
}

/// Copies the layer and tree part of one address into the other.
#[inline]
pub fn copy_subtree_addr(out: &mut [u32; 8], input: &[u32; 8]) {
    out[0] = input[0];
    out[1] = input[1];
    out[2] = input[2];
}

#[inline]
pub fn set_ots_addr(addr: &mut [u32; 8], ots: u32) {
    addr[4] = ots;
}

#[inline]
pub fn set_chain_addr(addr: &mut [u32; 8], chain: u32) {
    addr[5] = chain;
}

#[inline]
pub fn set_hash_addr(addr: &mut [u32; 8], hash: u32) {
    addr[6] = hash;
}

#[inline]
pub fn set_ltree_addr(addr: &mut [u32; 8], ltree: u32) {
    addr[4] = ltree;
}

#[inline]
pub fn set_tree_height(addr: &mut [u32; 8], tree_height: u32) {
    addr[5] = tree_height;
}

#[inline]
pub fn set_tree_index(addr: &mut [u32; 8], tree_index: u32) {
    addr[6] = tree_index;
}
