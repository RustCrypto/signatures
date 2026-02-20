use crate::error::XmssResult;
use crate::hash::{addr_to_bytes, prf_keygen, thash_f};
use crate::hash_address::{set_chain_addr, set_hash_addr, set_key_and_mask};
use crate::params::XmssParams;
use crate::utils::ull_to_bytes;

/// Expands an n-byte seed into a wots_len*n byte array using prf_keygen.
fn expand_seed(
    params: &XmssParams,
    outseeds: &mut [u8],
    inseed: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut buf = vec![0u8; n + 32];

    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    buf[..n].copy_from_slice(&pub_seed[..n]);

    for i in 0..params.wots_len {
        set_chain_addr(addr, i);
        addr_to_bytes(&mut buf[n..n + 32], addr);
        prf_keygen(
            params,
            &mut outseeds[i as usize * n..(i as usize + 1) * n],
            &buf,
            inseed,
        )?;
    }
    Ok(())
}

/// Computes the chaining function.
/// Interprets `input` as start-th value of the chain.
fn gen_chain(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    start: u32,
    steps: u32,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;

    out[..n].copy_from_slice(&input[..n]);

    let mut i = start;
    while i < start + steps && i < params.wots_w {
        set_hash_addr(addr, i);
        let mut tmp = vec![0u8; n];
        tmp.copy_from_slice(&out[..n]);
        thash_f(params, out, &tmp, pub_seed, addr)?;
        i += 1;
    }
    Ok(())
}

/// base_w algorithm as described in draft.
/// Interprets an array of bytes as integers in base w.
fn base_w(params: &XmssParams, output: &mut [u32], input: &[u8]) {
    let out_len = output.len();
    let mut in_idx = 0;
    let mut total: u8 = 0;
    let mut bits: u32 = 0;

    for out_val in output.iter_mut().take(out_len) {
        if bits == 0 {
            total = input[in_idx];
            in_idx += 1;
            bits += 8;
        }
        bits -= params.wots_log_w;
        // wots_w is always a power of 2 <= 256, so (wots_w - 1) fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let mask = (params.wots_w - 1) as u8;
        *out_val = u32::from((total >> bits) & mask);
    }
}

/// Computes the WOTS+ checksum over a message (in base_w).
fn wots_checksum(params: &XmssParams, csum_base_w: &mut [u32], msg_base_w: &[u32]) {
    let mut csum: u32 = 0;

    for val in msg_base_w.iter().take(params.wots_len1 as usize) {
        csum += params.wots_w - 1 - val;
    }

    csum <<= 8 - ((params.wots_len2 * params.wots_log_w) % 8);
    let csum_bytes_len = (params.wots_len2 * params.wots_log_w).div_ceil(8) as usize;
    let mut csum_bytes = vec![0u8; csum_bytes_len];
    ull_to_bytes(&mut csum_bytes, u64::from(csum));
    base_w(params, csum_base_w, &csum_bytes);
}

/// Takes a message and derives the matching chain lengths.
fn chain_lengths(params: &XmssParams, lengths: &mut [u32], msg: &[u8]) {
    let len1 = params.wots_len1 as usize;
    base_w(params, &mut lengths[..len1], msg);
    let (msg_part, csum_part) = lengths.split_at_mut(len1);
    wots_checksum(params, csum_part, msg_part);
}

/// WOTS key generation. Takes a 32 byte seed for the private key, expands it to
/// a full WOTS private key and computes the corresponding public key.
pub fn wots_pkgen(
    params: &XmssParams,
    pk: &mut [u8],
    seed: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;

    expand_seed(params, pk, seed, pub_seed, addr)?;

    for i in 0..params.wots_len as usize {
        #[allow(clippy::cast_possible_truncation)]
        set_chain_addr(addr, i as u32);
        let mut tmp = vec![0u8; n];
        tmp.copy_from_slice(&pk[i * n..(i + 1) * n]);
        gen_chain(
            params,
            &mut pk[i * n..],
            &tmp,
            0,
            params.wots_w - 1,
            pub_seed,
            addr,
        )?;
    }
    Ok(())
}

/// Takes a n-byte message and the 32-byte seed for the private key to compute a
/// signature that is placed at 'sig'.
pub fn wots_sign(
    params: &XmssParams,
    sig: &mut [u8],
    msg: &[u8],
    seed: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut lengths = vec![0u32; params.wots_len as usize];

    chain_lengths(params, &mut lengths, msg);

    expand_seed(params, sig, seed, pub_seed, addr)?;

    for i in 0..params.wots_len as usize {
        #[allow(clippy::cast_possible_truncation)]
        set_chain_addr(addr, i as u32);
        let mut tmp = vec![0u8; n];
        tmp.copy_from_slice(&sig[i * n..(i + 1) * n]);
        gen_chain(
            params,
            &mut sig[i * n..],
            &tmp,
            0,
            lengths[i],
            pub_seed,
            addr,
        )?;
    }
    Ok(())
}

/// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
pub fn wots_pk_from_sig(
    params: &XmssParams,
    pk: &mut [u8],
    sig: &[u8],
    msg: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let mut lengths = vec![0u32; params.wots_len as usize];

    chain_lengths(params, &mut lengths, msg);

    for i in 0..params.wots_len as usize {
        #[allow(clippy::cast_possible_truncation)]
        set_chain_addr(addr, i as u32);
        gen_chain(
            params,
            &mut pk[i * n..],
            &sig[i * n..],
            lengths[i],
            params.wots_w - 1 - lengths[i],
            pub_seed,
            addr,
        )?;
    }
    Ok(())
}
