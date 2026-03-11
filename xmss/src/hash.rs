use sha2::{Digest, Sha256, Sha512};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::error::{Error, XmssResult};
use crate::hash_address::set_key_and_mask;
use crate::params::{XMSS_SHA2, XMSS_SHAKE128, XMSS_SHAKE256, XmssParams};
use crate::utils::ull_to_bytes;

const XMSS_HASH_PADDING_F: u64 = 0;
const XMSS_HASH_PADDING_H: u64 = 1;
const XMSS_HASH_PADDING_HASH: u64 = 2;
const XMSS_HASH_PADDING_PRF: u64 = 3;
const XMSS_HASH_PADDING_PRF_KEYGEN: u64 = 4;

pub(crate) fn addr_to_bytes(bytes: &mut [u8], addr: &[u32; 8]) {
    for i in 0..8 {
        ull_to_bytes(&mut bytes[i * 4..i * 4 + 4], addr[i] as u64);
    }
}

fn core_hash(params: &XmssParams, out: &mut [u8], input: &[u8]) -> XmssResult<()> {
    if params.n == 24 && params.func == XMSS_SHA2 {
        let result = Sha256::digest(input);
        out[..24].copy_from_slice(&result[..24]);
    } else if params.n == 24 && params.func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..24]);
    } else if params.n == 32 && params.func == XMSS_SHA2 {
        let result = Sha256::digest(input);
        out[..32].copy_from_slice(&result);
    } else if params.n == 32 && params.func == XMSS_SHAKE128 {
        let mut hasher = Shake128::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..32]);
    } else if params.n == 32 && params.func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..32]);
    } else if params.n == 64 && params.func == XMSS_SHA2 {
        let result = Sha512::digest(input);
        out[..64].copy_from_slice(&result);
    } else if params.n == 64 && params.func == XMSS_SHAKE256 {
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..64]);
    } else {
        return Err(Error::Hash {
            n: params.n,
            func: params.func,
        });
    }
    Ok(())
}

/// Computes PRF(key, in), for a key of params.n bytes, and a 32-byte input.
pub(crate) fn prf(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8; 32],
    key: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + n + 32;
    let mut buf = vec![0u8; buf_len];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_PRF);
    buf[padding_len..padding_len + n].copy_from_slice(&key[..n]);
    buf[padding_len + n..padding_len + n + 32].copy_from_slice(input);

    let result = core_hash(params, out, &buf);
    buf.zeroize();
    result
}

/// Computes PRF_keygen(key, in), for a key of params.n bytes,
/// and an input of 32 + params.n bytes.
pub(crate) fn prf_keygen(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    key: &[u8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 2 * n + 32;
    let mut buf = vec![0u8; buf_len];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_PRF_KEYGEN);
    buf[padding_len..padding_len + n].copy_from_slice(&key[..n]);
    buf[padding_len + n..padding_len + n + n + 32].copy_from_slice(&input[..n + 32]);

    let result = core_hash(params, out, &buf);
    buf.zeroize();
    result
}

/// Computes the message hash using R, the public root, the index of the leaf
/// node, and the message.
pub(crate) fn hash_message(
    params: &XmssParams,
    out: &mut [u8],
    r: &[u8],
    root: &[u8],
    idx: u64,
    m_with_prefix: &mut [u8],
    mlen: u64,
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;

    ull_to_bytes(&mut m_with_prefix[..padding_len], XMSS_HASH_PADDING_HASH);
    m_with_prefix[padding_len..padding_len + n].copy_from_slice(&r[..n]);
    m_with_prefix[padding_len + n..padding_len + 2 * n].copy_from_slice(&root[..n]);
    ull_to_bytes(
        &mut m_with_prefix[padding_len + 2 * n..padding_len + 3 * n],
        idx,
    );

    #[allow(clippy::cast_possible_truncation)]
    let total_len = mlen as usize + padding_len + 3 * n;
    core_hash(params, out, &m_with_prefix[..total_len])
}

/// Tree hash function for internal nodes (two n-byte inputs).
pub(crate) fn thash_h(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 3 * n;
    let mut buf = vec![0u8; buf_len];
    let mut bitmask = vec![0u8; 2 * n];
    let mut addr_as_bytes = [0u8; 32];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_H);

    set_key_and_mask(addr, 0);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(
        params,
        &mut buf[padding_len..padding_len + n],
        &addr_as_bytes,
        pub_seed,
    )?;

    set_key_and_mask(addr, 1);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, &mut bitmask[..n], &addr_as_bytes, pub_seed)?;

    set_key_and_mask(addr, 2);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, &mut bitmask[n..2 * n], &addr_as_bytes, pub_seed)?;

    for i in 0..2 * n {
        buf[padding_len + n + i] = input[i] ^ bitmask[i];
    }

    core_hash(params, out, &buf)
}

/// Tree hash function for WOTS chains (single n-byte input).
pub(crate) fn thash_f(
    params: &XmssParams,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) -> XmssResult<()> {
    let n = params.n as usize;
    let padding_len = params.padding_len as usize;
    let buf_len = padding_len + 2 * n;
    let mut buf = vec![0u8; buf_len];
    let mut bitmask = vec![0u8; n];
    let mut addr_as_bytes = [0u8; 32];

    ull_to_bytes(&mut buf[..padding_len], XMSS_HASH_PADDING_F);

    set_key_and_mask(addr, 0);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(
        params,
        &mut buf[padding_len..padding_len + n],
        &addr_as_bytes,
        pub_seed,
    )?;

    set_key_and_mask(addr, 1);
    addr_to_bytes(&mut addr_as_bytes, addr);
    prf(params, &mut bitmask, &addr_as_bytes, pub_seed)?;

    for i in 0..n {
        buf[padding_len + n + i] = input[i] ^ bitmask[i];
    }

    core_hash(params, out, &buf)
}
