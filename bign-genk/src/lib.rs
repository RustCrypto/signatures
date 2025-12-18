#![no_std]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

//! ## Usage
//!
//! See also: the documentation for the [`generate_k`] function.
//!
//! ```
//! use hex_literal::hex;
//! use bign_genk::consts::U32;
//! use belt_hash::{Digest, BeltHash};
//! use belt_block::BeltBlock;
//!
//! // BIGN P-256 field modulus
//! const BIGNP256_MODULUS: [u8; 32] =
//!     hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");
//!
//! // Public key for STB 34.101.45 Bign P256/BeltHash test case
//! const KEY: [u8; 32] =
//!     hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");
//!
//! // Test message for STB 34.101.45 Bign P256/BeltHash test case
//! const MSG: [u8; 13] =
//!     hex!("B194BAC8 0A08F53B 366D008E 58");
//!
//! // Expected K for STB 34.101.45 Bign P256/BeltHash test case
//! const EXPECTED_K: [u8; 32] =
//!     hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");
//!
//! let h = BeltHash::digest(MSG);
//! let k = bign_genk::generate_k::<BeltHash, BeltBlock, U32>(
//!     &KEY.into(),
//!     &BIGNP256_MODULUS.into(),
//!     &h,
//!     &[],
//! );
//! assert_eq!(k.as_slice(), &EXPECTED_K);
//! ```

pub use cipher::Array;
pub use cipher::typenum::consts;

use cipher::{BlockCipherEncrypt, BlockSizeUser, KeyInit, array::ArraySize, typenum::Unsigned};
use digest::Digest;
use digest::const_oid::AssociatedOid;

mod ct;

type BlockArray<C> = <<C as BlockSizeUser>::BlockSize as ArraySize>::ArrayType<u8>;

/// Deterministically generate ephemeral scalar `k`.
///
/// Accepts the following parameters and inputs:
///
/// - `x`: secret key
/// - `q`: field modulus
/// - `h`: hash/digest of an input message: must be reduced modulo `q` in advance
/// - `data`: additional associated data, e.g., CSRNG output used as added entropy
#[inline]
pub fn generate_k<D, C, N>(
    x: &Array<u8, N>,
    q: &Array<u8, N>,
    h: &Array<u8, N>,
    data: &[u8],
) -> Array<u8, N>
where
    D: BlockSizeUser + Clone + Digest + AssociatedOid,
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    N: ArraySize,
    BlockArray<C>: Copy,
{
    let mut k = Array::default();
    generate_k_mut::<D, C>(x, q, h, data, &mut k);
    k
}

/// Deterministically generate ephemeral scalar `k` by writing it into the provided output buffer.
///
/// This is an API that accepts dynamically sized inputs intended for use cases where the sizes
/// are determined at runtime, such as the legacy Digital Signature Algorithm (DSA).
///
/// Accepts the following parameters and inputs:
///
/// - `x`: secret key
/// - `q`: field modulus
/// - `h`: hash/digest of an input message: must be reduced modulo `q` in advance
/// - `data`: additional associated data, e.g., CSRNG output used as added entropy
#[inline]
pub fn generate_k_mut<D, C>(x: &[u8], q: &[u8], h: &[u8], data: &[u8], k: &mut [u8])
where
    D: BlockSizeUser + Clone + Digest + AssociatedOid,
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    BlockArray<C>: Copy,
{
    let len = k.len();
    assert_eq!(len, x.len());
    assert_eq!(len, q.len());
    assert_eq!(len, h.len());
    assert!(len == 32 || len == 48 || len == 64);

    // n = ℓ/64 (2, 3 or 4)
    let n = len / C::BlockSize::USIZE;

    // 2: θ ← belt-hash(OID(h) ‖ ⟨d⟩ ‖ t)
    let mut hasher: D = Digest::new();

    hasher.update([0x06, (D::OID.len() - 1) as u8]);
    hasher.update(D::OID);
    hasher.update(x);
    hasher.update(data);
    let theta = hasher.finalize();

    // belt-block(θ)
    let cipher = C::new_from_slice(&theta).expect("Invalid key length");

    // 3. r ← H
    // r = r₁ ‖ r₂ ‖ ... ‖ r_n, where r_i ∈ {0,1}^128
    let mut r = [Array::<u8, C::BlockSize>::default(); 4];
    for (i, chunk) in h.chunks(C::BlockSize::USIZE).enumerate().take(n) {
        r[i][..chunk.len()].copy_from_slice(chunk);
    }

    // 4.
    let mut i = 1u32;
    loop {
        let s = match n {
            2 => {
                // 4.1) s ← r₁
                r[0]
            }
            3 => {
                // 4.2.a) s ← r₁ ⊕ r₂
                let s = xor_blocks::<C>(&r[0], &r[1]);
                // 4.2.b) r₁ ← r₂
                r[0] = r[1];
                s
            }
            4 => {
                // 4.3.a) s ← r₁ ⊕ r₂ ⊕ r₃
                let mut s = xor_blocks::<C>(&r[0], &r[1]);
                xor_assign(&mut s, &r[2]);
                // 4.3.b) r₁ ← r₂
                r[0] = r[1];
                // 4.3.c) r₂ ← r₃
                r[1] = r[2];
                s
            }
            _ => unreachable!(),
        };

        // 4.4: r_(n-1) ← belt-block(s, θ) ⊕ r_n ⊕ ⟨i⟩_128
        let mut encrypted = s;
        cipher.encrypt_block(&mut encrypted);

        // ⊕ r_n
        xor_assign(&mut encrypted, &r[n - 1]);

        // ⊕ ⟨i⟩_128
        xor_assign(&mut encrypted, &i.to_le_bytes());

        // r_(n-1)
        r[n - 2] = encrypted;

        // 4.5: r_n ← s
        r[n - 1] = s;

        // 4.6: Check every 2n iterations
        if i % (2 * n as u32) == 0 {
            for (j, chunk) in r.iter().enumerate().take(n) {
                k[j * C::BlockSize::USIZE..(j + 1) * C::BlockSize::USIZE].copy_from_slice(chunk);
            }

            // Assert: k ∈ {1, 2, ..., q-1}
            if (!ct::is_zero(k) & ct::lt(k, q)).into() {
                return; // 5-6: k ← r, return
            }
        }

        i = i.wrapping_add(1);
    }
}

/// XOR two blocks of arbitrary size
#[inline]
fn xor_blocks<C>(
    a: &Array<u8, C::BlockSize>,
    b: &Array<u8, C::BlockSize>,
) -> Array<u8, C::BlockSize>
where
    C: BlockSizeUser,
    BlockArray<C>: Copy,
{
    let mut result = *a;
    xor_assign(&mut result, b);
    result
}

/// XOR-assignment
#[inline]
fn xor_assign(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= b_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use belt_block::{BeltBlock, cipher::typenum::U32};
    use belt_hash::BeltHash;
    use hex_literal::hex;

    /// Table 7 appendix G STB 34.101.45
    #[test]
    fn stb_table_g7() {
        let d = hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");
        let q = hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");
        let h = hex!("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A");
        let t = hex!("BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF");

        let expected_k =
            hex!("7ADC8713 283EBFA5 47A2AD9C DFB245AE 0F7B968D F0F91CB7 85D1F932 A3583107");

        let k = generate_k::<BeltHash, BeltBlock, U32>(&d.into(), &q.into(), &h.into(), &t);

        assert_eq!(k.as_slice(), &expected_k);
    }
}
