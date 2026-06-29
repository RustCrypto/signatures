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
//! See also: [`KGenerator`] documentation.
//!
//! ```
//! use hex_literal::hex;
//! use bign_genk::bigint::U256;
//! use belt_hash::{Digest, BeltHash};
//! use belt_block::BeltBlock;
//!
//! // BIGN P-256 curve order `q` (big-endian)
//! const BIGNP256_ORDER: [u8; 32] =
//!     hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC");
//!
//! // Public key for STB 34.101.45 Bign P256/BeltHash test case
//! const KEY: [u8; 32] =
//!     hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");
//!
//! // Test message for STB 34.101.45 BignP256/BeltHash test case
//! const MSG: [u8; 13] =
//!     hex!("B194BAC8 0A08F53B 366D008E 58");
//!
//! // Expected K for STB 34.101.45 Bign P256/BeltHash test case
//! const EXPECTED_K: [u8; 32] =
//!     hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");
//!
//! // `q` is big-endian in the STB 34.101.45 tables;
//! let q = U256::from_be_slice(&BIGNP256_ORDER);
//!
//! let h = BeltHash::digest(MSG);
//! let mut kgen = bign_genk::KGenerator::<BeltBlock, U256>::new::<BeltHash>(&KEY, &h, &[], &q);
//!
//! let mut k = [0u8; 32];
//! kgen.fill_next_k(&mut k);
//! assert_eq!(k, EXPECTED_K);
//! ```

pub use bigint;
pub use cipher::Array;
pub use cipher::typenum::consts;

use belt_hash::BeltHash;
use bigint::{Encoding, Unsigned};
use cipher::{
    BlockCipherEncrypt, BlockSizeUser, KeyInit, array::ArraySize, typenum::Unsigned as _,
};
use core::fmt;
use digest::{Digest, const_oid::AssociatedOid};

type BlockArray<C> = <<C as BlockSizeUser>::BlockSize as ArraySize>::ArrayType<u8>;

/// Deterministic generator for the ephemeral scalar `k` as defined by STB 34.101.45 (BIGN).
///
/// - `C`: block cipher used by `belt-wbl` (`belt-block`).
/// - `U`: [`bigint`] integer type holding the curve order `q`.
pub struct KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    /// `belt-block` keyed with `θ`.
    cipher: C,
    /// Internal state `r = r₁ ‖ r₂ ‖ ... ‖ r_n`, where `r_i ∈ {0,1}^128`.
    r: [Array<u8, C::BlockSize>; 4],
    /// `n = ℓ/64` (2, 3 or 4): number of 128-bit blocks.
    n: usize,
    /// Field modulus.
    q: &'a U,
}

impl<'a, C, U> KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    /// Initialize the `k` generator.
    ///
    /// Accepts the following parameters and inputs:
    ///
    /// - `x`: secret key
    /// - `h`: hash/digest of an input message: must be reduced modulo `q` in advance
    /// - `data`: additional associated data `t`, e.g. CSRNG output used as added entropy
    /// - `q`: curve order, as a [`bigint`] integer (the candidate `k` is compared against it)
    pub fn new<M: AssociatedOid>(x: &[u8], h: &[u8], data: &[u8], q: &'a U) -> Self {
        let len = x.len();
        assert_eq!(len, h.len());
        assert!(len == 32 || len == 48 || len == 64);

        // n = ℓ/64 (2, 3 or 4)
        let n = len / C::BlockSize::USIZE;

        // 2: θ ← belt-hash(OID(h) ‖ ⟨d⟩ ‖ t)
        let mut hasher = BeltHash::new();
        hasher.update([0x06, (M::OID.len() - 1) as u8]);
        hasher.update(M::OID);
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

        Self { cipher, r, n, q }
    }

    /// Generate a candidate `k` value.
    ///
    /// This may be called repeatedly in the event a particular `k` is unsuitable, e.g. the
    /// resulting `r` value is zero.
    pub fn fill_next_k(&mut self, k: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let n = self.n;
        assert_eq!(k.len(), n * bs);

        loop {
            // One `belt-wbl` encryption: `2n` rounds with `⟨i⟩` running over `1..=2n`.
            for i in 1..=(2 * n as u32) {
                let s = match n {
                    2 => {
                        // 4.1) s ← r₁
                        self.r[0]
                    }
                    3 => {
                        // 4.2.a) s ← r₁ ⊕ r₂
                        let s = xor_blocks::<C>(&self.r[0], &self.r[1]);
                        // 4.2.b) r₁ ← r₂
                        self.r[0] = self.r[1];
                        s
                    }
                    4 => {
                        // 4.3.a) s ← r₁ ⊕ r₂ ⊕ r₃
                        let mut s = xor_blocks::<C>(&self.r[0], &self.r[1]);
                        xor_assign(&mut s, &self.r[2]);
                        // 4.3.b) r₁ ← r₂
                        self.r[0] = self.r[1];
                        // 4.3.c) r₂ ← r₃
                        self.r[1] = self.r[2];
                        s
                    }
                    _ => unreachable!(),
                };

                // 4.4: r_(n-1) ← belt-block(s, θ) ⊕ r_n ⊕ ⟨i⟩_128
                let mut encrypted = s;
                self.cipher.encrypt_block(&mut encrypted);

                // ⊕ r_n
                xor_assign(&mut encrypted, &self.r[n - 1]);

                // ⊕ ⟨i⟩_128
                xor_assign(&mut encrypted, &i.to_le_bytes());

                // r_(n-1)
                self.r[n - 2] = encrypted;

                // 4.5: r_n ← s
                self.r[n - 1] = s;
            }

            for (j, chunk) in self.r.iter().enumerate().take(n) {
                k[j * bs..(j + 1) * bs].copy_from_slice(chunk);
            }

            // Assert: k ∈ {1, 2, ..., q-1}
            //
            // `k` is the little-endian octet string `r₁ ‖ r₂ ‖ ... ‖ r_n`; decode it as a
            // little-endian integer and range-check it in constant time against `q`.
            let repr = <U::Repr>::try_from(&k[..]).expect("k must equal the modulus width");
            let candidate = U::from_le_bytes(repr);

            if ((!candidate.is_zero()) & candidate.ct_lt(self.q)).to_bool() {
                return; // 5-6: k ← r, return
            }
        }
    }
}

impl<'a, C, U> fmt::Debug for KGenerator<'a, C, U>
where
    C: BlockSizeUser + Clone + BlockCipherEncrypt + KeyInit,
    U: Unsigned + Encoding,
    BlockArray<C>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KGenerator").finish_non_exhaustive()
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
    use bash_hash::{BashHash384, BashHash512};
    use belt_block::BeltBlock;
    use belt_hash::BeltHash;
    use bigint::{U256, U384, U512};
    use hex_literal::hex;

    macro_rules! gek_tests {
        ($($name:ident: $uint:ty, $oid:ty, $d:expr, $q:expr, $h:expr, $expected:expr;)+) => {
            $(
                #[test]
                fn $name() {
                    let q = <$uint>::from_be_slice(&$q);
                    let mut kgen = KGenerator::<BeltBlock, $uint>::new::<$oid>(&$d, &$h, &[], &q);

                    let expected = $expected;
                    let mut buf = [0u8; 64];
                    let k = &mut buf[..expected.len()];
                    kgen.fill_next_k(k);

                    assert_eq!(&k[..], &expected[..]);
                }
            )+
        };
    }

    gek_tests! {
        bign_gek_1: U256, BeltHash,
            hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC"),
            hex!("ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75"),
            hex!("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E");

        bign_gek_2: U256, BeltHash,
            hex!("79628979 DF369BEB 94DEF329 9476AED4 14F39148 AA69E31A 7397E8AA 70578AB3"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C95E2EAB 40309C49 56129C2E F129D6CC"),
            hex!("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A"),
            hex!("0BA66DA6 214E48A7 01F22695 BA9CD6D5 67DE17A1 C6010624 88728ED8 BBF48ED0");

        bign_gek_3: U384, BashHash384,
            hex!("84C21DBF 7B3C2372 DC21386C 216FA16C 9EF10AEA F9F96A87 2FD8058F 2780BA93 0F08BE3B EC804161 37E11A23 2D93B50E"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74"),
            hex!("64334AF8 30D33F63 E9ACDFA1 84E32522 103FFF5C 6860110A 2CD369ED BC04387C 501D8F92 F749AE4D E15A8305 C353D64D"),
            hex!("E48C1A79 06765348 6533401B 25D8D93D 174DE469 5DD2125C 0D2F9468 CC41387E 3C1D8D90 3E950903 2A1FEBF7 92C74D18");

        bign_gek_4: U384, BashHash384,
            hex!("04E1315F 05B86B66 2D809209 D6104DE8 D25DB189 FBCE4BFF E6F6CBDE 84C96024 302D154E F8A7EEF0 B6FD2927 89C3272D"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74"),
            hex!("D06EFBC1 6FD6C088 0CBFC6A4 E3D65AB1 01FA8282 6934190F AABEBFBF FEDE93B2 2B85EA72 A7FB3147 A133A5A8 FEBD8320"),
            hex!("76BF95EA F9876FD9 8619501F 2120D8F7 8DCE2AFB C2E37353 B57B576E 24D821B2 6A078978 F6C3648A 51E67B60 DE40BCE7");

        bign_gek_5: U512, BashHash512,
            hex!("BEC09635 3EF4568A A417622A 95F2B563 33BF3A02 040B3137 2FD5737D E0F1A2BA 6090C1D1 A27155D8 711FFE5B 31027847 1B0B97CF 1B8FE821 C50205E5 D24AB9B8"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 27AAEE8F 8837F39C 962A7D21 D84B63FE D5E9B891 8DB5AB9D 91E1F014 4D7A028D"),
            hex!("2A66C87C 189C12E2 55239406 123BDEDB F19955EA F0808B2A D705E249 220845E2 0F4786FB 6765D0B5 C48984B1 B16556EF 19EA8192 B985E423 3D9C0950 8D6339E7"),
            hex!("B1CAB7FE 937559E2 074BD6CB A402F39D 55F94B6C B1073939 6B63AF93 88306A96 89428B71 A57CC827 6F9608E8 EBB597F3 5CC03B72 90AD2B80 A40CF7E3 642A38E8");

        bign_gek_6: U512, BashHash512,
            hex!("A90188D4 EAA8D5B3 1FD54F3E 02E10FEB F1577A14 642D7C88 B9951F3B 957C006C 567A20BD 7635B9FF 02C3045E DDD84553 D484DE44 9CFC054C 5A96C8CD 5CEA0E33"),
            hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 27AAEE8F 8837F39C 962A7D21 D84B63FE D5E9B891 8DB5AB9D 91E1F014 4D7A028D"),
            hex!("07ABBF85 80E7E5A3 21E9B940 F667AE20 9E2952CE F557978A E743DB08 6BAB4885 B708233C 3F5541DF 8AAFC361 1482FDE4 98E58B33 79A6622D AC2664C9 C118A162"),
            hex!("47F9F579 98B359FE 1EF1E693 D5ADF97E 208314C0 ED013235 101E6EDA 7675BABD 125F4D99 93B4A810 9B4A9832 21DF6A42 E7CCA9F4 15A45810 84B1F203 5FD80376");
    }
}
