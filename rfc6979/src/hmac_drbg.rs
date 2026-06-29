use core::fmt::{self, Debug};
use hmac::{
    KeyInit, SimpleHmacReset,
    digest::{Digest, FixedOutputReset, Mac, array::Array, block_api::BlockSizeUser},
};

/// Implementation of `HMAC_DRBG` as described in NIST SP800-90A.
///
/// <https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final>
///
/// This is a HMAC-based deterministic random bit generator.
// TODO(tarcieri): extract this into its own crate
pub(crate) struct HmacDrbg<D>
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    /// HMAC key `K` (see RFC 6979 Section 3.2.c)
    k: SimpleHmacReset<D>,

    /// Chaining value `V` (see RFC 6979 Section 3.2.c)
    v: Array<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    /// Initialize `HMAC_DRBG`.
    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic")]
    pub(crate) fn new(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let mut k = SimpleHmacReset::new(&Default::default());
        let mut v = Array::default();

        v.fill(0x01);

        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(entropy_input);
            k.update(nonce);
            k.update(personalization_string);
            k = SimpleHmacReset::new_from_slice(&k.finalize().into_bytes()).expect("should work");

            // Steps 3.2.e,g: v = HMAC_k(v)
            k.update(&v);
            v = k.finalize_reset().into_bytes();
        }

        Self { k, v }
    }

    /// Write the next `HMAC_DRBG` output to the given byte slice.
    #[allow(clippy::missing_panics_doc, reason = "should not panic")]
    pub(crate) fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut out_chunks = out.chunks_exact_mut(self.v.len());

        for out_chunk in &mut out_chunks {
            self.k.update(&self.v);
            self.v = self.k.finalize_reset().into_bytes();
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        let out_remainder = out_chunks.into_remainder();
        if !out_remainder.is_empty() {
            self.k.update(&self.v);
            self.v = self.k.finalize_reset().into_bytes();
            out_remainder.copy_from_slice(&self.v[..out_remainder.len()]);
        }

        self.k.update(&self.v);
        self.k.update(&[0x00]);
        self.k = SimpleHmacReset::new_from_slice(&self.k.finalize_reset().into_bytes())
            .expect("should work");
        self.k.update(&self.v);
        self.v = self.k.finalize_reset().into_bytes();
    }
}

impl<D> Debug for HmacDrbg<D>
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HmacDrbg").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::HmacDrbg;
    use hex_literal::hex;
    use sha2::Sha256;

    // ECDSA with K-163+SHA-256.
    #[test]
    fn rfc6979_appendix_a1_k163() {
        let x = hex!("009A4D6792295A7F730FC3F2B49CBC0F62E862272F");

        // NOTE: this input is `SHA256("sample")` with `bits2octets` applied in advance
        let h = hex!("01795EDF0D54DB760F156D0DAC04C0322B3A204224");

        let mut drbg = HmacDrbg::<Sha256>::new(&x, &h, &[]);
        let mut out = [0u8; 21];
        drbg.fill_bytes(&mut out);
        assert_eq!(out, hex!("9305A46DE7FF8EB107194DEBD3FD48AA20D5E7656C"));
    }
}
