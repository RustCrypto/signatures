use core::fmt::{self, Debug};
use hmac::{
    KeyInit, SimpleHmac,
    digest::{Digest, Mac, OutputSizeUser, array::Array, block_api::BlockSizeUser},
};

/// Implementation of [NIST SP800-90A]'s `HMAC_DRBG` HMAC-based deterministic random bit generator.
///
/// [NIST SP800-90A]: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
// TODO(tarcieri): extract this into the `hmacdrbg` crate: RustCrypto/CSRNGs#7
pub(crate) struct HmacDrbg<D>
where
    D: OutputSizeUser,
{
    /// HMAC key `K` (see RFC 6979 Section 3.2.c)
    k: Array<u8, D::OutputSize>,

    /// Chaining value `V` (see RFC 6979 Section 3.2.c)
    v: Array<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: BlockSizeUser + Digest,
{
    /// Initialize `HMAC_DRBG`.
    #[must_use]
    pub(crate) fn new(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let mut drbg = Self {
            k: Array::default(),
            v: Array::default(),
        };
        drbg.v.fill(0x01);
        drbg.update(&[entropy_input, nonce, personalization_string]);
        drbg
    }

    /// Write the next `HMAC_DRBG` output to the given byte slice.
    pub(crate) fn fill_bytes(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(self.v.len()) {
            self.update_v();
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        self.update(&[]);
    }

    /// Update `K` and `V` using the provided seed material.
    fn update(&mut self, inputs: &[&[u8]]) {
        let mut hmac = self.hmac_k();
        hmac.update(&self.v);
        hmac.update(&[0x00]);
        inputs.iter().for_each(|&input| hmac.update(input));

        self.k = hmac.finalize().into_bytes();
        self.update_v();

        if !inputs.is_empty() {
            let mut hmac = self.hmac_k();
            hmac.update(&self.v);
            hmac.update(&[0x01]);
            inputs.iter().for_each(|&input| hmac.update(input));

            self.k = hmac.finalize().into_bytes();
            self.update_v();
        }
    }

    /// Update `V = HMAC(K, V)`.
    fn update_v(&mut self) {
        let mut hmac = self.hmac_k();
        hmac.update(&self.v);
        self.v = hmac.finalize().into_bytes();
    }

    /// Initialize HMAC using the current value of `K`.
    fn hmac_k(&self) -> SimpleHmac<D> {
        SimpleHmac::<D>::new_from_slice(&self.k).expect("HMAC key should be valid")
    }
}

impl<D> Debug for HmacDrbg<D>
where
    D: OutputSizeUser,
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
