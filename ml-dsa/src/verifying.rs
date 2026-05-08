//! ML-DSA signature verification.

use crate::{
    B32, B64, EncodedVerifyingKey, MlDsaParams, MuBuilder, Signature,
    algebra::{Elem, NttMatrix, NttVector, Vector},
    crypto::H,
    ntt::{Ntt, NttInverse},
    param::ParameterSet,
    sampling::{expand_a, sample_in_ball},
};
use sha3::Shake256;
use signature::{DigestVerifier, Error, MultipartVerifier};

/// An ML-DSA verification key.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey<P: ParameterSet> {
    rho: B32,
    t1: Vector<P::K>,

    // Derived values
    A_hat: NttMatrix<P::K, P::L>,
    t1_2d_hat: NttVector<P::K>,
    tr: B64,
}

impl<P: MlDsaParams> VerifyingKey<P> {
    pub(crate) fn new(
        rho: B32,
        t1: Vector<P::K>,
        A_hat: NttMatrix<P::K, P::L>,
        enc: Option<EncodedVerifyingKey<P>>,
    ) -> Self {
        let enc = enc.unwrap_or_else(|| Self::encode_internal(&rho, &t1));

        let t1_2d_hat = (Elem::new(1 << 13) * &t1).ntt();
        let tr: B64 = H::default().absorb(&enc).squeeze_new();

        Self {
            rho,
            t1,
            A_hat,
            t1_2d_hat,
            tr,
        }
    }

    #[inline]
    fn new_expand_a(rho: B32, t1: Vector<P::K>, enc: Option<EncodedVerifyingKey<P>>) -> Self {
        let A_hat = expand_a(&rho);
        Self::new(rho, t1, A_hat, enc)
    }

    /// Computes µ according to FIPS 204 for use in ML-DSA.Sign and ML-DSA.Verify.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the given `Mp` returns one.
    pub fn compute_mu<F: FnOnce(&mut Shake256) -> Result<(), Error>>(
        &self,
        Mp: F,
        ctx: &[u8],
    ) -> Result<B64, Error> {
        let mut mu = MuBuilder::new(&self.tr, ctx);
        Mp(mu.as_mut())?;
        Ok(mu.finish())
    }

    /// This algorithm reflects the ML-DSA.Verify_internal algorithm from FIPS 204.  It does not
    /// include the domain separator that distinguishes between the normal and pre-hashed cases,
    /// and it does not separate the context string from the rest of the message.
    // Algorithm 8 ML-DSA.Verify_internal
    pub fn verify_internal(&self, M: &[u8], sigma: &Signature<P>) -> bool
    where
        P: MlDsaParams,
    {
        let mu = MuBuilder::internal(&self.tr, &[M]);
        self.raw_verify_mu(&mu, sigma)
    }

    pub(crate) fn raw_verify_mu(&self, mu: &B64, sigma: &Signature<P>) -> bool
    where
        P: MlDsaParams,
    {
        // Reconstruct w
        let c = sample_in_ball(&sigma.c_tilde, P::TAU);

        let z_hat = sigma.z.ntt();
        let c_hat = c.ntt();
        let Az_hat = &self.A_hat * &z_hat;
        let ct1_2d_hat = &c_hat * &self.t1_2d_hat;

        let wp_approx = (&Az_hat - &ct1_2d_hat).ntt_inverse();
        let w1p = sigma.h.use_hint(&wp_approx);

        let w1p_tilde = P::encode_w1(&w1p);
        let cp_tilde = H::default()
            .absorb(mu)
            .absorb(&w1p_tilde)
            .squeeze_new::<P::Lambda>();

        sigma.c_tilde == cp_tilde
    }

    /// This algorithm reflects the ML-DSA.Verify algorithm from FIPS 204.
    // Algorithm 3 ML-DSA.Verify
    pub fn verify_with_context(&self, M: &[u8], ctx: &[u8], sigma: &Signature<P>) -> bool {
        self.raw_verify_with_context(&[M], ctx, sigma)
    }

    /// This algorithm reflects the ML-DSA.Verify algorithm with a pre-computed μ from FIPS 204.
    // Algorithm 3 ML-DSA.Verify (optional pre-computed μ variant)
    pub fn verify_mu(&self, mu: &B64, sigma: &Signature<P>) -> bool {
        self.raw_verify_mu(mu, sigma)
    }

    fn raw_verify_with_context(&self, M: &[&[u8]], ctx: &[u8], sigma: &Signature<P>) -> bool {
        if ctx.len() > 255 {
            return false;
        }

        let mu = MuBuilder::new(&self.tr, ctx).message(M);
        self.verify_mu(&mu, sigma)
    }

    pub(crate) fn encode_internal(rho: &B32, t1: &Vector<P::K>) -> EncodedVerifyingKey<P> {
        let t1_enc = P::encode_t1(t1);
        P::concat_vk(rho.clone(), t1_enc)
    }

    /// Encode the key in a fixed-size byte array.
    // Algorithm 22 pkEncode
    pub fn encode(&self) -> EncodedVerifyingKey<P> {
        Self::encode_internal(&self.rho, &self.t1)
    }

    /// Decode the key from an appropriately sized byte array.
    // Algorithm 23 pkDecode
    pub fn decode(enc: &EncodedVerifyingKey<P>) -> Self {
        let (rho, t1_enc) = P::split_vk(enc);
        let t1 = P::decode_t1(t1_enc);
        Self::new_expand_a(rho.clone(), t1, Some(enc.clone()))
    }
}

impl<P: MlDsaParams> core::hash::Hash for VerifyingKey<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

impl<P: MlDsaParams> signature::Verifier<Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), Error> {
        self.multipart_verify(&[msg], signature)
    }
}

impl<P: MlDsaParams> MultipartVerifier<Signature<P>> for VerifyingKey<P> {
    fn multipart_verify(&self, msg: &[&[u8]], signature: &Signature<P>) -> Result<(), Error> {
        self.raw_verify_with_context(msg, &[], signature)
            .then_some(())
            .ok_or(Error::new())
    }
}

impl<P: MlDsaParams> DigestVerifier<Shake256, Signature<P>> for VerifyingKey<P> {
    fn verify_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
        signature: &Signature<P>,
    ) -> Result<(), Error> {
        let mut mu = MuBuilder::new(&self.tr, &[]);
        f(mu.as_mut())?;
        let mu = mu.finish();

        self.raw_verify_mu(&mu, signature)
            .then_some(())
            .ok_or(Error::new())
    }
}
