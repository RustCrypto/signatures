//! ML-DSA `SigningKey` and `ExpandedSigningKey`.
//!
//! These types implement signature generation.

use crate::{
    B32, B64, ExpandedSigningKeyBytes, MlDsaParams, MuBuilder, Seed, Signature, VerifyingKey,
    algebra::{AlgebraExt, NttMatrix, NttVector, Vector},
    crypto::H,
    hint::Hint,
    ntt::{Ntt, NttInverse},
    param::{SamplingSize, SpecQ},
    sampling::{expand_a, expand_mask, expand_s, sample_in_ball},
};
use common::{KeyExport, KeyInit, KeySizeUser, typenum::U32};
use core::fmt;
use ctutils::{Choice, CtEq};
use hybrid_array::typenum::Unsigned;
use module_lattice::MaybeBox;
use shake::Shake256;
use signature::{DigestSigner, Error, MultipartSigner, Signer};

#[cfg(feature = "rand_core")]
use {
    common::Generate,
    signature::{
        RandomizedDigestSigner, RandomizedMultipartSigner, RandomizedSigner,
        rand_core::TryCryptoRng,
    },
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA signing key (i.e. private/secret key).
///
/// This type is initialized through a [`Seed`], and can be used to generate ML-DSA signatures.
#[derive(Clone)]
pub struct SigningKey<P: MlDsaParams> {
    /// The expanded form of the signing key.
    expanded_key: MaybeBox<ExpandedSigningKey<P>>,

    /// The seed this signing key was derived from
    seed: MaybeBox<Seed>,

    /// When the `alloc` feature is available, precompute the [`VerifyingKey`].
    #[cfg(feature = "alloc")]
    verifying_key: VerifyingKey<P>,
}

impl<P: MlDsaParams> SigningKey<P> {
    /// Deterministically generate a signing key pair from the specified [`Seed`].
    ///
    /// This method reflects the `ML-DSA.KeyGen_internal` algorithm from FIPS 204 (Algorithm 6).
    #[must_use]
    pub fn from_seed(xi: &Seed) -> Self {
        // Derive seeds
        let mut h = H::default()
            .absorb(xi)
            .absorb(&[P::K::U8])
            .absorb(&[P::L::U8]);

        let rho: B32 = h.squeeze_new();
        let rhop: B64 = h.squeeze_new();
        let K: B32 = h.squeeze_new();

        // Sample private key components
        let A_hat = expand_a::<P::K, P::L>(&rho);
        let s1 = expand_s::<P::L>(&rhop, P::Eta::ETA, 0);
        let s2 = expand_s::<P::K>(&rhop, P::Eta::ETA, P::L::USIZE);

        // Compute derived values
        let As1_hat = &A_hat * &s1.ntt();
        let t = &As1_hat.ntt_inverse() + &s2;

        // Compress and encode
        let (t1, t0) = t.power2round();

        let enc = VerifyingKey::<P>::encode_internal(&rho, &t1);
        let tr: B64 = H::default().absorb(&enc).squeeze_new();
        let expanded_key = ExpandedSigningKey::new(rho, K, tr, s1, s2, t0, A_hat);

        #[cfg(feature = "alloc")]
        let verifying_key = expanded_key.verifying_key();

        SigningKey {
            expanded_key: MaybeBox::new(expanded_key),
            seed: MaybeBox::new(xi.clone()),
            #[cfg(feature = "alloc")]
            verifying_key,
        }
    }

    /// Borrow the [`Seed`] value: 32-bytes which can be used to reconstruct the [`SigningKey`].
    ///
    /// <div class="warning">
    /// <b>Warning</b>
    ///
    /// This value is key material. Please treat it with care.
    /// </div>
    #[inline]
    #[must_use]
    pub fn as_seed(&self) -> &Seed {
        &self.seed
    }

    /// Serialize the [`Seed`] value: 32-bytes which can be used to reconstruct the [`SigningKey`].
    ///
    /// <div class="warning">
    /// <b>Warning</b>
    ///
    /// This value is key material. Please treat it with care.
    /// </div>
    #[inline]
    #[must_use]
    pub fn to_seed(&self) -> Seed {
        *self.seed
    }

    /// The expanded form of the signing key.
    #[doc(hidden)]
    #[must_use]
    pub fn expanded_key(&self) -> &ExpandedSigningKey<P> {
        &self.expanded_key
    }
}

impl<P: MlDsaParams> KeySizeUser for SigningKey<P> {
    type KeySize = U32;
}

impl<P: MlDsaParams> KeyInit for SigningKey<P> {
    fn new(seed: &Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<P: MlDsaParams> KeyExport for SigningKey<P> {
    fn to_bytes(&self) -> Seed {
        self.to_seed()
    }
}

/// Algorithm 1: `ML-DSA.KeyGen()`.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> Generate for SigningKey<P> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Seed::try_generate_from_rng(rng)?;
        Ok(Self::from_seed(&seed))
    }
}

impl<P: MlDsaParams> fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

// NOTE: when the `alloc` feature is enabled, we receive a blanket impl of `Keypair` via the impl
// of the `KeypairRef` trait which simply clones the precomputed verifying key, providing equivalent
// functionality and thus this is actually still an additive use of features.
#[cfg(not(feature = "alloc"))]
impl<P: MlDsaParams> signature::Keypair for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;
    fn verifying_key(&self) -> VerifyingKey<P> {
        self.expanded_key.verifying_key()
    }
}

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> AsRef<VerifyingKey<P>> for SigningKey<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> signature::KeypairRef for SigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.
impl<P: MlDsaParams> Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.
impl<P: MlDsaParams> MultipartSigner<Signature<P>> for SigningKey<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.expanded_key.raw_sign_deterministic(msg, &[])
    }
}

/// The `DigestSigner` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA
/// with a pre-computed μ, and only supports signing with an empty context string.
impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for SigningKey<P> {
    fn try_sign_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
    ) -> Result<Signature<P>, Error> {
        self.expanded_key.try_sign_digest(&f)
    }
}

impl<P: MlDsaParams> PartialEq for SigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: MlDsaParams> CtEq for SigningKey<P> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expanded_key
            .ct_eq(&other.expanded_key)
            .and(self.seed.ct_eq(&other.seed))
    }
}

impl<P: MlDsaParams> Drop for SigningKey<P> {
    fn drop(&mut self) {
        // NOTE: `expanded_key` has its own zeroizing `Drop` impl so we just need to clear `seed`
        #[cfg(feature = "zeroize")]
        self.seed.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for SigningKey<P> {}

/// An ML-DSA signing key
#[derive(Clone)]
pub struct ExpandedSigningKey<P: MlDsaParams> {
    rho: B32,
    K: B32,
    pub(crate) tr: B64,
    s1: Vector<P::L>,
    s2: Vector<P::K>,
    t0: Vector<P::K>,

    // Derived values
    s1_hat: NttVector<P::L>,
    s2_hat: NttVector<P::K>,
    t0_hat: NttVector<P::K>,
    A_hat: NttMatrix<P::K, P::L>,
}

impl<P: MlDsaParams> ExpandedSigningKey<P> {
    pub(crate) fn new(
        rho: B32,
        K: B32,
        tr: B64,
        s1: Vector<P::L>,
        s2: Vector<P::K>,
        t0: Vector<P::K>,
        A_hat: NttMatrix<P::K, P::L>,
    ) -> Self {
        let s1_hat = s1.ntt();
        let s2_hat = s2.ntt();
        let t0_hat = t0.ntt();

        Self {
            rho,
            K,
            tr,
            s1,
            s2,
            t0,

            s1_hat,
            s2_hat,
            t0_hat,
            A_hat,
        }
    }

    #[inline]
    fn new_expand_a(
        rho: B32,
        K: B32,
        tr: B64,
        s1: Vector<P::L>,
        s2: Vector<P::K>,
        t0: Vector<P::K>,
    ) -> Self {
        let A_hat = expand_a(&rho);
        Self::new(rho, K, tr, s1, s2, t0, A_hat)
    }

    /// Deterministically generate an expanded signing key from the specified seed.
    ///
    /// This method reflects the ML-DSA.KeyGen_internal algorithm from FIPS 204, but only returns a
    /// signing key.
    #[must_use]
    #[inline]
    pub fn from_seed(seed: &Seed) -> Self {
        let kp = SigningKey::from_seed(seed);
        (*kp.expanded_key).clone()
    }

    /// This method reflects the ML-DSA.Sign_internal algorithm from FIPS 204. It does not
    /// include the domain separator that distinguishes between the normal and pre-hashed cases,
    /// and it does not separate the context string from the rest of the message.
    // Algorithm 7 ML-DSA.Sign_internal
    // TODO(RLB) Only expose based on a feature. Tests need access, but normal code shouldn't.
    pub fn sign_internal(&self, Mp: &[&[u8]], rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        let mu = MuBuilder::internal(&self.tr, Mp);
        self.raw_sign_mu(&mu, rnd)
    }

    pub(crate) fn raw_sign_mu(&self, mu: &B64, rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        // Compute the private random seed
        let rhopp: B64 = H::default()
            .absorb(&self.K)
            .absorb(rnd)
            .absorb(mu)
            .squeeze_new();

        // Rejection sampling loop
        for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
            let y = expand_mask::<P::L, P::Gamma1>(&rhopp, kappa);
            let w = (&self.A_hat * &y.ntt()).ntt_inverse();
            let w1 = w.high_bits::<P::TwoGamma2>();

            let w1_tilde = P::encode_w1(&w1);
            let c_tilde = H::default()
                .absorb(mu)
                .absorb(&w1_tilde)
                .squeeze_new::<P::Lambda>();
            let c = sample_in_ball(&c_tilde, P::TAU);
            let c_hat = c.ntt();

            let cs1 = (&c_hat * &self.s1_hat).ntt_inverse();
            let cs2 = (&c_hat * &self.s2_hat).ntt_inverse();

            let z = &y + &cs1;
            let r0 = (&w - &cs2).low_bits::<P::TwoGamma2>();

            if z.infinity_norm() >= P::GAMMA1_MINUS_BETA
                || r0.infinity_norm() >= P::GAMMA2_MINUS_BETA
            {
                continue;
            }

            let ct0 = (&c_hat * &self.t0_hat).ntt_inverse();
            let minus_ct0 = -&ct0;
            let w_cs2_ct0 = &(&w - &cs2) + &ct0;
            let h = Hint::<P>::new(&minus_ct0, &w_cs2_ct0);

            if ct0.infinity_norm() >= P::Gamma2::U32 || h.hamming_weight() > P::Omega::USIZE {
                continue;
            }

            let z = MaybeBox::new(z.mod_plus_minus::<SpecQ>());
            return Signature { c_tilde, z, h };
        }

        unreachable!("Rejection sampling failed to find a valid signature");
    }

    /// This method reflects the randomized ML-DSA.Sign algorithm.
    ///
    /// # Errors
    ///
    /// This method will return an opaque error if the context string is more than 255 bytes long,
    /// or if it fails to get enough randomness.
    // Algorithm 2 ML-DSA.Sign
    #[cfg(feature = "rand_core")]
    pub fn sign_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        M: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        self.raw_sign_randomized(&[M], ctx, rng)
    }

    #[cfg(feature = "rand_core")]
    fn raw_sign_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        Mp: &[&[u8]],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mut rnd = B32::default();
        rng.try_fill_bytes(&mut rnd).map_err(|_| Error::new())?;

        let mu = MuBuilder::new(&self.tr, ctx).message(Mp);
        Ok(self.raw_sign_mu(&mu, &rnd))
    }

    /// This method reflects the randomized ML-DSA.Sign algorithm with a pre-computed μ.
    ///
    /// # Errors
    ///
    /// This method can return an opaque error if it fails to get enough randomness.
    // Algorithm 2 ML-DSA.Sign (optional pre-computed μ variant)
    #[cfg(feature = "rand_core")]
    pub fn sign_mu_randomized<R: TryCryptoRng + ?Sized>(
        &self,
        mu: &B64,
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        let mut rnd = B32::default();
        rng.try_fill_bytes(&mut rnd).map_err(|_| Error::new())?;

        Ok(self.raw_sign_mu(mu, &rnd))
    }

    /// This method reflects the optional deterministic variant of the ML-DSA.Sign algorithm.
    ///
    /// # Errors
    ///
    /// This method will return an opaque error if the context string is more than 255 bytes long.
    // Algorithm 2 ML-DSA.Sign (optional deterministic variant)
    pub fn sign_deterministic(&self, M: &[u8], ctx: &[u8]) -> Result<Signature<P>, Error> {
        self.raw_sign_deterministic(&[M], ctx)
    }

    /// This method reflects the optional deterministic variant of the ML-DSA.Sign algorithm with a
    /// pre-computed μ.
    // Algorithm 2 ML-DSA.Sign (optional deterministic and pre-computed μ variant)
    pub fn sign_mu_deterministic(&self, mu: &B64) -> Signature<P> {
        let rnd = B32::default();
        self.raw_sign_mu(mu, &rnd)
    }

    fn raw_sign_deterministic(&self, Mp: &[&[u8]], ctx: &[u8]) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mu = MuBuilder::new(&self.tr, ctx).message(Mp);
        Ok(self.sign_mu_deterministic(&mu))
    }

    /// This auxiliary function derives a `VerifyingKey` from a bare
    /// `ExpandedSigningKey` (even in the absence of the original seed).
    ///
    /// This is a utility function that is useful when importing the private key
    /// from an external source which does not export the seed and does not
    /// provide the precomputed public key associated with the private key
    /// itself.
    ///
    /// `ExpandedSigningKey` implements `signature::Keypair`: this inherent method is
    /// retained for convenience, so it is available for callers even when the
    /// `signature::Keypair` trait is out-of-scope.
    pub fn verifying_key(&self) -> VerifyingKey<P> {
        let kp: &dyn signature::Keypair<VerifyingKey = VerifyingKey<P>> = self;
        kp.verifying_key()
    }

    /// DEPRECATED: decode the key from an appropriately sized byte array.
    ///
    /// Note that this form is deprecated in practice; prefer to use [`ExpandedSigningKey::from_seed`].
    ///
    /// <div class="warning">
    /// <b>Panics</b>
    ///
    /// This API does not validate expanded signing keys and can potentially panic if keys are
    /// malformed or maliciously generated.
    ///
    /// To avoid panics, use [`ExpandedSigningKey::from_seed`] instead.
    /// </div>
    // Algorithm 25 skDecode
    #[deprecated(since = "0.1.0", note = "use `ExpandedSigningKey::from_seed` instead")]
    pub fn from_expanded(enc: &ExpandedSigningKeyBytes<P>) -> Self
    where
        P: MlDsaParams,
    {
        let (rho, K, tr, s1_enc, s2_enc, t0_enc) = P::split_sk(enc);
        Self::new_expand_a(
            rho.clone(),
            K.clone(),
            tr.clone(),
            P::decode_s1(s1_enc),
            P::decode_s2(s2_enc),
            P::decode_t0(t0_enc),
        )
    }

    /// DEPRECATED: encode the key in a fixed-size byte array.
    ///
    /// Note that this form is deprecated in practice; prefer to use [`SigningKey::to_seed`].
    // Algorithm 24 skEncode
    #[deprecated(since = "0.1.0", note = "use `SigningKey::to_seed` instead")]
    pub fn to_expanded(&self) -> ExpandedSigningKeyBytes<P>
    where
        P: MlDsaParams,
    {
        let s1_enc = P::encode_s1(&self.s1);
        let s2_enc = P::encode_s2(&self.s2);
        let t0_enc = P::encode_t0(&self.t0);
        P::concat_sk(
            self.rho.clone(),
            self.K.clone(),
            self.tr.clone(),
            s1_enc,
            s2_enc,
            t0_enc,
        )
    }
}

/// The `Signer` implementation for `ExpandedSigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.  If you would like to include a context
/// string, use the [`ExpandedSigningKey::sign_deterministic`] method.
impl<P: MlDsaParams> Signer<Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

/// The `Signer` implementation for `ExpandedSigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string. If you would like to include a context
/// string, use the [`ExpandedSigningKey::sign_deterministic`] method.
impl<P: MlDsaParams> MultipartSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.raw_sign_deterministic(msg, &[])
    }
}

/// The `Signer` implementation for `ExpandedSigningKey` uses the optional deterministic variant of ML-DSA
/// with a pre-computed µ, and only supports signing with an empty context string. If you would
/// like to include a context string, use the [`ExpandedSigningKey::sign_mu_deterministic`] method.
impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
    ) -> Result<Signature<P>, Error> {
        let mut mu = MuBuilder::new(&self.tr, &[]);
        f(mu.as_mut())?;
        let mu = mu.finish();

        Ok(self.sign_mu_deterministic(&mu))
    }
}

/// The [`signature::Keypair`] implementation for [`ExpandedSigningKey`] allows to derive a
/// [`VerifyingKey`] from a bare `ExpandedSigningKey` (even in the absence of the original seed).
impl<P: MlDsaParams> signature::Keypair for ExpandedSigningKey<P> {
    type VerifyingKey = VerifyingKey<P>;

    /// This is a utility function that is useful when importing the private key
    /// from an external source which does not export the seed and does not
    /// provide the precomputed public key associated with the private key
    /// itself.
    fn verifying_key(&self) -> Self::VerifyingKey {
        let As1 = &self.A_hat * &self.s1_hat;
        let t = &As1.ntt_inverse() + &self.s2;

        /* Discard t0 */
        let (t1, _) = t.power2round();

        VerifyingKey::new(self.rho.clone(), t1, self.A_hat.clone(), None)
    }
}

/// The `RandomizedSigner` implementation for `ExpandedSigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`ExpandedSigningKey::sign_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Signature<P>, Error> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

/// The `RandomizedSigner` implementation for `ExpandedSigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`ExpandedSigningKey::sign_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedMultipartSigner<Signature<P>> for ExpandedSigningKey<P> {
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<Signature<P>, Error> {
        self.raw_sign_randomized(msg, &[], rng)
    }
}

/// The `RandomizedSigner` implementation for `ExpandedSigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`ExpandedSigningKey::sign_mu_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedDigestSigner<Shake256, Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut Shake256) -> Result<(), Error>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> Result<Signature<P>, Error> {
        let mut mu = MuBuilder::new(&self.tr, &[]);
        f(mu.as_mut())?;
        let mu = mu.finish();

        self.sign_mu_randomized(&mu, rng)
    }
}

impl<P: MlDsaParams> PartialEq for ExpandedSigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: MlDsaParams> CtEq for ExpandedSigningKey<P> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.rho
            .ct_eq(&other.rho)
            .and(self.K.ct_eq(&other.K))
            .and(self.tr.ct_eq(&other.tr))
            .and(self.s1.ct_eq(&other.s1))
            .and(self.s2.ct_eq(&other.s2))
            .and(self.t0.ct_eq(&other.t0))
    }
}

impl<P: MlDsaParams> fmt::Debug for ExpandedSigningKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandedSigningKey").finish_non_exhaustive()
    }
}

impl<P: MlDsaParams> Drop for ExpandedSigningKey<P> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.rho.zeroize();
            self.K.zeroize();
            self.tr.zeroize();
            self.s1.zeroize();
            self.s2.zeroize();
            self.t0.zeroize();
            self.s1_hat.zeroize();
            self.s2_hat.zeroize();
            self.t0_hat.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for ExpandedSigningKey<P> {}
