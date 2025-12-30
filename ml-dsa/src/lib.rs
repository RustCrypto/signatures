#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![warn(clippy::as_conversions)] // Use proper conversions, not `as`
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::similar_names)] // Allow notation matching the spec
#![allow(clippy::many_single_char_names)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented
#![warn(unreachable_pub)] // Prevent unexpected interface changes

//! # Quickstart
//!
//! ```
//! # #[cfg(feature = "rand_core")]
//! # {
//! use ml_dsa::{
//!     signature::{Keypair, Signer, Verifier},
//!     MlDsa65, KeyGen,
//! };
//! use getrandom::rand_core::TryRngCore;
//!
//! let mut rng = getrandom::SysRng.unwrap_err();
//! let kp = MlDsa65::key_gen(&mut rng);
//!
//! let msg = b"Hello world";
//! let sig = kp.signing_key().sign(msg);
//!
//! assert!(kp.verifying_key().verify(msg, &sig).is_ok());
//! # }
//! ```

mod algebra;
mod crypto;
mod encode;
mod hint;
mod ntt;
mod param;
mod pkcs8;
mod sampling;
mod util;

// TODO(RLB) Move module to an independent crate shared with ml_kem
mod module_lattice;

use core::convert::{AsRef, TryFrom, TryInto};
use hybrid_array::{
    Array,
    typenum::{
        Diff, Length, Prod, Quot, Shleft, U1, U2, U4, U5, U6, U7, U8, U17, U19, U32, U48, U55, U64,
        U75, U80, U88, Unsigned,
    },
};
use sha3::Shake256;
use signature::{DigestSigner, DigestVerifier, MultipartSigner, MultipartVerifier, Signer};

#[cfg(feature = "rand_core")]
use {
    rand_core::{CryptoRng, TryCryptoRng},
    signature::{RandomizedDigestSigner, RandomizedMultipartSigner, RandomizedSigner},
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::{AlgebraExt, Elem, NttMatrix, NttVector, Truncate, Vector};
use crate::crypto::H;
use crate::hint::Hint;
use crate::ntt::{Ntt, NttInverse};
use crate::param::{ParameterSet, QMinus1, SamplingSize, SpecQ};
use crate::sampling::{expand_a, expand_mask, expand_s, sample_in_ball};
use crate::util::B64;
use core::fmt;

pub use crate::param::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, MlDsaParams};
pub use crate::util::B32;
pub use signature::{self, Error};

/// ML-DSA seeds are signing (private) keys, which are consistently 32-bytes across all security
/// levels, and are the preferred serialization for representing such keys.
pub type Seed = B32;

/// An ML-DSA signature
#[derive(Clone, PartialEq, Debug)]
pub struct Signature<P: MlDsaParams> {
    c_tilde: Array<u8, P::Lambda>,
    z: Vector<P::L>,
    h: Hint<P>,
}

impl<P: MlDsaParams> Signature<P> {
    /// Encode the signature in a fixed-size byte array.
    // Algorithm 26 sigEncode
    pub fn encode(&self) -> EncodedSignature<P> {
        let c_tilde = self.c_tilde.clone();
        let z = P::encode_z(&self.z);
        let h = self.h.bit_pack();
        P::concat_sig(c_tilde, z, h)
    }

    /// Decode the signature from an appropriately sized byte array.
    // Algorithm 27 sigDecode
    pub fn decode(enc: &EncodedSignature<P>) -> Option<Self> {
        let (c_tilde, z, h) = P::split_sig(enc);

        let c_tilde = c_tilde.clone();
        let z = P::decode_z(z);
        let h = Hint::bit_unpack(h)?;

        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
            return None;
        }

        Some(Self { c_tilde, z, h })
    }
}

impl<'a, P: MlDsaParams> TryFrom<&'a [u8]> for Signature<P> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let enc = EncodedSignature::<P>::try_from(value).map_err(|_| Error::new())?;
        Self::decode(&enc).ok_or(Error::new())
    }
}

impl<P: MlDsaParams> TryInto<EncodedSignature<P>> for Signature<P> {
    type Error = Error;

    fn try_into(self) -> Result<EncodedSignature<P>, Self::Error> {
        Ok(self.encode())
    }
}

impl<P: MlDsaParams> signature::SignatureEncoding for Signature<P> {
    type Repr = EncodedSignature<P>;
}

struct MuBuilder(H);

impl MuBuilder {
    fn new(tr: &[u8], ctx: &[u8]) -> Self {
        let mut h = H::default();
        h = h.absorb(tr);
        h = h.absorb(&[0]);
        h = h.absorb(&[Truncate::truncate(ctx.len())]);
        h = h.absorb(ctx);

        Self(h)
    }

    fn internal(tr: &[u8], Mp: &[&[u8]]) -> B64 {
        let mut h = H::default().absorb(tr);

        for m in Mp {
            h = h.absorb(m);
        }

        h.squeeze_new()
    }

    fn message(mut self, M: &[&[u8]]) -> B64 {
        for m in M {
            self.0 = self.0.absorb(m);
        }

        self.0.squeeze_new()
    }

    fn finish(mut self) -> B64 {
        self.0.squeeze_new()
    }
}

impl AsMut<Shake256> for MuBuilder {
    fn as_mut(&mut self) -> &mut Shake256 {
        self.0.updatable()
    }
}

/// An ML-DSA key pair
pub struct KeyPair<P: MlDsaParams> {
    /// The signing key of the key pair
    signing_key: SigningKey<P>,

    /// The verifying key of the key pair
    verifying_key: VerifyingKey<P>,

    /// The seed this signing key was derived from
    seed: B32,
}

impl<P: MlDsaParams> KeyPair<P> {
    /// The signing key of the key pair
    pub fn signing_key(&self) -> &SigningKey<P> {
        &self.signing_key
    }

    /// The verifying key of the key pair
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }

    /// Serialize the [`Seed`] value: 32-bytes which can be used to reconstruct the
    /// [`KeyPair`].
    ///
    /// # ⚠️ Warning!
    ///
    /// This value is key material. Please treat it with care.
    #[inline]
    pub fn to_seed(&self) -> Seed {
        self.seed
    }
}

impl<P: MlDsaParams> AsRef<VerifyingKey<P>> for KeyPair<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

impl<P: MlDsaParams> fmt::Debug for KeyPair<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

impl<P: MlDsaParams> signature::KeypairRef for KeyPair<P> {
    type VerifyingKey = VerifyingKey<P>;
}

/// The `Signer` implementation for `KeyPair` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.
impl<P: MlDsaParams> Signer<Signature<P>> for KeyPair<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

/// The `Signer` implementation for `KeyPair` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.
impl<P: MlDsaParams> MultipartSigner<Signature<P>> for KeyPair<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.signing_key.raw_sign_deterministic(msg, &[])
    }
}

/// The `DigestSigner` implementation for `KeyPair` uses the optional deterministic variant of ML-DSA
/// with a pre-computed μ, and only supports signing with an empty context string.
impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for KeyPair<P> {
    fn try_sign_digest<F: Fn(&mut Shake256) -> Result<(), Error>>(
        &self,
        f: F,
    ) -> Result<Signature<P>, Error> {
        self.signing_key.try_sign_digest(&f)
    }
}

/// An ML-DSA signing key
#[derive(Clone, PartialEq)]
pub struct SigningKey<P: MlDsaParams> {
    rho: B32,
    K: B32,
    tr: B64,
    s1: Vector<P::L>,
    s2: Vector<P::K>,
    t0: Vector<P::K>,

    // Derived values
    s1_hat: NttVector<P::L>,
    s2_hat: NttVector<P::K>,
    t0_hat: NttVector<P::K>,
    A_hat: NttMatrix<P::K, P::L>,
}

impl<P: MlDsaParams> fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.K.zeroize();
        self.tr.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
        self.t0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for SigningKey<P> {}

impl<P: MlDsaParams> SigningKey<P> {
    fn new(
        rho: B32,
        K: B32,
        tr: B64,
        s1: Vector<P::L>,
        s2: Vector<P::K>,
        t0: Vector<P::K>,
        A_hat: Option<NttMatrix<P::K, P::L>>,
    ) -> Self {
        let A_hat = A_hat.unwrap_or_else(|| expand_a(&rho));
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

    /// Deterministically generate a signing key from the specified seed.
    ///
    /// This method reflects the ML-DSA.KeyGen_internal algorithm from FIPS 204, but only returns a
    /// signing key.
    #[must_use]
    pub fn from_seed(seed: &Seed) -> Self {
        let kp = P::from_seed(seed);
        kp.signing_key
    }

    /// This method reflects the ML-DSA.Sign_internal algorithm from FIPS 204. It does not
    /// include the domain separator that distinguishes between the normal and pre-hashed cases,
    /// and it does not separate the context string from the rest of the message.
    // Algorithm 7 ML-DSA.Sign_internal
    // TODO(RLB) Only expose based on a feature.  Tests need access, but normal code shouldn't.
    pub fn sign_internal(&self, Mp: &[&[u8]], rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        let mu = MuBuilder::internal(&self.tr, Mp);
        self.raw_sign_mu(&mu, rnd)
    }

    fn raw_sign_mu(&self, mu: &B64, rnd: &B32) -> Signature<P>
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

            let z = z.mod_plus_minus::<SpecQ>();
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

    /// Encode the key in a fixed-size byte array.
    // Algorithm 24 skEncode
    pub fn encode(&self) -> EncodedSigningKey<P>
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

    /// Decode the key from an appropriately sized byte array.
    // Algorithm 25 skDecode
    pub fn decode(enc: &EncodedSigningKey<P>) -> Self
    where
        P: MlDsaParams,
    {
        let (rho, K, tr, s1_enc, s2_enc, t0_enc) = P::split_sk(enc);
        Self::new(
            rho.clone(),
            K.clone(),
            tr.clone(),
            P::decode_s1(s1_enc),
            P::decode_s2(s2_enc),
            P::decode_t0(t0_enc),
            None,
        )
    }

    /// This auxiliary function derives a `VerifyingKey` from a bare
    /// `SigningKey` (even in the absence of the original seed).
    ///
    /// This is a utility function that is useful when importing the private key
    /// from an external source which does not export the seed and does not
    /// provide the precomputed public key associated with the private key
    /// itself.
    ///
    /// `SigningKey` implements `signature::Keypair`: this inherent method is
    /// retained for convenience, so it is available for callers even when the
    /// `signature::Keypair` trait is out-of-scope.
    pub fn verifying_key(&self) -> VerifyingKey<P> {
        let kp: &dyn signature::Keypair<VerifyingKey = VerifyingKey<P>> = self;

        kp.verifying_key()
    }
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.  If you would like to include a context
/// string, use the [`SigningKey::sign_deterministic`] method.
impl<P: MlDsaParams> Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.try_multipart_sign(&[msg])
    }
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string. If you would like to include a context
/// string, use the [`SigningKey::sign_deterministic`] method.
impl<P: MlDsaParams> MultipartSigner<Signature<P>> for SigningKey<P> {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
        self.raw_sign_deterministic(msg, &[])
    }
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA
/// with a pre-computed µ, and only supports signing with an empty context string. If you would
/// like to include a context string, use the [`SigningKey::sign_mu_deterministic`] method.
impl<P: MlDsaParams> DigestSigner<Shake256, Signature<P>> for SigningKey<P> {
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

/// The `KeyPair` implementation for `SigningKey` allows to derive a `VerifyingKey` from
/// a bare `SigningKey` (even in the absence of the original seed).
impl<P: MlDsaParams> signature::Keypair for SigningKey<P> {
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

        VerifyingKey::new(self.rho.clone(), t1, Some(self.A_hat.clone()), None)
    }
}

/// The `RandomizedSigner` implementation for `SigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`SigningKey::sign_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedSigner<Signature<P>> for SigningKey<P> {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Signature<P>, Error> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

/// The `RandomizedSigner` implementation for `SigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`SigningKey::sign_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedMultipartSigner<Signature<P>> for SigningKey<P> {
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<Signature<P>, Error> {
        self.raw_sign_randomized(msg, &[], rng)
    }
}

/// The `RandomizedSigner` implementation for `SigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the
/// [`SigningKey::sign_mu_randomized`] method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> RandomizedDigestSigner<Shake256, Signature<P>> for SigningKey<P> {
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

/// An ML-DSA verification key
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
    fn new(
        rho: B32,
        t1: Vector<P::K>,
        A_hat: Option<NttMatrix<P::K, P::L>>,
        enc: Option<EncodedVerifyingKey<P>>,
    ) -> Self {
        let A_hat = A_hat.unwrap_or_else(|| expand_a(&rho));
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

    fn raw_verify_mu(&self, mu: &B64, sigma: &Signature<P>) -> bool
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

    fn encode_internal(rho: &B32, t1: &Vector<P::K>) -> EncodedVerifyingKey<P> {
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
        Self::new(rho.clone(), t1, None, Some(enc.clone()))
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

/// `MlDsa44` is the parameter set for security category 2.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa44;

impl ParameterSet for MlDsa44 {
    type K = U4;
    type L = U4;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U17>;
    type Gamma2 = Quot<QMinus1, U88>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U88, U2>, U1>>;
    type Lambda = U32;
    type Omega = U80;
    const TAU: usize = 39;
}

/// `MlDsa65` is the parameter set for security category 3.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa65;

impl ParameterSet for MlDsa65 {
    type K = U6;
    type L = U5;
    type Eta = U4;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U48;
    type Omega = U55;
    const TAU: usize = 49;
}

/// `MlDsa87` is the parameter set for security category 5.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa87;

impl ParameterSet for MlDsa87 {
    type K = U8;
    type L = U7;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U64;
    type Omega = U75;
    const TAU: usize = 60;
}

/// A parameter set that knows how to generate key pairs
pub trait KeyGen: MlDsaParams {
    /// The type that is returned by key generation
    type KeyPair: signature::Keypair;

    /// Generate a signing key pair from the specified RNG
    #[cfg(feature = "rand_core")]
    fn key_gen<R: CryptoRng + ?Sized>(rng: &mut R) -> Self::KeyPair;

    /// Deterministically generate a signing key pair from the specified seed
    ///
    /// This method reflects the ML-DSA.KeyGen_internal algorithm from FIPS 204.
    fn from_seed(xi: &B32) -> Self::KeyPair;
}

impl<P> KeyGen for P
where
    P: MlDsaParams,
{
    type KeyPair = KeyPair<P>;

    /// Generate a signing key pair from the specified RNG
    // Algorithm 1 ML-DSA.KeyGen()
    #[cfg(feature = "rand_core")]
    fn key_gen<R: CryptoRng + ?Sized>(rng: &mut R) -> KeyPair<P> {
        let mut xi = B32::default();
        rng.fill_bytes(&mut xi);
        Self::from_seed(&xi)
    }

    /// Deterministically generate a signing key pair from the specified seed
    ///
    /// This method reflects the ML-DSA.KeyGen_internal algorithm from FIPS 204.
    // Algorithm 6 ML-DSA.KeyGen_internal
    fn from_seed(xi: &Seed) -> KeyPair<P>
    where
        P: MlDsaParams,
    {
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

        let verifying_key = VerifyingKey::new(rho, t1, Some(A_hat.clone()), None);
        let signing_key =
            SigningKey::new(rho, K, verifying_key.tr.clone(), s1, s2, t0, Some(A_hat));

        KeyPair {
            signing_key,
            verifying_key,
            seed: xi.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::param::*;
    use getrandom::rand_core::{RngCore, TryRngCore};
    use signature::digest::Update;

    #[test]
    fn output_sizes() {
        //           priv pub  sig
        // ML-DSA-44 2560 1312 2420
        // ML-DSA-65 4032 1952 3309
        // ML-DSA-87 4896 2592 4627
        assert_eq!(SigningKeySize::<MlDsa44>::USIZE, 2560);
        assert_eq!(VerifyingKeySize::<MlDsa44>::USIZE, 1312);
        assert_eq!(SignatureSize::<MlDsa44>::USIZE, 2420);

        assert_eq!(SigningKeySize::<MlDsa65>::USIZE, 4032);
        assert_eq!(VerifyingKeySize::<MlDsa65>::USIZE, 1952);
        assert_eq!(SignatureSize::<MlDsa65>::USIZE, 3309);

        assert_eq!(SigningKeySize::<MlDsa87>::USIZE, 4896);
        assert_eq!(VerifyingKeySize::<MlDsa87>::USIZE, 2592);
        assert_eq!(SignatureSize::<MlDsa87>::USIZE, 4627);
    }

    fn encode_decode_round_trip_test<P>()
    where
        P: MlDsaParams + PartialEq,
    {
        let seed = Array::default();
        let kp = P::from_seed(&seed);
        assert_eq!(kp.to_seed(), seed);

        let sk = kp.signing_key;
        let vk = kp.verifying_key;

        let vk_bytes = vk.encode();
        let vk2 = VerifyingKey::<P>::decode(&vk_bytes);
        assert!(vk == vk2);

        let sk_bytes = sk.encode();
        let sk2 = SigningKey::<P>::decode(&sk_bytes);
        assert!(sk == sk2);

        let M = b"Hello world";
        let rnd = Array([0u8; 32]);
        let sig = sk.sign_internal(&[M], &rnd);
        let sig_bytes = sig.encode();
        let sig2 = Signature::<P>::decode(&sig_bytes).unwrap();
        assert!(sig == sig2);
    }

    #[test]
    fn encode_decode_round_trip() {
        encode_decode_round_trip_test::<MlDsa44>();
        encode_decode_round_trip_test::<MlDsa65>();
        encode_decode_round_trip_test::<MlDsa87>();
    }

    fn public_from_private_test<P>()
    where
        P: MlDsaParams + PartialEq,
    {
        let kp = P::from_seed(&Array::default());
        let sk = kp.signing_key;
        let vk = kp.verifying_key;
        let vk_derived = sk.verifying_key();

        assert!(vk == vk_derived);
    }

    #[test]
    fn public_from_private() {
        public_from_private_test::<MlDsa44>();
        public_from_private_test::<MlDsa65>();
        public_from_private_test::<MlDsa87>();
    }

    fn sign_verify_round_trip_test<P>()
    where
        P: MlDsaParams,
    {
        let kp = P::from_seed(&Array::default());
        let sk = kp.signing_key;
        let vk = kp.verifying_key;

        let M = b"Hello world";
        let rnd = Array([0u8; 32]);
        let sig = sk.sign_internal(&[M], &rnd);

        assert!(vk.verify_internal(M, &sig));
    }

    #[test]
    fn sign_verify_round_trip() {
        sign_verify_round_trip_test::<MlDsa44>();
        sign_verify_round_trip_test::<MlDsa65>();
        sign_verify_round_trip_test::<MlDsa87>();
    }

    fn many_round_trip_test<P>()
    where
        P: MlDsaParams,
    {
        const ITERATIONS: usize = 1000;

        let mut rng = getrandom::SysRng.unwrap_err();
        let mut seed = B32::default();

        for _i in 0..ITERATIONS {
            let seed_data: &mut [u8] = seed.as_mut();
            rng.fill_bytes(seed_data);

            let kp = P::from_seed(&seed);
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let rnd = Array([0u8; 32]);
            let sig = sk.sign_internal(&[M], &rnd);

            let sig_enc = sig.encode();
            let sig_dec = Signature::<P>::decode(&sig_enc).unwrap();

            assert_eq!(sig_dec, sig);
            assert!(vk.verify_internal(M, &sig_dec));
        }
    }

    #[test]
    fn many_round_trip() {
        many_round_trip_test::<MlDsa44>();
        many_round_trip_test::<MlDsa65>();
        many_round_trip_test::<MlDsa87>();
    }

    #[test]
    fn sign_mu_verify_mu_round_trip() {
        fn sign_mu_verify_mu<P>()
        where
            P: MlDsaParams,
        {
            let kp = P::from_seed(&Array::default());
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let rnd = Array([0u8; 32]);
            let mu = MuBuilder::internal(&sk.tr, &[M]);
            let sig = sk.raw_sign_mu(&mu, &rnd);

            assert!(vk.raw_verify_mu(&mu, &sig));
        }
        sign_mu_verify_mu::<MlDsa44>();
        sign_mu_verify_mu::<MlDsa65>();
        sign_mu_verify_mu::<MlDsa87>();
    }

    #[test]
    fn sign_mu_verify_internal_round_trip() {
        fn sign_mu_verify_internal<P>()
        where
            P: MlDsaParams,
        {
            let kp = P::from_seed(&Array::default());
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let rnd = Array([0u8; 32]);
            let mu = MuBuilder::internal(&sk.tr, &[M]);
            let sig = sk.raw_sign_mu(&mu, &rnd);

            assert!(vk.verify_internal(M, &sig));
        }
        sign_mu_verify_internal::<MlDsa44>();
        sign_mu_verify_internal::<MlDsa65>();
        sign_mu_verify_internal::<MlDsa87>();
    }

    #[test]
    fn sign_internal_verify_mu_round_trip() {
        fn sign_internal_verify_mu<P>()
        where
            P: MlDsaParams,
        {
            let kp = P::from_seed(&Array::default());
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let rnd = Array([0u8; 32]);
            let mu = MuBuilder::internal(&sk.tr, &[M]);
            let sig = sk.sign_internal(&[M], &rnd);

            assert!(vk.raw_verify_mu(&mu, &sig));
        }
        sign_internal_verify_mu::<MlDsa44>();
        sign_internal_verify_mu::<MlDsa65>();
        sign_internal_verify_mu::<MlDsa87>();
    }

    #[test]
    fn sign_digest_round_trip() {
        fn sign_digest<P>()
        where
            P: MlDsaParams,
        {
            let kp = P::from_seed(&Array::default());
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let sig = sk.sign_digest(|digest| digest.update(M));
            assert_eq!(sig, sk.sign(M));

            vk.verify_digest(
                |digest| {
                    digest.update(M);
                    Ok(())
                },
                &sig,
            )
            .unwrap();
        }
        sign_digest::<MlDsa44>();
        sign_digest::<MlDsa65>();
        sign_digest::<MlDsa87>();
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn sign_randomized_digest_round_trip() {
        fn sign_digest<P>()
        where
            P: MlDsaParams,
        {
            let kp = P::from_seed(&Array::default());
            let sk = kp.signing_key;
            let vk = kp.verifying_key;

            let M = b"Hello world";
            let mut rng = getrandom::SysRng.unwrap_err();
            let sig = sk.sign_digest_with_rng(&mut rng, |digest| digest.update(M));

            vk.verify_digest(
                |digest| {
                    digest.update(M);
                    Ok(())
                },
                &sig,
            )
            .unwrap();
        }
        sign_digest::<MlDsa44>();
        sign_digest::<MlDsa65>();
        sign_digest::<MlDsa87>();
    }

    #[test]
    fn from_seed_implementations_match() {
        fn assert_from_seed_equality<P>()
        where
            P: MlDsaParams,
        {
            let seed = Seed::default();
            let kp1 = P::from_seed(&seed);
            let sk1 = SigningKey::<P>::from_seed(&seed);
            let vk1 = sk1.verifying_key();
            assert_eq!(kp1.signing_key, sk1);
            assert_eq!(kp1.verifying_key, vk1);
        }
        assert_from_seed_equality::<MlDsa44>();
        assert_from_seed_equality::<MlDsa65>();
        assert_from_seed_equality::<MlDsa87>();
    }
}
