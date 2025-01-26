#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![warn(clippy::as_conversions)] // Use proper conversions, not `as`
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::similar_names)] // Allow notation matching the spec
#![allow(clippy::many_single_char_names)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented

//! # Quickstart
//!
//! ```
//! use ml_dsa::{MlDsa65, KeyGen};
//! use signature::{Keypair, Signer, Verifier};
//!
//! let mut rng = rand::thread_rng();
//! let kp = MlDsa65::key_gen(&mut rng);
//!
//! let msg = b"Hello world";
//! let sig = kp.signing_key().sign(msg);
//!
//! assert!(kp.verifying_key().verify(msg, &sig).is_ok());
//! ```

mod algebra;
mod crypto;
mod encode;
mod hint;
mod ntt;
mod param;
mod sampling;
mod util;

// TODO(RLB) Move module to an independent crate shared with ml_kem
mod module_lattice;

use core::convert::{AsRef, TryFrom, TryInto};
use hybrid_array::{
    typenum::{
        Diff, Length, Prod, Quot, Shleft, Unsigned, U1, U17, U19, U2, U32, U4, U48, U5, U55, U6,
        U64, U7, U75, U8, U80, U88,
    },
    Array,
};

#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "pkcs8")]
use {
    const_oid::db::fips204,
    pkcs8::{
        der::{self, AnyRef},
        spki::{
            self, AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
            SubjectPublicKeyInfoRef,
        },
        AlgorithmIdentifierRef, PrivateKeyInfoRef,
    },
};

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
use pkcs8::{
    der::asn1::{BitString, BitStringRef, OctetStringRef},
    spki::{SignatureBitStringEncoding, SubjectPublicKeyInfo},
    EncodePrivateKey, EncodePublicKey,
};

use crate::algebra::{AlgebraExt, Elem, NttMatrix, NttVector, Truncate, Vector};
use crate::crypto::H;
use crate::hint::Hint;
use crate::ntt::{Ntt, NttInverse};
use crate::param::{ParameterSet, QMinus1, SamplingSize, SpecQ};
use crate::sampling::{expand_a, expand_mask, expand_s, sample_in_ball};
use crate::util::B64;

pub use crate::param::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, MlDsaParams};
pub use crate::util::B32;
pub use signature::Error;

/// An ML-DSA signature
#[derive(Clone, PartialEq)]
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

#[cfg(feature = "alloc")]
impl<P: MlDsaParams> SignatureBitStringEncoding for Signature<P> {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.encode().to_vec())
    }
}

#[cfg(feature = "pkcs8")]
impl<P> AssociatedAlgorithmIdentifier for Signature<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = P::ALGORITHM_IDENTIFIER;
}

// This method takes a slice of slices so that we can accommodate the varying calculations (direct
// for test vectors, 0... for sign/sign_deterministic, 1... for the pre-hashed version) without
// having to allocate memory for components.
fn message_representative(tr: &[u8], Mp: &[&[u8]]) -> B64 {
    let mut h = H::default().absorb(tr);

    for m in Mp {
        h = h.absorb(m);
    }

    h.squeeze_new()
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
}

impl<P: MlDsaParams> AsRef<VerifyingKey<P>> for KeyPair<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

impl<P: MlDsaParams> signature::KeypairRef for KeyPair<P> {
    type VerifyingKey = VerifyingKey<P>;
}

#[cfg(feature = "pkcs8")]
impl<P> TryFrom<PrivateKeyInfoRef<'_>> for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        match private_key_info.algorithm {
            alg if alg == P::ALGORITHM_IDENTIFIER => {}
            other => return Err(spki::Error::OidUnknown { oid: other.oid }.into()),
        };

        let seed = Array::try_from(private_key_info.private_key.as_bytes())
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        Ok(P::key_gen_internal(&seed))
    }
}

/// The `Signer` implementation for `KeyPair` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.
impl<P: MlDsaParams> signature::Signer<Signature<P>> for KeyPair<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.signing_key.sign_deterministic(msg, &[])
    }
}

#[cfg(feature = "pkcs8")]
impl<P> SignatureAlgorithmIdentifier for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl<P> EncodePrivateKey for KeyPair<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        let pkcs8_key = pkcs8::PrivateKeyInfoRef::new(
            P::ALGORITHM_IDENTIFIER,
            OctetStringRef::new(&self.seed)?,
        );
        Ok(der::SecretDocument::encode_msg(&pkcs8_key)?)
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

    /// This method reflects the ML-DSA.Sign_internal algorithm from FIPS 204. It does not
    /// include the domain separator that distinguishes between the normal and pre-hashed cases,
    /// and it does not separate the context string from the rest of the message.
    // Algorithm 7 ML-DSA.Sign_internal
    // TODO(RLB) Only expose based on a feature.  Tests need access, but normal code shouldn't.
    pub fn sign_internal(&self, Mp: &[&[u8]], rnd: &B32) -> Signature<P>
    where
        P: MlDsaParams,
    {
        // Compute the message representative
        // XXX(RLB): This line incorporates some of the logic from ML-DSA.sign to avoid computing
        // the concatenated M'.
        // XXX(RLB) Should the API represent this as an input?
        let mu = message_representative(&self.tr, Mp);

        // Compute the private random seed
        let rhopp: B64 = H::default()
            .absorb(&self.K)
            .absorb(rnd)
            .absorb(&mu)
            .squeeze_new();

        // Rejection sampling loop
        for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
            let y = expand_mask::<P::L, P::Gamma1>(&rhopp, kappa);
            let w = (&self.A_hat * &y.ntt()).ntt_inverse();
            let w1 = w.high_bits::<P::TwoGamma2>();

            let w1_tilde = P::encode_w1(&w1);
            let c_tilde = H::default()
                .absorb(&mu)
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
    pub fn sign_randomized(
        &self,
        M: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let mut rnd = B32::default();
        rng.try_fill_bytes(&mut rnd).map_err(|_| Error::new())?;

        let Mp = &[&[0], &[Truncate::truncate(ctx.len())], ctx, M];
        Ok(self.sign_internal(Mp, &rnd))
    }

    /// This method reflects the optional deterministic variant of the ML-DSA.Sign algorithm.
    ///
    /// # Errors
    ///
    /// This method will return an opaque error if the context string is more than 255 bytes long.
    // Algorithm 2 ML-DSA.Sign (optional deterministic variant)
    pub fn sign_deterministic(&self, M: &[u8], ctx: &[u8]) -> Result<Signature<P>, Error> {
        if ctx.len() > 255 {
            return Err(Error::new());
        }

        let rnd = B32::default();
        let Mp = &[&[0], &[Truncate::truncate(ctx.len())], ctx, M];
        Ok(self.sign_internal(Mp, &rnd))
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
}

/// The `Signer` implementation for `SigningKey` uses the optional deterministic variant of ML-DSA, and
/// only supports signing with an empty context string.  If you would like to include a context
/// string, use the [`SigningKey::sign_deterministic`] method.
impl<P: MlDsaParams> signature::Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
        self.sign_deterministic(msg, &[])
    }
}

/// The `RandomizedSigner` implementation for `SigningKey` only supports signing with an empty
/// context string. If you would like to include a context string, use the [`SigningKey::sign`]
/// method.
#[cfg(feature = "rand_core")]
impl<P: MlDsaParams> signature::RandomizedSigner<Signature<P>> for SigningKey<P> {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature<P>, Error> {
        self.sign_randomized(msg, &[], rng)
    }
}

#[cfg(feature = "pkcs8")]
impl<P> SignatureAlgorithmIdentifier for SigningKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "pkcs8")]
impl<P> TryFrom<PrivateKeyInfoRef<'_>> for SigningKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        let keypair = KeyPair::try_from(private_key_info)?;

        Ok(keypair.signing_key)
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

    /// This algorithm reflects the ML-DSA.Verify_internal algorithm from FIPS 204.  It does not
    /// include the domain separator that distinguishes between the normal and pre-hashed cases,
    /// and it does not separate the context string from the rest of the message.
    // Algorithm 8 ML-DSA.Verify_internal
    pub fn verify_internal(&self, Mp: &[&[u8]], sigma: &Signature<P>) -> bool
    where
        P: MlDsaParams,
    {
        // Compute the message representative
        let mu = message_representative(&self.tr, Mp);

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
            .absorb(&mu)
            .absorb(&w1p_tilde)
            .squeeze_new::<P::Lambda>();

        sigma.c_tilde == cp_tilde
    }

    /// This algorithm reflect the ML-DSA.Verify algorithm from FIPS 204.
    // Algorithm 3 ML-DSA.Verify
    pub fn verify_with_context(&self, M: &[u8], ctx: &[u8], sigma: &Signature<P>) -> bool {
        if ctx.len() > 255 {
            return false;
        }

        let Mp = &[&[0], &[Truncate::truncate(ctx.len())], ctx, M];
        self.verify_internal(Mp, sigma)
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
        self.verify_with_context(msg, &[], signature)
            .then_some(())
            .ok_or(Error::new())
    }
}

#[cfg(feature = "pkcs8")]
impl<P> SignatureAlgorithmIdentifier for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "alloc")]
impl<P> EncodePublicKey for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let public_key = self.encode();
        let subject_public_key = BitStringRef::new(0, &public_key)?;

        SubjectPublicKeyInfo {
            algorithm: P::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl<P> TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKey<P>
where
    P: MlDsaParams,
    P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        match spki.algorithm {
            alg if alg == P::ALGORITHM_IDENTIFIER => {}
            other => return Err(spki::Error::OidUnknown { oid: other.oid }),
        };

        Ok(Self::decode(
            &EncodedVerifyingKey::<P>::try_from(
                spki.subject_public_key
                    .as_bytes()
                    .ok_or_else(|| der::Tag::BitString.value_error())?,
            )
            .map_err(|_| pkcs8::Error::KeyMalformed)?,
        ))
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

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for MlDsa44 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_44,
        parameters: None,
    };
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

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for MlDsa65 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_65,
        parameters: None,
    };
}

/// `MlKem87` is the parameter set for security category 5.
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

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for MlDsa87 {
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
        oid: fips204::ID_ML_DSA_87,
        parameters: None,
    };
}

/// A parameter set that knows how to generate key pairs
pub trait KeyGen: MlDsaParams {
    /// The type that is returned by key generation
    type KeyPair: signature::Keypair;

    /// Generate a signing key pair from the specified RNG
    #[cfg(feature = "rand_core")]
    fn key_gen(rng: &mut impl CryptoRngCore) -> Self::KeyPair;

    /// Deterministically generate a signing key pair from the specified seed
    // TODO(RLB): Only expose this based on a feature.
    fn key_gen_internal(xi: &B32) -> Self::KeyPair;
}

impl<P> KeyGen for P
where
    P: MlDsaParams,
{
    type KeyPair = KeyPair<P>;

    /// Generate a signing key pair from the specified RNG
    // Algorithm 1 ML-DSA.KeyGen()
    #[cfg(feature = "rand_core")]
    fn key_gen(rng: &mut impl CryptoRngCore) -> KeyPair<P> {
        let mut xi = B32::default();
        rng.fill_bytes(&mut xi);
        Self::key_gen_internal(&xi)
    }

    /// Deterministically generate a signing key pair from the specified seed
    // Algorithm 6 ML-DSA.KeyGen_internal
    fn key_gen_internal(xi: &B32) -> KeyPair<P>
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
        let kp = P::key_gen_internal(&Default::default());
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

    fn sign_verify_round_trip_test<P>()
    where
        P: MlDsaParams,
    {
        let kp = P::key_gen_internal(&Default::default());
        let sk = kp.signing_key;
        let vk = kp.verifying_key;

        let M = b"Hello world";
        let rnd = Array([0u8; 32]);
        let sig = sk.sign_internal(&[M], &rnd);

        assert!(vk.verify_internal(&[M], &sig));
    }

    #[test]
    fn sign_verify_round_trip() {
        sign_verify_round_trip_test::<MlDsa44>();
        sign_verify_round_trip_test::<MlDsa65>();
        sign_verify_round_trip_test::<MlDsa87>();
    }
}
