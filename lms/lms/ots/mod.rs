//! Everything related to LM-OTS

mod keypair;
pub(crate) mod modes;
mod private;
mod public;
pub mod signature;
mod util;

pub use modes::{
    LmsOtsMode, LmsOtsSha256N32W1, LmsOtsSha256N32W2, LmsOtsSha256N32W4, LmsOtsSha256N32W8,
};
pub use private::PrivateKey;
pub use public::PublicKey;
pub use signature::Signature;

#[cfg(test)]
pub mod tests {
    use crate::constants::ID_LEN;
    use crate::ots::modes::{
        LmsOtsMode, LmsOtsSha256N32W1, LmsOtsSha256N32W2, LmsOtsSha256N32W4, LmsOtsSha256N32W8,
    };
    use crate::ots::private::PrivateKey;
    use digest::Digest;
    use digest::OutputSizeUser;
    use generic_array::{ArrayLength, GenericArray};
    use hex_literal::hex;
    use rand::thread_rng;
    use rand_core::{CryptoRng, RngCore};
    use signature::RandomizedSignerMut;
    use signature::Verifier;
    use std::matches;
    use std::ops::Add;
    use typenum::{Sum, U2};

    // tests that a signature signed with a private key verifies under
    // its public key
    fn test_sign<Mode: LmsOtsMode>()
    where
        <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U2>,
        Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U2>: ArrayLength<u8>,
    {
        let mut rng = thread_rng();
        let mut sk = PrivateKey::<Mode>::new(0, [0xcc; ID_LEN], &mut rng);
        let pk = sk.public();
        let msg = "this is a test message".as_bytes();

        assert!(sk.is_valid());
        let sig = sk.try_sign_with_rng(&mut rng, msg);
        assert!(!sk.is_valid());

        assert!(sig.is_ok());

        let sig = sig.unwrap();
        let result = pk.verify(msg, &sig);

        assert!(matches!(result, Ok(())));
    }

    // tests that a signature signed with a private key does not verify under
    // a different public key
    fn test_sign_fail_verify<Mode: LmsOtsMode>()
    where
        <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U2>,
        Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U2>: ArrayLength<u8>,
    {
        let mut rng = thread_rng();
        let mut sk = PrivateKey::<Mode>::new(0, [0xcc; ID_LEN], &mut rng);
        let mut pk = sk.public();
        let msg = "this is a test message".as_bytes();

        assert!(sk.is_valid());
        let sig = sk.try_sign_with_rng(&mut rng, msg);
        assert!(!sk.is_valid());

        assert!(sig.is_ok());

        let sig = sig.unwrap();
        // modify q to get the wrong public key
        pk.q = 1;
        let result = pk.verify(msg, &sig);

        assert!(result.is_err());
    }

    #[test]
    fn test_signverify_sha256_n32_w1() {
        test_sign::<LmsOtsSha256N32W1>();
    }

    #[test]
    fn test_signverify_sha256_n32_w2() {
        test_sign::<LmsOtsSha256N32W2>();
    }

    #[test]
    fn test_signverify_sha256_n32_w4() {
        test_sign::<LmsOtsSha256N32W4>();
    }

    #[test]
    fn test_signverify_sha256_n32_w8() {
        test_sign::<LmsOtsSha256N32W8>();
    }

    #[test]
    fn test_sign_fail_verify_sha256_n32_w1() {
        test_sign_fail_verify::<LmsOtsSha256N32W1>();
    }

    #[test]
    fn test_sign_fail_verify_sha256_n32_w2() {
        test_sign_fail_verify::<LmsOtsSha256N32W2>();
    }

    #[test]
    fn test_sign_fail_verify_sha256_n32_w4() {
        test_sign_fail_verify::<LmsOtsSha256N32W4>();
    }

    #[test]
    fn test_sign_fail_verify_sha256_n32_w8() {
        test_sign_fail_verify::<LmsOtsSha256N32W8>();
    }

    /// Constant RNG for testing purposes only.
    pub struct ConstantRng<'a>(pub &'a [u8]);

    impl<'a> RngCore for ConstantRng<'a> {
        fn next_u32(&mut self) -> u32 {
            let (head, tail) = self.0.split_at(4);
            self.0 = tail;
            u32::from_be_bytes(head.try_into().unwrap())
        }

        fn next_u64(&mut self) -> u64 {
            let (head, tail) = self.0.split_at(8);
            self.0 = tail;
            u64::from_be_bytes(head.try_into().unwrap())
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let (hd, tl) = self.0.split_at(dest.len());
            dest.copy_from_slice(hd);
            self.0 = tl;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            if dest.len() > self.0.len() {
                return Err(rand_core::Error::new("not enough bytes"));
            }
            let (hd, tl) = self.0.split_at(dest.len());
            dest.copy_from_slice(hd);
            self.0 = tl;
            Ok(())
        }
    }

    /// WARNING: This is not a secure cryptographic RNG. It is only used for testing.
    impl CryptoRng for ConstantRng<'_> {}

    #[test]
    /// Test Case 2, Appendix F. LMS level 2. https://datatracker.ietf.org/doc/html/rfc8554#appendix-F
    fn test_sign_kat1() {
        let seed = hex!("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        let id = hex!("215f83b7ccb9acbcd08db97b0d04dc2b");
        let q = 4;
        let y0 = hex!("11b3649023696f85150b189e50c00e98850ac343a77b3638319c347d7310269d");
        let mut sk = PrivateKey::<LmsOtsSha256N32W8>::new_from_seed(q, id, seed);
        let _ = sk.public();

        let c = hex!("0eb1ed54a2460d512388cad533138d240534e97b1e82d33bd927d201dfc24ebb");
        let mut rng = ConstantRng(&c);
        let msg = "The enumeration in the Constitution, of certain rights, shall not be construed to deny or disparage others retained by the people.\n".as_bytes();
        let sig = sk.try_sign_with_rng(&mut rng, msg).unwrap();

        assert_eq!(&sig.c, GenericArray::from_slice(&c));
        assert_eq!(&sig.y[0], GenericArray::from_slice(&y0));
    }

    #[test]
    // Tests that the public key generated from a given seed matches the expected value.
    fn test_keygen_kat() {
        let seed = hex!("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        let id = hex!("215f83b7ccb9acbcd08db97b0d04dc2b");
        let q = 5;
        // Test Case 2, Appendix F. final signature. path[0]
        // https://datatracker.ietf.org/doc/html/rfc8554#appendix-F

        let k = hex!("4de1f6965bdabc676c5a4dc7c35f97f82cb0e31c68d04f1dad96314ff09e6b3d");

        let sk = PrivateKey::<LmsOtsSha256N32W8>::new_from_seed(q, id, seed);
        let pk = sk.public();
        // H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
        let x = <LmsOtsSha256N32W8 as LmsOtsMode>::Hasher::new()
            .chain_update(pk.id)
            .chain_update((pk.q + (1 << 5)).to_be_bytes())
            .chain_update(crate::constants::D_LEAF)
            .chain_update(pk.k)
            .finalize();
        assert_eq!(&x[..], &k[..]);
    }
}
