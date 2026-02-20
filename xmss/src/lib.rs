//! XMSS (eXtended Merkle Signature Scheme) implementation in Rust.
//!
//! Implements RFC 8391 XMSS and XMSSMT hash-based signature schemes.

mod error;
mod hash;
mod hash_address;
mod params;
#[cfg(feature = "pkcs8")]
mod pkcs8;
mod utils;
mod wots;
mod xmss;
mod xmss_commons;
mod xmss_core;

pub use error::{Error, XmssResult};

pub use params::{
    XmssMtSha2_20_2_192,
    // XMSSMT multi-tree parameter sets
    XmssMtSha2_20_2_256,
    XmssMtSha2_20_2_512,
    XmssMtSha2_20_4_192,
    XmssMtSha2_20_4_256,
    XmssMtSha2_20_4_512,
    XmssMtSha2_40_2_192,
    XmssMtSha2_40_2_256,
    XmssMtSha2_40_2_512,
    XmssMtSha2_40_4_192,
    XmssMtSha2_40_4_256,
    XmssMtSha2_40_4_512,
    XmssMtSha2_40_8_192,
    XmssMtSha2_40_8_256,
    XmssMtSha2_40_8_512,
    XmssMtSha2_60_3_192,
    XmssMtSha2_60_3_256,
    XmssMtSha2_60_3_512,
    XmssMtSha2_60_6_192,
    XmssMtSha2_60_6_256,
    XmssMtSha2_60_6_512,
    XmssMtSha2_60_12_192,
    XmssMtSha2_60_12_256,
    XmssMtSha2_60_12_512,
    XmssMtShake_20_2_256,
    XmssMtShake_20_2_512,
    XmssMtShake_20_4_256,
    XmssMtShake_20_4_512,
    XmssMtShake_40_2_256,
    XmssMtShake_40_2_512,
    XmssMtShake_40_4_256,
    XmssMtShake_40_4_512,
    XmssMtShake_40_8_256,
    XmssMtShake_40_8_512,
    XmssMtShake_60_3_256,
    XmssMtShake_60_3_512,
    XmssMtShake_60_6_256,
    XmssMtShake_60_6_512,
    XmssMtShake_60_12_256,
    XmssMtShake_60_12_512,
    XmssMtShake256_20_2_192,
    XmssMtShake256_20_2_256,
    XmssMtShake256_20_4_192,
    XmssMtShake256_20_4_256,
    XmssMtShake256_40_2_192,
    XmssMtShake256_40_2_256,
    XmssMtShake256_40_4_192,
    XmssMtShake256_40_4_256,
    XmssMtShake256_40_8_192,
    XmssMtShake256_40_8_256,
    XmssMtShake256_60_3_192,
    XmssMtShake256_60_3_256,
    XmssMtShake256_60_6_192,
    XmssMtShake256_60_6_256,
    XmssMtShake256_60_12_192,
    XmssMtShake256_60_12_256,
    XmssParameter,
    // XMSS single-tree parameter sets
    XmssSha2_10_192,
    XmssSha2_10_256,
    XmssSha2_10_512,
    XmssSha2_16_192,
    XmssSha2_16_256,
    XmssSha2_16_512,
    XmssSha2_20_192,
    XmssSha2_20_256,
    XmssSha2_20_512,
    XmssShake_10_256,
    XmssShake_10_512,
    XmssShake_16_256,
    XmssShake_16_512,
    XmssShake_20_256,
    XmssShake_20_512,
    XmssShake256_10_192,
    XmssShake256_10_256,
    XmssShake256_16_192,
    XmssShake256_16_256,
    XmssShake256_20_192,
    XmssShake256_20_256,
};

pub use xmss::{DetachedSignature, KeyPair, Signature, SigningKey, VerifyingKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_sha2_10_256_sign_verify() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        let message = b"test message";
        let sig = kp.signing_key().sign(message).unwrap();

        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_xmss_sha2_10_256_bad_signature() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        let message = b"test message";
        let sig = kp.signing_key().sign(message).unwrap();

        // Corrupt the signature
        let mut sig_bytes = sig.as_ref().to_vec();
        sig_bytes[10] ^= 0xFF;
        let bad_sig = Signature::<XmssSha2_10_256>::try_from(sig_bytes).unwrap();

        let result = kp.verifying_key().verify(&bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_xmssmt_sha2_20_2_256_sign_verify() {
        let mut kp = KeyPair::<XmssMtSha2_20_2_256>::generate(&mut rand::rng()).unwrap();

        let message = b"test message for xmssmt";
        let sig = kp.signing_key().sign(message).unwrap();

        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_multiple_signatures() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        for i in 0..3 {
            let msg = format!("message {}", i);
            let sig = kp.signing_key().sign(msg.as_bytes()).unwrap();
            let recovered = kp.verifying_key().verify(&sig).unwrap();
            assert_eq!(recovered, msg.as_bytes());
        }
    }

    #[test]
    fn test_xmss_sign_detached_verify() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        let message = b"detached test message";
        let sig = kp.signing_key().sign_detached(message).unwrap();

        // Detached signature should not contain the message
        let full_sig = kp.signing_key().sign(b"another").unwrap();
        assert!(sig.as_ref().len() < full_sig.as_ref().len());

        kp.verifying_key().verify_detached(&sig, message).unwrap();

        // Wrong message should fail
        assert!(
            kp.verifying_key()
                .verify_detached(&sig, b"wrong message")
                .is_err()
        );
    }

    #[test]
    fn test_xmss_verify_truncated_signature() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        let sig = kp.signing_key().sign(b"test message").unwrap();

        // Truncate the signature to be too short
        let short_bytes = &sig.as_ref()[..sig.as_ref().len() / 2];
        let short_sig = Signature::<XmssSha2_10_256>::try_from(short_bytes).unwrap();

        assert!(kp.verifying_key().verify(&short_sig).is_err());
    }

    #[test]
    fn test_key_exhaustion() {
        let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        // Modify the index to be at the last valid position (2^10 - 1 = 1023).
        let mut sk_bytes = kp.signing_key().as_ref().to_vec();
        // Index is at bytes[4..8] (after OID), big-endian.
        sk_bytes[4] = 0x00;
        sk_bytes[5] = 0x00;
        sk_bytes[6] = 0x03;
        sk_bytes[7] = 0xFF; // 1023
        let mut last_sk = SigningKey::<XmssSha2_10_256>::try_from(sk_bytes).unwrap();

        // Signing at the last index should succeed.
        let sig = last_sk.sign(b"last message").unwrap();
        let recovered = kp.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, b"last message");

        // Signing again should fail with KeyExhausted.
        let result = last_sk.sign(b"one more");
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_keygen() {
        // Sequential seed pattern: SK_SEED || SK_PRF || PUB_SEED
        let seed: Vec<u8> = (0u8..96).collect();

        let kp1 = KeyPair::<XmssSha2_10_256>::from_seed(&seed).unwrap();
        let mut kp2 = KeyPair::<XmssSha2_10_256>::from_seed(&seed).unwrap();

        // Same seed must produce identical keys.
        assert_eq!(kp1.verifying_key(), kp2.verifying_key());

        // Sign with one, verify with the other's public key.
        let sig = kp2.signing_key().sign(b"deterministic test").unwrap();
        let recovered = kp1.verifying_key().verify(&sig).unwrap();
        assert_eq!(recovered, b"deterministic test");
    }

    #[test]
    fn test_verifying_key_from_signing_key() {
        let kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

        // Derive verifying key from signing key.
        let derived_pk = VerifyingKey::from(kp.signing_key_ref());
        assert_eq!(kp.verifying_key(), &derived_pk);
    }

    /// Decodes a hex string to bytes. Panics on invalid input (test-only).
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    /// KAT verification test using liboqs XMSS-SHA2_10_256 known-answer test vectors.
    #[test]
    fn test_kat_xmss_sha2_10_256_verify() {
        let pk_hex = "00000001B901B8D9332FE458EB6DE87AF74655D0B5AD936A66FDB6AC9D1B8CF25BB6DB8404562AD35E8ECAFAAFDA16981CDAA147606BEEA62801342AF13C8B5535F72F94";
        let msg_hex = "B338DD755D5618C464AB331F14DE3DD4A358BBA00D28FB35236741E902F7B248CE";
        let sm_hex = concat!(
            "00000000404DFF9B9F3931FE6158FFF355A8EE715C9BC6A87FE6627928F3CA10",
            "55FA7010C534B0D4C6FFDF4DBFE00E72405EFE83BBCF19AA2030A8CB16380848",
            "2B6376FF8CE01FB8090F4842896A1EA5E9282F35CACD245A4B9DE9FE84E93158",
            "51D68A72B3ECB9F440937C8BA4AC3F0429246CBC2777E8B92D84F4BA49FAB894",
            "65FCB0FC8017E582746F531B4697925154A22E2D6A0F1B81913438000C295153",
            "D7ADCA8F852C50D360F65F887479E9631A2CA30FE3AD92E7BF648643835F4F8C",
            "C081A6C951B83B77608A08C021821DA61962CFCC8E97D75441921D39C5AD5375",
            "43EFBAF0345DC70826E6E950929570C72E51619600C58D932A72657B19AF163E",
            "0B8F7AAF2949A5EB26C517909E0E663E36753491182975206009107509DFFC89",
            "8D308B903E84A8B29718BF7125397AFF5467D53CF8F36EB945B6B98D48E81C01",
            "74A0E03541D24369CF8EDDA4288FFA615D16FBC7355CFC0966BA9256E5B8A44D",
            "A95760DFB61301B10FD3E82436E267DB089773E43B984297D1E0D395DCC77FCF",
            "ECCEFEBD4B80B3F241872EA251DA466CA6C5324346F4B5E6886654A86592641A",
            "8C32AC554261B2D9130462C976B039E593F873AD1712820FF3E723FE57F13775",
            "1AB3CA8B5B20D28D1B9384DF1D710AC39FAF699989418B7856C2034C695A693E",
            "CC336EB472DE5049C743089529695B028F2F72BE0893E59169E9A2376C64BC5C",
            "CAC5482E5A6E9C88D710A3FF8F23C206B09D314BF50568228B1BACF1CE330D52",
            "9BD3793D7C7CD9EC770C111D9681D6F1B97D908CBBD436444853FEB47F234D31",
            "F5E92B9E0465D67AC0FE48859126BEFA7F7D121A67C2C2970B37B8081B4E73C5",
            "A21A41F60160A61FAFBD48649A3D2032C1679A67F348E3E25275FCD9AF650937",
            "FEB0A30F25878CEED7D6CA693518B5A2F5418135EA9316EFFDECDB1DFFC9EE3A",
            "62EFF0E66F3D05BD9D5F8679B536BB6D39792B28DF2481A6EECB9BEE40B11A10",
            "D39A90EA1AAC47BF956FBFE9B0427B599B9BC024F326515E71615419423FEC3F",
            "19F621D49B6EED59F129A6B1411B7B1AFCF073095D57B03F25A16F946ED716BF",
            "705F567A151BE85B8E8195CC2F070BFD482702182B8A4A43ED942F6BD3CBF9DE",
            "7E8AEB17C41E1C009C94FF4A2050E3731088B75474B38DC52BADF53C7DCD3FB9",
            "8D023649FC4799CE060ADDACEC7CD4E656074E631C1CB8AEF88EFEE0817C2E3D",
            "79E287F4510E48DFB7E23CB49D6FCA39A1E0F471F16A8BB65AF02150D059036D",
            "00386DD287BEA4D52FB263B57AE5ADD901CADE838B1D7347D9E47EAF6456148C",
            "6C4E44B0FA3DFCF5C9CEC2D80AD509A65AEF0E3E663B7F31BCA437311BA799D",
            "4C2ACC138F85D73CB40792FF03F8F20427D951444990CA3976A71368A7DC1455",
            "E880722F06F02163BC712E852A914F22E5675EB9B1C6C8B7FD20A8880AD2EEF9",
            "7982C065C937BD3639357E4C7450CBDA0B51CCA8E3E078DC760FD99EBF646B82",
            "369576539B2BD5B2C866ED5AE94423A5CE18C685352398D01C983F080D7BEB8A",
            "9243AAA9AC1DDCC1B058B92BEAD301E8F3B8F5EF71EEE7966302B44D2E26D2A0",
            "2393713E5D4D3FEF42196FAA368274C78C2932D22840ECA6018CE7D16B19A072",
            "7CB1966EB28B57D137C5264CC2E627F24A3BAD50EA4F75C7BD8998709C01ED5A",
            "CFFF0891934E94DA2CACCA212FB48BE3F9EAA310547E73C388D881F36AE21EFE",
            "DD23744F6B07C5D6D2776C191ED41E607316F61BBEF7A20E1A03150AE833D189",
            "52AE35188FBFDFA55C12A388836717BB2BDD97E89121C56C3B53E8198242315C",
            "9E438512E0C8354A3E599CB7217AE688647A72985606BBD0720F6FA5C5B6F70E",
            "88234EE54C6DB0A41106C866564650829FE4B232635B06B18240C9F86369C75B",
            "2F7D237211A380C43F95D362E0680D9EA2CA47E1DC8C49703E22650B765F847A",
            "D86BE25A3B7630D640A0097632DF13F600E8A025DD9A1FC67B0EB09C1CA9FA39",
            "23896927DEE1E3CC0C81F4B82E43B89CACC69C9B8ADCA1670F7D4E50DB7BCD94",
            "C2115E75F2BFD2336DA5A304D0F3455927360BF5040E95D1454106F2A8A7CD27",
            "D5510E7B5BE7B5B9EDEFDC3D4249D655C51F4C1DBA0F359BE4769AB66EDBC802",
            "824E9AB866E8EEAA2FEB1CC855F0A745AAC84A610DF0238112C6519F8E7346C4",
            "5331A6036F84D5B6250F4B5BC0A2A6A31DAF9C60EB13C20CC649A18E27A6C98B",
            "82F08E21706A8BDF338CC69C1679D25ECFF733A721211C1F6DD28091AAA9C93B",
            "047EFCD2C8A55F2DA65E616F07DCC0F44081D4E359C1688A00F062EC925D2443",
            "2862B547BB70F2AF126A3DABA5C918B224DE444B8733E6FA601B3D349307E945",
            "83D0EC976AEDA2B90972324B3ACE8C7B79A67723AEA037E12DA9EFA9CA9668A4",
            "F5FDADFB9EEE13398921F5023E354A6894825431DBA7317E6A6F69F0E77294BC",
            "D02D7616E75AC31EC528FC070B8C34027C4E9CD0672903412FCA6B723650D56A",
            "F562069312FC7EF1891A77E1A3F29D810C205EE212E75863F3B8B1ED216DF888",
            "ADD07AFF45F1B5C01196329311414797CD5F67FFC54AAD04C803FF7E83C2E8BA",
            "224CE83695BB7916AC42B1861F5CB527FDBCD82DBFA31C5ACF981D841420383750",
            "4263C96A0015841FBCC721F96D50A86D6E096AB54AF9980F06CEE6341C78D658",
            "3F6BAE8081B3C44B0F10FB7300874B5011FF0F97C52F975A31355884C2F12B6F",
            "FEE20E8371D38183C9D04977BFA037C9BD4DD7F7CE203FD7FAD3852B3C2AE9D0",
            "78ADEC70DB1A7140EF1114EBB03E8DE03237E0A27FF510015AC76FCEFE4EBD4C",
            "3A1B6C67DB2A82FE2B1BF18723DB0F29FE4AD47B2EEF22AC3C6661CFA7DA747",
            "6D23B470FA2E0441B6473EBD291791F09B4ADA70A5286EB05167BD59BFD8C464",
            "27413D60692382EFB7882F60DC53AAAFDF2014CA7D27F8FA93C187A8371B4179",
            "6557AE739912E5991C713532E81FA57F9BA562E1D3026D2D2D7373D99871BC62",
            "768AD70D3DB184EABED83E30C11C9BC62F3340923A0082B987EC45CC7BD1DB4B",
            "2B15E8AD3EAD74E96D8C20D85617BBEDC0BDAF8ED48B7EE8D7C42990028EC066",
            "9AFC0861C22F2E9109F9BB35426BDDB4A69EB8F45CD5B226F92E8026F1E62DE1",
            "DE435A4FC0CAEDA91C38A88F0037BDB296CD7B07FF040B1E08F02711E946B307",
            "A5A38487F53070985B8E28BE6CCE809F34100F0CA780996CD38E91BA7773BB63",
            "2D0BE7978F3AF3A92B961BD3A8759590726D6C1811F9E0BCA87377334E7C1F12",
            "FE37401CA0200823938C816ED98981521470F7F2CCDD69D85E7530EBF39E3A59",
            "2B1C09BC6C352C3FDB108FB26E7ACD3D5A4FC0442962E2C09651AC0D026E370F",
            "1EE1A8219C4833D70793D6E581FD25B0E95FAB1EDA67232C2FA12C4E379A6627",
            "E75AD408C1D2526005F2567CED8608E88CF53064FCDC58007198ADFA860F9FED",
            "1DF80EFACC768A0A063E1AFEE6DF1BE3483105B1C45EB50BF7863B4278422CEB",
            "A9001EA00299AC0415BF28A9C49CC2E92FC15565B547538A027886C6EB0D83B7",
            "1138CE1A",
        );

        let pk_bytes = hex_decode(pk_hex);
        let msg_bytes = hex_decode(msg_hex);
        let sm_bytes = hex_decode(sm_hex);

        assert_eq!(pk_bytes.len(), 68); // 4 OID + 32 root + 32 PUB_SEED
        assert_eq!(msg_bytes.len(), 33);
        assert_eq!(sm_bytes.len(), 2500);

        let pk = VerifyingKey::<XmssSha2_10_256>::try_from(pk_bytes.as_slice())
            .expect("failed to parse KAT public key");
        let sig = DetachedSignature::<XmssSha2_10_256>::try_from(sm_bytes.as_slice())
            .expect("failed to parse KAT signature");

        pk.verify_detached(&sig, &msg_bytes)
            .expect("KAT verification failed — signature should be valid");

        // Also verify that a corrupted message fails.
        let mut bad_msg = msg_bytes.clone();
        bad_msg[0] ^= 0xFF;
        assert!(
            pk.verify_detached(&sig, &bad_msg).is_err(),
            "KAT verification should fail with corrupted message"
        );
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;

        #[test]
        fn test_signing_key_serde_json_roundtrip() {
            let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let sk = kp.signing_key();

            let json = serde_json::to_string(&*sk).unwrap();
            let sk2: SigningKey<XmssSha2_10_256> = serde_json::from_str(&json).unwrap();
            assert_eq!(*sk, sk2);
        }

        #[test]
        fn test_verifying_key_serde_json_roundtrip() {
            let kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let pk = kp.verifying_key();

            let json = serde_json::to_string(pk).unwrap();
            let pk2: VerifyingKey<XmssSha2_10_256> = serde_json::from_str(&json).unwrap();
            assert_eq!(*pk, pk2);
        }

        #[test]
        fn test_signature_serde_json_roundtrip() {
            let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let sig = kp.signing_key().sign(b"test message").unwrap();

            let json = serde_json::to_string(&sig).unwrap();
            let sig2: Signature<XmssSha2_10_256> = serde_json::from_str(&json).unwrap();
            assert_eq!(sig, sig2);
        }

        #[test]
        fn test_signing_key_postcard_roundtrip() {
            let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let sk = kp.signing_key();

            let bytes = postcard::to_allocvec(&*sk).unwrap();
            let sk2: SigningKey<XmssSha2_10_256> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(*sk, sk2);
        }

        #[test]
        fn test_verifying_key_postcard_roundtrip() {
            let kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let pk = kp.verifying_key();

            let bytes = postcard::to_allocvec(pk).unwrap();
            let pk2: VerifyingKey<XmssSha2_10_256> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(*pk, pk2);
        }

        #[test]
        fn test_signature_postcard_roundtrip() {
            let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let sig = kp.signing_key().sign(b"test message").unwrap();

            let bytes = postcard::to_allocvec(&sig).unwrap();
            let sig2: Signature<XmssSha2_10_256> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(sig, sig2);
        }
    }

    #[cfg(feature = "pkcs8")]
    mod pkcs8_tests {
        use super::*;
        use ::pkcs8::EncodePrivateKey;

        #[test]
        fn test_pkcs8_roundtrip() {
            let kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();
            let der = kp.to_pkcs8_der().expect("PKCS#8 encode failed");
            let kp2 = KeyPair::<XmssSha2_10_256>::from_pkcs8_der(der.as_bytes())
                .expect("PKCS#8 decode failed");
            assert_eq!(kp.verifying_key(), kp2.verifying_key());
        }
    }
}
