use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    typenum::{IsLess, Le, NonZero},
    Digest, FixedOutput, HashMarker, OutputSizeUser,
};
use dsa::{Components, PrivateKey, PublicKey, Signature};
use num_bigint::BigUint;
use num_traits::Num;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use signature::DigestSigner;

fn dsa_1024_private_key() -> PrivateKey {
    let p = BigUint::from_str_radix(
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
                E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
                73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
                881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        16,
    )
    .unwrap();
    let q = BigUint::from_str_radix("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16).unwrap();
    let g = BigUint::from_str_radix(
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
            89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
            87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
            17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        16,
    )
    .unwrap();

    let x = BigUint::from_str_radix("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7", 16).unwrap();
    let y = BigUint::from_str_radix(
        "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
            92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
            4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
            82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B",
        16,
    )
    .unwrap();

    let components = Components::from_components(p, q, g);
    let public_key = PublicKey::from_components(components, y);

    PrivateKey::from_components(public_key, x)
}

const MESSAGE: &[u8] = b"sample";
const MESSAGE_2: &[u8] = b"test";

/// Generate a signature given the unhashed message and a private key
fn generate_signature<D>(private_key: PrivateKey, data: &[u8]) -> Signature
where
    D: Digest + CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    private_key.sign_digest(<D as Digest>::new().chain_update(data))
}

/// Generate a signature using the 1024-bit DSA key
fn generate_1024_signature<D>(data: &[u8]) -> Signature
where
    D: Digest + CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    generate_signature::<D>(dsa_1024_private_key(), data)
}

/// Create a signature container from the two components in their textual hexadecimal form
fn from_str_signature(r: &str, s: &str) -> Signature {
    Signature::from_components(
        BigUint::from_str_radix(r, 16).unwrap(),
        BigUint::from_str_radix(s, 16).unwrap(),
    )
}

/// Return the RFC 6979 test cases
///
/// # Returns
///
/// Vector of tuples.
/// First element is the message appended to the panic upon signature mismatch, the second one is the expected signature and the third element is a function
/// that generates an RFC-6979 signature using the `dsa` crate
fn cases() -> Vec<(Signature, Box<dyn Fn() -> Signature>)> {
    vec![
        // sha1, 1024, "sample"
        (
            from_str_signature(
                "2E1A0C2562B2912CAAF89186FB0F42001585DA55",
                "29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5",
            ),
            Box::new(|| generate_1024_signature::<Sha1>(MESSAGE)),
        ),
        // sha1, 1024, "test"
        (
            from_str_signature(
                "42AB2052FD43E123F0607F115052A67DCD9C5C77",
                "183916B0230D45B9931491D4C6B0BD2FB4AAF088",
            ),
            Box::new(|| generate_1024_signature::<Sha1>(MESSAGE_2)),
        ),
        // sha224, 1024, "sample"
        (
            from_str_signature(
                "4BC3B686AEA70145856814A6F1BB53346F02101E",
                "410697B92295D994D21EDD2F4ADA85566F6F94C1",
            ),
            Box::new(|| generate_1024_signature::<Sha224>(MESSAGE)),
        ),
        // sha224, 1024, "test"
        (
            from_str_signature(
                "6868E9964E36C1689F6037F91F28D5F2C30610F2",
                "49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F",
            ),
            Box::new(|| generate_1024_signature::<Sha224>(MESSAGE_2)),
        ),
        // sha256, 1024, "sample"
        (
            from_str_signature(
                "81F2F5850BE5BC123C43F71A3033E9384611C545",
                "4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89",
            ),
            Box::new(|| generate_1024_signature::<Sha256>(MESSAGE)),
        ),
        // sha256, 1024, "test"
        (
            from_str_signature(
                "22518C127299B0F6FDC9872B282B9E70D0790812",
                "6837EC18F150D55DE95B5E29BE7AF5D01E4FE160",
            ),
            Box::new(|| generate_1024_signature::<Sha256>(MESSAGE_2)),
        ),
        // sha384, 1024, "sample"
        (
            from_str_signature(
                "07F2108557EE0E3921BC1774F1CA9B410B4CE65A",
                "54DF70456C86FAC10FAB47C1949AB83F2C6F7595",
            ),
            Box::new(|| generate_1024_signature::<Sha384>(MESSAGE)),
        ),
        // sha384, 1024, "test"
        (
            from_str_signature(
                "854CF929B58D73C3CBFDC421E8D5430CD6DB5E66",
                "91D0E0F53E22F898D158380676A871A157CDA622",
            ),
            Box::new(|| generate_1024_signature::<Sha384>(MESSAGE_2)),
        ),
        // sha512, 1024, "sample"
        (
            from_str_signature(
                "16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B",
                "02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C",
            ),
            Box::new(|| generate_1024_signature::<Sha512>(MESSAGE)),
        ),
        // sha512, 1024, "test"
        (
            from_str_signature(
                "8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0",
                "7C670C7AD72B6C050C109E1790008097125433E8",
            ),
            Box::new(|| generate_1024_signature::<Sha512>(MESSAGE_2)),
        ),
    ]
}

#[test]
fn rfc6979_signatures() {
    for (idx, (expected, gen_fn)) in cases().into_iter().enumerate() {
        assert_eq!(expected, gen_fn(), "{}th test case", idx);
    }
}
