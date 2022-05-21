/// DSA key size
pub struct KeySize {
    /// Bit size of p
    pub(crate) l: u32,

    /// Bit size of q
    pub(crate) n: u32,
}

impl KeySize {
    /// DSA parameter size constant: L = 1024, N = 160
    #[deprecated(
        note = "This size constant has a security strength of under 112 bits per SP 800-57 Part 1 Rev. 5"
    )]
    pub const DSA_1024_160: Self = Self { l: 1024, n: 160 };

    /// DSA parameter size constant: L = 2048, N = 224
    pub const DSA_2048_224: Self = Self { l: 2048, n: 224 };

    /// DSA parameter size constant: L = 2048, N = 256
    pub const DSA_2048_256: Self = Self { l: 2048, n: 256 };

    /// DSA parameter size constant: L = 3072, N = 256
    pub const DSA_3072_256: Self = Self { l: 3072, n: 256 };
}
