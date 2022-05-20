macro_rules! define_param_size {
    ($l:literal, $n:literal) => {
        ::paste::paste! {
            #[doc = "DSA parameter size constant; L = " $l ", N = " $n]
            pub const [<DSA_ $l _ $n>]: Self = Self::custom($l, $n);
        }
    };
    (deprecated: $l:literal, $n:literal) => {
        ::paste::paste! {
            #[deprecated(note="This size constant has a security strength of under 112 bits per SP 800-57 Part 1 Rev. 5")]
            #[doc = "DSA parameter size constant; L = " $l ", N = " $n]
            pub const [<DSA_ $l _ $n>]: Self = Self::custom($l, $n);
        }
    };
}

/// DSA key size
pub struct KeySize {
    /// Bit size of p
    pub(crate) l: u32,

    /// Bit size of q
    pub(crate) n: u32,
}

impl KeySize {
    define_param_size!(deprecated: 1024, 160);
    define_param_size!(2048, 224);
    define_param_size!(2048, 256);
    define_param_size!(3072, 256);

    /// Define a custom parameter size
    ///
    /// **⚠ YOU MOST LIKELY DO NOT NEED TO AND SHOULD NOT USE THIS!**
    pub const fn custom(l: u32, n: u32) -> Self {
        Self { l, n }
    }
}
