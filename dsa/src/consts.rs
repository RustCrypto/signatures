//!
//! DSA-related constants (like parameter sizes)
//!

macro_rules! define_param_size {
    ($l:literal, $n:literal) => {
        ::paste::paste! {
            #[doc = "DSA parameter size constant; L = " $l ", N = " $n]
            pub const [<DSA_ $l _ $n>]: (u32, u32) = ($l, $n);
        }
    };
    (deprecated: $l:literal, $n:literal) => {
        ::paste::paste! {
            #[deprecated(note="This size constant has a security strength of under 112 bits per SP 800-57 Part 1 Rev. 5")]
            #[doc = "DSA parameter size constant; L = " $l ", N = " $n]
            pub const [<DSA_ $l _ $n>]: (u32, u32) = ($l, $n);
        }
    };
}

define_param_size!(deprecated: 1024, 160);
define_param_size!(2048, 224);
define_param_size!(2048, 256);
define_param_size!(3072, 256);
