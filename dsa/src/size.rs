use core::cmp::Ordering;
use crypto_bigint::Limb;

/// DSA key size
#[derive(Clone, Debug, Copy)]
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

    /// Create a KeySize from other, potentially unsafe, key lengths
    ///
    /// This aims at supporting non-standard or older/weak keys.
    #[cfg(feature = "hazmat")]
    pub(crate) fn other(l: u32, n: u32) -> Self {
        Self { l, n }
    }
}

impl KeySize {
    pub(crate) fn l_aligned(&self) -> u32 {
        self.l.div_ceil(Limb::BITS) * Limb::BITS
    }

    pub(crate) fn n_aligned(&self) -> u32 {
        self.n.div_ceil(Limb::BITS) * Limb::BITS
    }

    pub(crate) fn matches(&self, l: u32, n: u32) -> bool {
        l == self.l_aligned() && n == self.n_aligned()
    }
}

impl PartialEq for KeySize {
    fn eq(&self, other: &Self) -> bool {
        self.l_aligned() == other.l_aligned() && self.n_aligned() == other.n_aligned()
    }
}

impl PartialOrd for KeySize {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let l = self.l_aligned().partial_cmp(&other.l_aligned())?;
        let n = self.n_aligned().partial_cmp(&other.n_aligned())?;

        Some(l.then(n))
    }
}
