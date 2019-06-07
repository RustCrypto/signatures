//! Crate-local prelude (for alloc-dependent features like `Vec`)

#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use alloc::vec::Vec;

#[cfg(feature = "std")]
pub use std::vec::Vec;
