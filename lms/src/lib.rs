//! LMS in Rust
//!
//! This is a strongly typed implementation of Leighton-Micali signatures. You
//! can find the private key, public key, and signature struct documentations in
//! their respective crates. See [lms] for anything LMS related and [ots] for
//! anything LM-OTS related.

pub mod error;
pub mod lms;
pub mod ots;

// TODO: do we need to expose these?
pub(crate) mod constants;
pub(crate) mod types;
