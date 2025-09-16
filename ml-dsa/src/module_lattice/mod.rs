//! This module contains functions that should be common across ML-KEM and ML-DSA:
//!
//! * Linear algebra with degree-256 polynomials over a prime-order field, vectors of such
//!   polynomials, and NTT polynomials / vectors.
//!
//! * Packing of polynomials into coefficients with a specified number of bits.
//!
//! * Utility functions such as truncating integers, flattening arrays of arrays, and unflattening
//!   arrays into arrays of arrays.
//!
//! While this is currently a module within the `ml_dsa` crate, the idea of pulling it out is that
//! it could be a separate crate on which both the `ml_dsa` crate and the `ml_kem` crate depend.

// XXX(RLB) There are no unit tests in this module right now, because the algebra and encode/decode
// routines all require a field, and the concrete field definitions are down in the dependent
// modules.  Maybe we should pull the field definitions up into this module so that we can verify
// that everything works.  That might also let us make private some of the tools used to build
// things up.

/// Linear algebra with degree-256 polynomials over a prime-order field, vectors of such
/// polynomials, and NTT polynomials / vectors
pub(crate) mod algebra;

/// Packing of polynomials into coefficients with a specified number of bits.
pub(crate) mod encode;

/// Utility functions such as truncating integers, flattening arrays of arrays, and unflattening
/// arrays into arrays of arrays.
pub(crate) mod util;
