//! All types related to LMS

use crate::constants::ID_LEN;

/// Anything that has a corresponding `lmots_algorithm_type` or
/// `lms_algorithm_type` will implement this trait.
pub trait Typecode {
    /// The associated enum value for the algorithm type.
    const TYPECODE: u32;
}

/// The 16 byte identifier I from the LM-OTS algorithm.
pub type Identifier = [u8; ID_LEN];
