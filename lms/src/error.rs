//! Error types

// TODO: review errors and make sure they are appropriate
// I expect it does not make sense to use a single error type for both
// LMS and OTS parsing, as we are currently doing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The error returned by `TryFrom<&[u8]>` impls
pub enum LmsDeserializeError {
    /// Length of the slice was `< 4` and no algorithm can be parsed
    NoAlgorithm,
    /// The parsed algorithm does not match the requested deserialization
    WrongAlgorithm,
    /// The slice did not contain enough data
    TooShort,
    /// The slice contained too much data
    TooLong,
    /// The parsed `q` value was too large
    InvalidQ,
}
