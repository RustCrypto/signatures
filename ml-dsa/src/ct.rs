//! Constant-time selection utilities.
//!
//! Provides a [`ct_select!`] macro and supporting [`CtSelect`] trait for
//! branchless conditional selection, preventing timing side-channels from
//! branch prediction on secret-dependent values.
//!
//! This serves the same purpose as LLVM's `__builtin_ct_select` intrinsic
//! (introduced in LLVM 22). On x86-64 the intrinsic compiles to `cmov`;
//! on `AArch64` to `CSEL`. When Rust gains native access to the LLVM
//! intrinsic, the implementation here can be swapped transparently.
//!
//! See: <https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/>

use subtle::{Choice, ConditionallySelectable};

use crate::algebra::Elem;

/// Constant-time conditional selection trait.
///
/// Selects between two values based on a [`Choice`] without branching.
/// When `choice` is `1` (true), returns `b`; when `0` (false), returns `a`.
pub(crate) trait CtSelect: Sized {
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self;
}

impl CtSelect for u32 {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        u32::conditional_select(a, b, choice)
    }
}

impl CtSelect for u64 {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        u64::conditional_select(a, b, choice)
    }
}

impl CtSelect for Elem {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Elem::new(u32::conditional_select(&a.0, &b.0, choice))
    }
}

impl CtSelect for (Elem, Elem) {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        (
            Elem::ct_select(&a.0, &b.0, choice),
            Elem::ct_select(&a.1, &b.1, choice),
        )
    }
}

/// Branchless conditional select — the Rust equivalent of LLVM's
/// `__builtin_ct_select`.
///
/// Evaluates both `$if_true` and `$if_false` unconditionally, then
/// selects the result based on `$choice` using bitwise operations
/// (no CPU branch). Both expressions must have the same type, which
/// must implement [`CtSelect`].
///
/// `$choice` must be a [`subtle::Choice`]. Use `ct_eq`, `ct_gt`,
/// `ct_lt` from the `subtle` crate to produce [`Choice`] values from
/// constant-time comparisons.
///
/// # Examples
///
/// ```ignore
/// use subtle::ConstantTimeLess;
/// let result: u32 = ct_select!(a.ct_lt(&b), val_if_true, val_if_false);
/// ```
macro_rules! ct_select {
    ($choice:expr, $if_true:expr, $if_false:expr) => {{
        let if_true = $if_true;
        let if_false = $if_false;
        let choice: subtle::Choice = $choice;
        $crate::ct::CtSelect::ct_select(&if_false, &if_true, choice)
    }};
}

pub(crate) use ct_select;
