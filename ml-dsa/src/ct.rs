//! Constant-time selection utilities.
//!
//! Provides a [`ct_select!`] macro and supporting [`CtSelectExt`] trait for
//! branchless conditional selection, preventing timing side-channels from
//! branch prediction on secret-dependent values.
//!
//! Built on the [`ctutils`] crate, which uses the [`cmov`] crate for
//! architecture-specific predication intrinsics (`cmov` on x86-64,
//! `CSEL` on `AArch64`).
//!
//! See: <https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/>

use ctutils::Choice;

use crate::algebra::Elem;

/// Constant-time conditional selection for types not covered by
/// [`ctutils::CtSelect`] (which cannot be impl'd for foreign types
/// due to the orphan rule).
///
/// Selects between two values based on a [`Choice`] without branching.
/// When `choice` is `TRUE`, returns `b`; when `FALSE`, returns `a`.
pub(crate) trait CtSelectExt: Sized {
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self;
}

impl CtSelectExt for u32 {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ctutils::CtSelect::ct_select(a, b, choice)
    }
}

impl CtSelectExt for u64 {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ctutils::CtSelect::ct_select(a, b, choice)
    }
}

impl CtSelectExt for Elem {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Elem::new(ctutils::CtSelect::ct_select(&a.0, &b.0, choice))
    }
}

impl CtSelectExt for (Elem, Elem) {
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        (
            CtSelectExt::ct_select(&a.0, &b.0, choice),
            CtSelectExt::ct_select(&a.1, &b.1, choice),
        )
    }
}

/// Branchless conditional select — the Rust equivalent of LLVM's
/// `__builtin_ct_select`.
///
/// Evaluates both `$if_true` and `$if_false` unconditionally, then
/// selects the result based on `$choice` using predication instructions
/// (no CPU branch). Both expressions must have the same type, which
/// must implement [`CtSelectExt`].
///
/// `$choice` must be a [`ctutils::Choice`]. Use `ct_eq`, `ct_gt`,
/// `ct_lt` from the `ctutils` crate to produce [`Choice`] values from
/// constant-time comparisons.
///
/// # Examples
///
/// ```ignore
/// use ctutils::CtLt;
/// let result: u32 = ct_select!(a.ct_lt(&b), val_if_true, val_if_false);
/// ```
macro_rules! ct_select {
    ($choice:expr, $if_true:expr, $if_false:expr) => {{
        let if_true = $if_true;
        let if_false = $if_false;
        let choice: ctutils::Choice = $choice;
        $crate::ct::CtSelectExt::ct_select(&if_false, &if_true, choice)
    }};
}

pub(crate) use ct_select;
