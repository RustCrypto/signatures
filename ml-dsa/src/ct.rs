//! Constant-time selection utilities.
//!
//! Provides a [`CtSelectExt`] trait for branchless conditional selection,
//! preventing timing side-channels from branch prediction on
//! secret-dependent values.
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

