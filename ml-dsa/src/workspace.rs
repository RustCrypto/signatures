//! Caller-owned scratch for allocation-free signing with the `low-memory` feature.

use crate::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    algebra::{Elem, NttPolynomial, NttVector, Polynomial, Vector},
    ntt::{ntt_in_place, ntt_inverse_in_place},
};
use core::fmt;
use hybrid_array::{Array, typenum::U256};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable, inline signing scratch for the `low-memory` feature.
///
/// With `alloc` disabled, signing with this workspace performs no heap allocations. Firmware can
/// place it in a static cell or another exclusively borrowed SRAM region. It contains secret
/// intermediates: enable `zeroize` to erase them after signing and when the workspace is dropped.
/// A workspace must not be shared between simultaneous signing operations.
///
/// The concrete parameter sets provide a const `new` constructor, so a
/// static workspace can be initialized without constructing it on the stack.
pub struct SigningWorkspace<P: MlDsaParams> {
    pub(crate) z: Vector<P::L>,
    pub(crate) y_hat: NttVector<P::L>,
    pub(crate) w: Vector<P::K>,
    pub(crate) product: Polynomial,
    pub(crate) c_hat: NttPolynomial,
    pub(crate) hints: Array<Array<bool, U256>, P::K>,
}

impl<P: MlDsaParams> Default for SigningWorkspace<P> {
    fn default() -> Self {
        Self {
            z: Vector::default(),
            y_hat: NttVector::default(),
            w: Vector::default(),
            product: Polynomial::default(),
            c_hat: NttPolynomial::default(),
            hints: Array::default(),
        }
    }
}

macro_rules! impl_new {
    ($p:ty, $k:expr, $l:expr) => {
        impl SigningWorkspace<$p> {
            /// Construct empty scratch, including in a static initializer.
            #[must_use]
            pub const fn new() -> Self {
                Self {
                    z: Vector::new(Array(
                        [const { Polynomial::new(Array([Elem::new(0); 256])) }; $l],
                    )),
                    y_hat: NttVector::new(Array(
                        [const { NttPolynomial::new(Array([Elem::new(0); 256])) }; $l],
                    )),
                    w: Vector::new(Array(
                        [const { Polynomial::new(Array([Elem::new(0); 256])) }; $k],
                    )),
                    product: Polynomial::new(Array([Elem::new(0); 256])),
                    c_hat: NttPolynomial::new(Array([Elem::new(0); 256])),
                    hints: Array([Array([false; 256]); $k]),
                }
            }
        }
    };
}

impl_new!(MlDsa44, 4, 4);
impl_new!(MlDsa65, 6, 5);
impl_new!(MlDsa87, 8, 7);

impl<P: MlDsaParams> SigningWorkspace<P> {
    /// Dense multiplication avoids using secret coefficients as indices or skipping zeroes.
    pub(crate) fn multiply_secret(&mut self, secret: &Polynomial) {
        self.product.0.copy_from_slice(&secret.0);
        ntt_in_place(&mut self.product.0.0);
        for j in 0..256 {
            self.product.0[j] = self.product.0[j] * self.c_hat.0[j];
        }
        ntt_inverse_in_place(&mut self.product.0.0);
    }
}

impl<P: MlDsaParams> fmt::Debug for SigningWorkspace<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningWorkspace").finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> Zeroize for SigningWorkspace<P> {
    fn zeroize(&mut self) {
        self.z.zeroize();
        self.y_hat.zeroize();
        self.w.zeroize();
        self.product.zeroize();
        self.c_hat.zeroize();
        self.hints.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> Drop for SigningWorkspace<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: MlDsaParams> ZeroizeOnDrop for SigningWorkspace<P> {}
