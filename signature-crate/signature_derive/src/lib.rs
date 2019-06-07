//! Custom derive support for the `signature` crate.
//!
//! This crate can be used to derive `Signer` and `Verifier` impls for
//! types that impl `DigestSigner` or `DigestVerifier` respectively.

#![crate_type = "proc-macro"]
#![recursion_limit = "128"]
#![deny(warnings, unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]

extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::quote;
use synstructure::{decl_derive, AddBounds};

/// Derive the `Signer` trait for `DigestSigner` types
fn derive_signer(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        use signature::{DigestSignature, DigestSigner, Error};

        gen impl<S> Signer<S> for @Self
        where
            S: DigestSignature,
            Self: DigestSigner<S::Digest, S>,
        {
            fn try_sign(&self, msg: &[u8]) -> Result<S, Error> {
                self.try_sign_digest(S::Digest::new().chain(msg))
            }
        }
    })
}
decl_derive!([Signer] => derive_signer);

/// Derive the `Verifier` trait for `DigestVerifier` types
fn derive_verifier(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        use signature::{DigestSignature, DigestVerifier, Error};

        gen impl<S> Verifier<S> for @Self
        where
            S: DigestSignature,
            Self: DigestVerifier<S::Digest, S>,
        {
            fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
                self.verify_digest(S::Digest::new().chain(msg), signature)
            }
        }
    })
}
decl_derive!([Verifier] => derive_verifier);

#[cfg(test)]
mod tests {
    use super::*;
    use synstructure::test_derive;

    #[test]
    fn signer() {
        test_derive! {
            derive_signer {
                struct MySigner<C: EllipticCurve> {
                    scalar: Scalar<C::ScalarSize>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_Signer_S_FOR_MySigner: () = {
                    use signature::{DigestSignature, DigestSigner, Error};

                    impl<S, C: EllipticCurve> Signer<S> for MySigner<C>
                    where
                        S: DigestSignature,
                        Self: DigestSigner<S::Digest, S>,
                    {
                        fn try_sign(&self, msg: &[u8]) -> Result <S, Error> {
                            self.try_sign_digest(S::Digest::new().chain(msg))
                        }
                    }
                };
            }
            no_build // tests in `signature-crate/tests`
        }
    }

    #[test]
    fn verifier() {
        test_derive! {
            derive_verifier {
                struct MyVerifier<C: EllipticCurve> {
                    point: UncompressedPoint<C>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_Verifier_S_FOR_MyVerifier: () = {
                    use signature::{DigestSignature, DigestVerifier, Error};

                    impl<S, C: EllipticCurve> Verifier<S> for MyVerifier<C>
                    where
                        S: DigestSignature,
                        Self: DigestVerifier<S::Digest, S>,
                    {
                        fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
                            self.verify_digest(S::Digest::new().chain(msg), signature)
                        }
                    }
                };
            }
            no_build // tests in `signature-crate/tests`
        }
    }
}
