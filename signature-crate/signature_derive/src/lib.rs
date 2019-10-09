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
use syn::{Attribute, Meta, NestedMeta};
use synstructure::{decl_derive, AddBounds};

/// Name of the digest attribute
const DIGEST_ATTRIBUTE_NAME: &str = "digest";

/// Derive the `Signer` trait for `DigestSigner` types
fn derive_signer(mut s: synstructure::Structure) -> TokenStream {
    let digest_path = DigestAttribute::parse(&s).into_meta("Signer");

    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Signer<S> for @Self
        where
            S: Signature,
            Self: signature::DigestSigner<#digest_path, S>
        {
            fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error> {
                self.try_sign_digest(#digest_path::new().chain(msg))
            }
        }
    })
}
decl_derive!([Signer, attributes(digest)] => derive_signer);

/// Derive the `Verifier` trait for `DigestVerifier` types
fn derive_verifier(mut s: synstructure::Structure) -> TokenStream {
    let digest_path = DigestAttribute::parse(&s).into_meta("Verifier");

    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Verifier<S> for @Self
        where
            S: Signature,
            Self: signature::DigestVerifier<#digest_path, S>
        {
            fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
                self.verify_digest(#digest_path::new().chain(msg), signature)
            }
        }
    })
}
decl_derive!([Verifier, attributes(digest)] => derive_verifier);

/// The `#[digest(...)]` attribute passed to the proc macro
#[derive(Default)]
struct DigestAttribute {
    digest: Option<Meta>,
}

impl DigestAttribute {
    /// Parse attributes from the incoming AST
    fn parse(s: &synstructure::Structure<'_>) -> Self {
        let mut result = Self::default();

        for v in s.variants().iter() {
            for attr in v.ast().attrs.iter() {
                result.parse_attr(attr);
            }
        }

        result
    }

    /// Parse attribute and handle `#[digest(...)]` attribute
    fn parse_attr(&mut self, attr: &Attribute) {
        let meta = attr
            .parse_meta()
            .unwrap_or_else(|e| panic!("error parsing digest attribute: {:?} ({})", attr, e));

        if let Meta::List(list) = meta {
            if !list.path.is_ident(DIGEST_ATTRIBUTE_NAME) {
                return;
            }

            for nested_meta in &list.nested {
                if let NestedMeta::Meta(meta) = nested_meta {
                    if self.digest.is_none() {
                        self.digest = Some(meta.to_owned());
                    } else {
                        panic!("multiple digest attributes in custom derive");
                    }
                } else {
                    panic!("malformed digest attribute: {:?}", nested_meta);
                }
            }
        }
    }

    /// Convert parsed attributes into the recovered `Meta`
    fn into_meta(self, trait_name: &str) -> Meta {
        self.digest.unwrap_or_else(|| {
            panic!(
                "#[digest(...)] attribute is mandatory when deriving {}",
                trait_name
            )
        })
    }
}
