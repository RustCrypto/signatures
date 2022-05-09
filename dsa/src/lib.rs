//!
//! DSA implementation in pure Rust
//!
//! # Disclaimer
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
//! INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//! IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//! TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//!
//! This software has **NOT** been audited and therefore most likely contains security issues!
//!
//! **USE AT YOUR OWN RISK!**
//!
//! ## Implementation progress
//!
//! - [x] Generate components
//! - [x] Generate keypair
//! - [x] Import keys
//! - [x] Export keys
//! - [x] Sign data
//! - [x] Verify signatures
//! - [ ] Test vectors
//!
//! ## Example
//!
//! Generate a DSA keypair
//!
//! ```
//! # use dsa::{consts::DSA_2048_256, Components, PrivateKey};
//! let mut csprng = rand::thread_rng();
//! let components = Components::generate(&mut csprng, DSA_2048_256);
//! let private_key = PrivateKey::generate(&mut csprng, components);
//! let public_key = private_key.public_key();
//! ```
//!
//! Create keypair from existing components
//!
//! ```
//! # use dsa::{Components, PrivateKey, PublicKey};
//! # use num_bigint::BigUint;
//! # use num_traits::One;
//! # let read_common_parameters = || (BigUint::one(), BigUint::one(), BigUint::one());
//! # let read_public_component = || BigUint::one();
//! # let read_private_component = || BigUint::one();
//! let (p, q, g) = read_common_parameters();
//! let components = Components::from_components(p, q, g);
//!
//! let x = read_public_component();
//! let public_key = PublicKey::from_components(components, x);
//!
//! let y = read_private_component();
//! let private_key = PrivateKey::from_components(public_key, y);
//! ```
//!

#![cfg_attr(not(feature = "signature-compat"), no_std)]
#![forbid(missing_docs, unsafe_code)]
#![deny(rust_2018_idioms)]

/// DSA object identifier as defined by RFC-3279, section 2.3.2
const DSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

pub use self::components::Components;
pub use self::privatekey::PrivateKey;
pub use self::publickey::PublicKey;
pub use self::signature::Signature;

// Re-export the types needed for de-/serialising keys to DER and PEM
pub use pkcs8;

#[cfg(feature = "signature-compat")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "signature-compat")))]
pub mod compat;
pub mod consts;

use num_bigint::BigUint;
use pkcs8::spki::ObjectIdentifier;

mod components;
mod generate;
mod privatekey;
mod publickey;
mod signature;

/// Returns a `BigUint` with the value 2
#[inline]
fn two() -> BigUint {
    BigUint::from(2_u8)
}
