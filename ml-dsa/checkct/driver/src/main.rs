#![no_std]
#![no_main]

// Compile the production modules directly to exercise private arithmetic without
// adding a public testing API to ml-dsa.
#[allow(dead_code)]
#[path = "../../../src/algebra.rs"]
mod algebra;
#[allow(dead_code)]
#[path = "../../../src/ntt.rs"]
mod ntt;

// These modules share the production algebra and parameter traits.
#[allow(dead_code)]
#[path = "../../../src/crypto.rs"]
mod crypto;
#[allow(dead_code)]
#[path = "../../../src/encode.rs"]
mod encode;
#[allow(dead_code)]
#[path = "../../../src/hint.rs"]
mod hint;
#[allow(dead_code)]
#[allow(non_snake_case)] // Match the production crate's specification notation.
#[path = "../../../src/param.rs"]
mod param;
#[allow(dead_code)]
#[path = "../../../src/sampling.rs"]
mod sampling;
#[path = "../../../src/signing/steps.rs"]
mod signing_steps;

use hybrid_array::{
    Array,
    sizes::{U32, U64},
};
use param::MlDsaParams;
type B32 = Array<u8, U32>;
type B64 = Array<u8, U64>;

mod driver;
mod params;
mod rng;
mod signing;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    panic!()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    __checkct_panic()
}

/// The analysis of a path stops when it reaches this function.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __checkct_panic() -> ! {
    loop {}
}
