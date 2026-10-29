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

mod driver;
mod rng;

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
