//! QEMU stack watermark probe. Unsafe code is confined to this standalone measurement harness.
#![no_std]
#![no_main]

use core::{
    hint::black_box,
    mem::{MaybeUninit, size_of},
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
#[cfg(feature = "low-memory")]
use ml_dsa::SigningWorkspace;
use ml_dsa::{Keypair, Seed, Signature, SigningKey, VerifyingKey};

#[cfg(all(feature = "ml-dsa-65", feature = "ml-dsa-87"))]
compile_error!("select only one parameter set");
#[cfg(feature = "ml-dsa-87")]
type Params = ml_dsa::MlDsa87;
#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
type Params = ml_dsa::MlDsa65;
#[cfg(not(any(feature = "ml-dsa-65", feature = "ml-dsa-87")))]
type Params = ml_dsa::MlDsa44;

static mut KEY: MaybeUninit<SigningKey<Params>> = MaybeUninit::uninit();
static mut VK: MaybeUninit<VerifyingKey<Params>> = MaybeUninit::uninit();
static mut SIG: MaybeUninit<Signature<Params>> = MaybeUninit::uninit();
#[cfg(feature = "low-memory")]
static mut WORKSPACE: SigningWorkspace<Params> = SigningWorkspace::<Params>::new();

#[inline(never)]
fn keygen() {
    unsafe {
        (*ptr::addr_of_mut!(KEY)).write(SigningKey::from_seed(black_box(&Seed::default())));
    }
}

#[inline(never)]
fn derive() {
    unsafe {
        (*ptr::addr_of_mut!(VK)).write((*ptr::addr_of!(KEY)).assume_init_ref().verifying_key());
    }
}

#[inline(never)]
fn sign() {
    let key = unsafe { (*ptr::addr_of!(KEY)).assume_init_ref() };
    #[cfg(not(feature = "low-memory"))]
    let sig = key
        .expanded_key()
        .sign_deterministic(black_box(b"stack probe"), &[])
        .unwrap();
    #[cfg(feature = "low-memory")]
    let sig = key
        .expanded_key()
        .sign_deterministic_with_workspace(black_box(b"stack probe"), &[], unsafe {
            &mut *ptr::addr_of_mut!(WORKSPACE)
        })
        .unwrap();
    unsafe {
        (*ptr::addr_of_mut!(SIG)).write(sig);
    }
}

#[inline(never)]
fn verify() {
    let (vk, sig) = unsafe {
        (
            (*ptr::addr_of!(VK)).assume_init_ref(),
            (*ptr::addr_of!(SIG)).assume_init_ref(),
        )
    };
    assert!(vk.verify_with_context(black_box(b"stack probe"), &[], black_box(sig)));
}

#[inline(never)]
fn measure(f: fn()) -> usize {
    unsafe extern "C" {
        static mut __sheap: u32;
        static _stack_start: u32;
    }
    // Paint only unused stack space. Leave a gap beneath this live frame and disable interrupts.
    cortex_m::interrupt::disable();
    let low = ptr::addr_of_mut!(__sheap);
    let sp = cortex_m::register::msp::read() as usize;
    let high = (sp - 256) & !3;
    let mut p = low;
    unsafe {
        while (p as usize) < high {
            p.write_volatile(0xa5a5a5a5);
            p = p.add(1);
        }
    }
    compiler_fence(Ordering::SeqCst);
    black_box(f)();
    compiler_fence(Ordering::SeqCst);
    p = low;
    unsafe {
        while (p as usize) < high && p.read_volatile() == 0xa5a5a5a5 {
            p = p.add(1);
        }
    }
    // Includes the startup and measurement caller frames; excludes static key/workspace storage.
    ptr::addr_of!(_stack_start) as usize - p as usize
}

#[entry]
fn main() -> ! {
    hprintln!(
        "key_bytes={} vk_bytes={} sig_bytes={}",
        size_of::<SigningKey<Params>>(),
        size_of::<VerifyingKey<Params>>(),
        size_of::<Signature<Params>>()
    );
    #[cfg(feature = "low-memory")]
    hprintln!("workspace_bytes={}", size_of::<SigningWorkspace<Params>>());
    for (name, f) in [
        ("keygen", keygen as fn()),
        ("derive", derive as fn()),
        ("sign", sign as fn()),
        ("verify", verify as fn()),
    ] {
        let peak = measure(f);
        hprintln!("{}={}", name, peak);
        #[cfg(feature = "low-memory")]
        if name == "sign" {
            assert!(
                peak <= 28 * 1024,
                "signing exceeded the 28 KiB stack budget"
            );
        }
    }
    debug::exit(debug::EXIT_SUCCESS);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    hprintln!("{}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {
        core::hint::spin_loop();
    }
}
