# Cortex-M33 stack probe

This standalone, allocator-free executable runs key generation, public-key derivation, signing,
and verification on QEMU's `mps2-an505` Cortex-M33 model. Its release profile uses optimization level
3, LTO, one codegen unit, and aborting panics. The library enables `zeroize` and disables default
features. The checked-in lockfile fixes the probe's dependencies.

From the repository root:

```sh
rustup target add thumbv8m.main-none-eabi
cargo build --locked --release --target thumbv8m.main-none-eabi \
  --manifest-path ml-dsa/tools/cortex-m-stack/Cargo.toml --features low-memory
qemu-system-arm -M mps2-an505 -display none -serial none -monitor none \
  -semihosting-config enable=on,target=native \
  -kernel ml-dsa/tools/cortex-m-stack/target/thumbv8m.main-none-eabi/release/ml-dsa-cortex-m-stack
```

Add `ml-dsa-65` or `ml-dsa-87` to `--features` for those parameter sets; the default is ML-DSA-44.
Omit `low-memory` to exercise the cached implementation. Only one parameter-set feature may be
selected at a time. QEMU should exit successfully after printing byte counts. With `low-memory`,
signing must use at most 28 KiB of measured stack or the probe fails.

Keys, the signature, and the const-initialized workspace reside in separate static SRAM buffers.
Interrupts are disabled. Before each operation, the probe paints unused stack memory beneath a
256-byte gap below its current stack pointer, then scans the watermark afterward. The reported
stack includes startup and measurement caller frames, excludes static buffers, and measures written
stack memory. A reserved but untouched frame can escape a watermark; allow headroom and check the
compiler's frames and the application's interrupt requirements. This is a deterministic smoke
measurement using a zero seed and `stack probe` message, not a worst-case signing or firmware budget.

The unsafe accesses are confined to this measurement executable: the library continues to forbid
unsafe code. The harness assumes sequential execution, no interrupts, successful initialization of
keys/signatures before borrowing them, and the linker-provided unused stack range. Its 2 MiB SRAM
mapping is for the QEMU board model, not an assertion about a target device's available RAM.

QEMU validates functionality and stack usage; it does not reproduce physical side channels or
real-device cycle costs.
