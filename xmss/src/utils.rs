/// Converts the value of `val` to `outlen` bytes in big-endian byte order.
pub(crate) fn ull_to_bytes(out: &mut [u8], val: u64) {
    let outlen = out.len();
    let mut v = val;
    for i in (0..outlen).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
}

/// Converts the bytes in `input` from big-endian byte order to an integer.
/// If `input` is longer than 8 bytes, only the first 8 bytes are used.
pub(crate) fn bytes_to_ull(input: &[u8]) -> u64 {
    let mut retval: u64 = 0;
    for &byte in input.iter().take(8) {
        retval = (retval << 8) | u64::from(byte);
    }
    retval
}
