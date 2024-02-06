use std::iter::IntoIterator;

/// Returns an iterator over the w-bit Winternitz coefficients of the inout bytes
/// Implements the Coef function from section 3.1.3 of RFC8554
/// https://datatracker.ietf.org/doc/html/rfc8554#section-3.1.3
pub(crate) fn coefs<'a>(
    bytes: impl IntoIterator<Item = &'a u8>,
    w: usize,
) -> impl Iterator<Item = u8> {
    let mask: u8 = match w {
        1 => 0x01,
        2 => 0x03,
        4 => 0x0f,
        8 => 0xff,
        _ => panic!("invalid bit width: {}", w),
    };

    let entries_per_byte: usize = 8 / w;
    bytes
        .into_iter()
        .cloned()
        .flat_map(move |byte| (0..entries_per_byte).map(move |i| (byte >> (8 - w - i * w)) & mask))
}

#[cfg(test)]
mod tests {
    use crate::ots::util::coefs;

    #[test]
    fn coef_test_w1() {
        let s = [0x12, 0x34];
        let cs = coefs(&s, 1).collect::<Vec<_>>();
        assert_eq!(cs, vec![0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0]);
    }

    #[test]
    fn coef_test_w2() {
        let s = [0x12, 0x34];
        let cs: Vec<u8> = coefs(&s, 2).collect::<Vec<_>>();
        assert_eq!(cs, vec![0, 1, 0, 2, 0, 3, 1, 0]);
    }

    #[test]
    fn coef_test_w4() {
        let s = [0x12, 0x34];
        let cs: Vec<u8> = coefs(&s, 4).collect::<Vec<_>>();
        assert_eq!(cs, vec![1, 2, 3, 4]);
    }

    #[test]
    fn coef_test_w8() {
        let s = [0x12, 0x34];
        let cs: Vec<u8> = coefs(&s, 8).collect::<Vec<_>>();
        assert_eq!(cs, vec![0x12, 0x34]);
    }
}
