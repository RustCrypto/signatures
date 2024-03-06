//! Constants as defined in RFC 8554

/// The length of the identifier `I`
pub const ID_LEN: usize = 16;

/// `D_PBLC`
pub const D_PBLC: [u8; 2] = [0x80, 0x80];
/// `D_MESG`
pub const D_MESG: [u8; 2] = [0x81, 0x81];
/// `D_LEAF`
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
/// `D_INTR`
pub const D_INTR: [u8; 2] = [0x83, 0x83];
