use crate::Signature;
use core::fmt;

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for component in [&self.R.0, &self.s.0] {
            for byte in component {
                write!(f, "{:02x}", byte)?;
            }
        }
        Ok(())
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for component in [&self.R.0, &self.s.0] {
            for byte in component {
                write!(f, "{:02X}", byte)?;
            }
        }
        Ok(())
    }
}
