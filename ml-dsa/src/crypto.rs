use hybrid_array::Array;
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, XofReader},
};

use crate::module_lattice::encode::ArraySize;

pub(crate) enum ShakeState<Shake: ExtendableOutput> {
    Absorbing(Shake),
    Squeezing(Shake::Reader),
}

impl<Shake: ExtendableOutput + Default> Default for ShakeState<Shake> {
    fn default() -> Self {
        Self::Absorbing(Shake::default())
    }
}

impl<Shake: ExtendableOutput + Default + Clone> ShakeState<Shake> {
    pub(crate) fn updatable(&mut self) -> &mut Shake {
        match self {
            Self::Absorbing(sponge) => sponge,
            Self::Squeezing(_) => unreachable!(),
        }
    }

    pub(crate) fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Self::Absorbing(sponge) => sponge.update(input),
            Self::Squeezing(_) => unreachable!(),
        }

        self
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        match self {
            Self::Absorbing(sponge) => {
                // Clone required to satisfy borrow checker
                let mut reader = sponge.clone().finalize_xof();
                reader.read(output);
                *self = Self::Squeezing(reader);
            }
            Self::Squeezing(reader) => {
                reader.read(output.as_mut());
            }
        }

        self
    }

    pub(crate) fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

pub(crate) type G = ShakeState<Shake128>;
pub(crate) type H = ShakeState<Shake256>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("3a9159f071e4dd1c8c4f968607c30942e120d8156b8b1e72e0d376e8871cb8b8");
        let expected2 = hex!("99072665674f26cc494a4bcf027c58267e8ee2da60e942759de86d2670bba1aa");

        let mut g = G::default().absorb(input);

        let mut actual = [0u8; 32];
        g.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = g.squeeze_new();
        assert_eq!(actual, expected2);
    }

    #[test]
    fn h() {
        let input = b"hello world";
        let expected1 = hex!("369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527");
        let expected2 = hex!("f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
