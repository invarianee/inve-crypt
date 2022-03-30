use crate::{Limb, LimbUInt, UInt};

#[derive(Clone, Debug)]
pub(super) struct Decoder<const LIMBS: usize> {
    limbs: [Limb; LIMBS],

    index: usize,

    bytes: usize,
}

impl<const LIMBS: usize> Decoder<LIMBS> {
    pub const fn new() -> Self {
        Self {
            limbs: [Limb::ZERO; LIMBS],
            index: 0,
            bytes: 0,
        }
    }

    pub const fn add_byte(mut self, byte: u8) -> Self {
        if self.bytes == Limb::BYTE_SIZE {
            assert!(self.index < LIMBS, "too many bytes in UInt");
            self.index += 1;
            self.bytes = 0;
        }

        self.limbs[self.index].0 |= (byte as LimbUInt) << (self.bytes * 8);
        self.bytes += 1;
        self
    }

    pub const fn finish(self) -> UInt<LIMBS> {
        assert!(self.index == LIMBS - 1, "decoded UInt is missing limbs");
        assert!(
            self.bytes == Limb::BYTE_SIZE,
            "decoded UInt is missing bytes"
        );
        UInt { limbs: self.limbs }
    }
}

impl<const LIMBS: usize> Default for Decoder<LIMBS> {
    fn default() -> Self {
        Self::new()
    }
}
