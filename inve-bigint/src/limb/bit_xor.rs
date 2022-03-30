use super::Limb;
use core::ops::BitXor;

impl Limb {
    pub const fn bitxor(self, rhs: Self) -> Self {
        Limb(self.0 ^ rhs.0)
    }
}

impl BitXor for Limb {
    type Output = Limb;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bitxor(rhs)
    }
}
