use super::Limb;

impl Limb {
    pub const fn bits(self) -> usize {
        Limb::BIT_SIZE - (self.0.leading_zeros() as usize)
    }
}
