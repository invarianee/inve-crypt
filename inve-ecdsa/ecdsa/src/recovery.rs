use crate::{Error, Result};

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RecoveryId(u8);

impl RecoveryId {
    pub const MAX: u8 = 3;

    pub fn new(is_y_odd: bool, is_x_reduced: bool) -> Self {
        Self((is_x_reduced as u8) << 1 | (is_y_odd as u8))
    }

    pub fn is_x_reduced(self) -> bool {
        (self.0 & 0b10) != 0
    }

    pub fn is_y_odd(self) -> bool {
        (self.0 & 1) != 0
    }

    pub fn to_byte(self) -> u8 {
        self.into()
    }
}

impl TryFrom<u8> for RecoveryId {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self> {
        if byte <= Self::MAX {
            Ok(Self(byte))
        } else {
            Err(Error::new())
        }
    }
}

impl From<RecoveryId> for u8 {
    fn from(id: RecoveryId) -> u8 {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::RecoveryId;

    #[test]
    fn new() {
        assert_eq!(RecoveryId::new(false, false).to_byte(), 0);
        assert_eq!(RecoveryId::new(true, false).to_byte(), 1);
        assert_eq!(RecoveryId::new(false, true).to_byte(), 2);
        assert_eq!(RecoveryId::new(true, true).to_byte(), 3);
    }

    #[test]
    fn try_from() {
        for n in 0u8..=3 {
            assert_eq!(RecoveryId::try_from(n).unwrap().to_byte(), n);
        }

        for n in 4u8..=255 {
            assert!(RecoveryId::try_from(n).is_err());
        }
    }

    #[test]
    fn is_x_reduced() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_x_reduced(), true);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_x_reduced(), true);
    }

    #[test]
    fn is_y_odd() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_y_odd(), true);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_y_odd(), true);
    }
}
