use super::{Limb, LimbUInt, WideLimbUInt};

impl Limb {
    pub const fn from_u8(n: u8) -> Self {
        Limb(n as LimbUInt)
    }

    pub const fn from_u16(n: u16) -> Self {
        Limb(n as LimbUInt)
    }

    pub const fn from_u32(n: u32) -> Self {
        #[allow(trivial_numeric_casts)]
        Limb(n as LimbUInt)
    }

    #[cfg(target_pointer_width = "64")]
    #[cfg_attr(docsrs, doc(cfg(target_pointer_width = "64")))]
    pub const fn from_u64(n: u64) -> Self {
        Limb(n)
    }
}

impl From<u8> for Limb {
    #[inline]
    fn from(n: u8) -> Limb {
        Limb(n.into())
    }
}

impl From<u16> for Limb {
    #[inline]
    fn from(n: u16) -> Limb {
        Limb(n.into())
    }
}

impl From<u32> for Limb {
    #[inline]
    fn from(n: u32) -> Limb {
        Limb(n.into())
    }
}

#[cfg(target_pointer_width = "64")]
#[cfg_attr(docsrs, doc(cfg(target_pointer_width = "64")))]
impl From<u64> for Limb {
    #[inline]
    fn from(n: u64) -> Limb {
        Limb(n)
    }
}

impl From<Limb> for LimbUInt {
    #[inline]
    fn from(limb: Limb) -> LimbUInt {
        limb.0
    }
}

impl From<Limb> for WideLimbUInt {
    #[inline]
    fn from(limb: Limb) -> WideLimbUInt {
        limb.0.into()
    }
}
