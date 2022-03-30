#[cfg(all(feature = "alloc", test))]
extern crate alloc;

#[macro_use]
mod nlimbs;

#[cfg(feature = "generic-array")]
mod array;
mod checked;
mod limb;
mod non_zero;
mod traits;
mod uint;
mod wrapping;

pub use crate::{
    checked::Checked,
    limb::{Limb, LimbUInt, WideLimbUInt},
    non_zero::NonZero,
    traits::*,
    uint::*,
    wrapping::Wrapping,
};
pub use subtle;

pub(crate) use limb::{LimbInt, WideLimbInt};

#[cfg(feature = "generic-array")]
pub use {
    crate::array::{ArrayDecoding, ArrayEncoding, ByteArray},
    generic_array::{self, typenum::consts},
};

#[cfg(feature = "rand_core")]
pub use rand_core;

#[cfg(feature = "rlp")]
pub use rlp;

#[cfg(feature = "zeroize")]
pub use zeroize;

pub mod prelude {
    pub use crate::traits::*;

    #[cfg(feature = "generic-array")]
    pub use crate::array::{ArrayDecoding, ArrayEncoding};
}
