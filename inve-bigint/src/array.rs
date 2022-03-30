use crate::{Encoding, Integer};
use core::ops::Add;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

#[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
pub type ByteArray<T> = GenericArray<u8, <T as ArrayEncoding>::ByteSize>;

#[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
pub trait ArrayEncoding: Encoding {
    type ByteSize: ArrayLength<u8> + Add + Eq + Ord + Unsigned;

    fn from_be_byte_array(bytes: ByteArray<Self>) -> Self;

    fn from_le_byte_array(bytes: ByteArray<Self>) -> Self;

    fn to_be_byte_array(&self) -> ByteArray<Self>;

    fn to_le_byte_array(&self) -> ByteArray<Self>;
}

#[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
pub trait ArrayDecoding {
    type Output: ArrayEncoding + Integer;

    fn into_uint_be(self) -> Self::Output;

    fn into_uint_le(self) -> Self::Output;
}
