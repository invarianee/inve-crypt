use cipher::{
    generic_array::{ArrayLength, GenericArray},
    Counter,
};

mod ctr128;
mod ctr32;
mod ctr64;

pub use ctr128::{Ctr128BE, Ctr128LE};
pub use ctr32::{Ctr32BE, Ctr32LE};
pub use ctr64::{Ctr64BE, Ctr64LE};

pub trait CtrFlavor<B: ArrayLength<u8>> {
    type CtrNonce: Clone;
    type Backend: Counter;
    const NAME: &'static str;

    fn remaining(cn: &Self::CtrNonce) -> Option<usize>;

    fn next_block(cn: &mut Self::CtrNonce) -> GenericArray<u8, B>;

    fn current_block(cn: &Self::CtrNonce) -> GenericArray<u8, B>;

    fn from_nonce(block: &GenericArray<u8, B>) -> Self::CtrNonce;

    fn set_from_backend(cn: &mut Self::CtrNonce, v: Self::Backend);

    fn as_backend(cn: &Self::CtrNonce) -> Self::Backend;
}
