pub use crypto_common;
pub use inout;

#[cfg(all(feature = "block-padding", feature = "alloc"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use crypto_common::rand_core;

#[cfg(feature = "block-padding")]
#[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
pub use inout::block_padding;

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub use zeroize;

#[cfg(feature = "dev")]
pub use blobby;

mod block;
#[cfg(feature = "dev")]
mod dev;
mod errors;
mod stream;
mod stream_core;
mod stream_wrapper;

pub use crate::{block::*, errors::*, stream::*, stream_core::*, stream_wrapper::*};
pub use crypto_common::{
    generic_array,
    typenum::{self, consts},
    AlgorithmName, Block, InnerIvInit, InvalidLength, Iv, IvSizeUser, Key, KeyInit, KeyIvInit,
    KeySizeUser,
};
use generic_array::{ArrayLength, GenericArray};

pub trait IvState: IvSizeUser {
    fn iv_state(&self) -> Iv<Self>;
}

pub trait ParBlocksSizeUser: BlockSizeUser {
    type ParBlocksSize: ArrayLength<Block<Self>>;
}

pub type ParBlocks<T> = GenericArray<Block<T>, <T as ParBlocksSizeUser>::ParBlocksSize>;
