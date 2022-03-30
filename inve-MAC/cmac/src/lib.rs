#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Mac};

use cipher::{BlockBackend, BlockCipher, BlockClosure, BlockEncryptMut};
use core::fmt;
use dbl::Dbl;
use digest::{
    block_buffer::Lazy,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::{InnerInit, InnerUser},
    generic_array::{
        typenum::{IsLess, Le, NonZero, U256},
        ArrayLength, GenericArray,
    },
    MacMarker, Output, OutputSizeUser, Reset,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

pub type Cmac<C> = CoreWrapper<CmacCore<C>>;

#[derive(Clone)]
pub struct CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    cipher: C,
    state: Block<C>,
}

impl<C> BlockSizeUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type Inner = C;
}

impl<C> MacMarker for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
}

impl<C> InnerInit for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let state = Default::default();
        Self { cipher, state }
    }
}

impl<C> BufferKindUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type BufferKind = Lazy;
}

impl<C> UpdateCore for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Ctx<'a, N: ArrayLength<u8>> {
            state: &'a mut Block<Self>,
            blocks: &'a [Block<Self>],
        }

        impl<'a, N: ArrayLength<u8>> BlockSizeUser for Ctx<'a, N> {
            type BlockSize = N;
        }

        impl<'a, N: ArrayLength<u8>> BlockClosure for Ctx<'a, N> {
            #[inline(always)]
            fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
                for block in self.blocks {
                    xor(self.state, block);
                    backend.proc_block((self.state).into());
                }
            }
        }

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend_mut(Ctx { state, blocks })
    }
}

impl<C> Reset for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, cipher } = self;
        let pos = buffer.get_pos();
        let buf = buffer.pad_with_zeros();

        let mut subkey = Default::default();
        cipher.encrypt_block_mut(&mut subkey);
        let key1 = subkey.dbl();

        xor(state, buf);
        if pos == buf.len() {
            xor(state, &key1);
        } else {
            state[pos] ^= 0x80;
            let key2 = key1.dbl();
            xor(state, &key2);
        }
        cipher.encrypt_block_mut(state);
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
    Block<C>: Dbl,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cmac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
    Block<C>: Dbl,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CmacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + ZeroizeOnDrop,
    Block<C>: Dbl,
{
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(buf: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
