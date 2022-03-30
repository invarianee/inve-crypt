pub use cipher;

use cfg_if::cfg_if;
use cipher::{
    consts::{U10, U12, U32, U4, U6, U64},
    generic_array::{typenum::Unsigned, GenericArray},
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod backends;
mod legacy;
mod xchacha;

pub use legacy::{ChaCha20Legacy, ChaCha20LegacyCore, LegacyNonce};
pub use xchacha::{hchacha, XChaCha12, XChaCha20, XChaCha8, XChaChaCore, XNonce};

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

const STATE_WORDS: usize = 16;

type Block = GenericArray<u8, U64>;

pub type Key = GenericArray<u8, U32>;

pub type Nonce = GenericArray<u8, U12>;

pub type ChaCha8 = StreamCipherCoreWrapper<ChaChaCore<U4>>;

pub type ChaCha12 = StreamCipherCoreWrapper<ChaChaCore<U6>>;

pub type ChaCha20 = StreamCipherCoreWrapper<ChaChaCore<U10>>;

cfg_if! {
    if #[cfg(chacha20_force_soft)] {
        type Tokens = ();
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if! {
            if #[cfg(chacha20_force_avx2)] {
                #[cfg(not(target_feature = "avx2"))]
                compile_error!("You must enable `avx2` target feature with \
                    `chacha20_force_avx2` configuration option");
                type Tokens = ();
            } else if #[cfg(chacha20_force_sse2)] {
                #[cfg(not(target_feature = "sse2"))]
                compile_error!("You must enable `sse2` target feature with \
                    `chacha20_force_sse2` configuration option");
                type Tokens = ();
            } else {
                cpufeatures::new!(avx2_cpuid, "avx2");
                cpufeatures::new!(sse2_cpuid, "sse2");
                type Tokens = (avx2_cpuid::InitToken, sse2_cpuid::InitToken);
            }
        }
    } else {
        type Tokens = ();
    }
}

pub struct ChaChaCore<R: Unsigned> {
    state: [u32; STATE_WORDS],
    #[allow(dead_code)]
    tokens: Tokens,
    rounds: PhantomData<R>,
}

impl<R: Unsigned> KeySizeUser for ChaChaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for ChaChaCore<R> {
    type IvSize = U12;
}

impl<R: Unsigned> BlockSizeUser for ChaChaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for ChaChaCore<R> {
    #[inline]
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let iv_chunks = iv.chunks_exact(4);
        for (val, chunk) in state[13..16].iter_mut().zip(iv_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        cfg_if! {
            if #[cfg(chacha20_force_soft)] {
                let tokens = ();
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(chacha20_force_avx2)] {
                        let tokens = ();
                    } else if #[cfg(chacha20_force_sse2)] {
                        let tokens = ();
                    } else {
                        let tokens = (avx2_cpuid::init(), sse2_cpuid::init());
                    }
                }
            } else {
                let tokens = ();
            }
        }

        Self {
            state,
            tokens,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> StreamCipherCore for ChaChaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u32::MAX - self.get_block_pos();
        rem.try_into().ok()
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        cfg_if! {
            if #[cfg(chacha20_force_soft)] {
                f.call(&mut backends::soft::Backend(self));
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(chacha20_force_avx2)] {
                        unsafe {
                            backends::avx2::inner::<R, _>(&mut self.state, f);
                        }
                    } else if #[cfg(chacha20_force_sse2)] {
                        unsafe {
                            backends::sse2::inner::<R, _>(&mut self.state, f);
                        }
                    } else {
                        let (avx2_token, sse2_token) = self.tokens;
                        if avx2_token.get() {
                            unsafe {
                                backends::avx2::inner::<R, _>(&mut self.state, f);
                            }
                        } else if sse2_token.get() {
                            unsafe {
                                backends::sse2::inner::<R, _>(&mut self.state, f);
                            }
                        } else {
                            f.call(&mut backends::soft::Backend(self));
                        }
                    }
                }
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }
}

impl<R: Unsigned> StreamCipherSeekCore for ChaChaCore<R> {
    type Counter = u32;

    #[inline(always)]
    fn get_block_pos(&self) -> u32 {
        self.state[12]
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u32) {
        self.state[12] = pos;
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> Drop for ChaChaCore<R> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> ZeroizeOnDrop for ChaChaCore<R> {}
