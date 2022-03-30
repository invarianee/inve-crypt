pub use cipher;

use cipher::{
    consts::{U1, U10, U24, U32, U4, U6, U64, U8},
    generic_array::{typenum::Unsigned, GenericArray},
    Block, BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamBackend,
    StreamCipherCore, StreamCipherCoreWrapper, StreamCipherSeekCore, StreamClosure,
};
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod xsalsa;

pub use xsalsa::{hsalsa, XSalsa12, XSalsa20, XSalsa8, XSalsaCore};

pub type Salsa8 = StreamCipherCoreWrapper<SalsaCore<U4>>;

pub type Salsa12 = StreamCipherCoreWrapper<SalsaCore<U6>>;

pub type Salsa20 = StreamCipherCoreWrapper<SalsaCore<U10>>;

pub type Key = GenericArray<u8, U32>;

pub type Nonce = GenericArray<u8, U8>;

pub type XNonce = GenericArray<u8, U24>;

const STATE_WORDS: usize = 16;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub struct SalsaCore<R: Unsigned> {
    state: [u32; STATE_WORDS],
    rounds: PhantomData<R>,
}

impl<R: Unsigned> SalsaCore<R> {
    pub fn from_raw_state(state: [u32; STATE_WORDS]) -> Self {
        Self {
            state,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> KeySizeUser for SalsaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for SalsaCore<R> {
    type IvSize = U8;
}

impl<R: Unsigned> BlockSizeUser for SalsaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for SalsaCore<R> {
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0] = CONSTANTS[0];

        for (i, chunk) in key[..16].chunks(4).enumerate() {
            state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[5] = CONSTANTS[1];

        for (i, chunk) in iv.chunks(4).enumerate() {
            state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[8] = 0;
        state[9] = 0;
        state[10] = CONSTANTS[2];

        for (i, chunk) in key[16..].chunks(4).enumerate() {
            state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[15] = CONSTANTS[3];

        Self {
            state,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> StreamCipherCore for SalsaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u64::MAX - self.get_block_pos();
        rem.try_into().ok()
    }
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(self));
    }
}

impl<R: Unsigned> StreamCipherSeekCore for SalsaCore<R> {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> u64 {
        (self.state[8] as u64) + ((self.state[9] as u64) << 32)
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u64) {
        self.state[8] = (pos & 0xffff_ffff) as u32;
        self.state[9] = ((pos >> 32) & 0xffff_ffff) as u32;
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> Drop for SalsaCore<R> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> ZeroizeOnDrop for SalsaCore<R> {}

struct Backend<'a, R: Unsigned>(&'a mut SalsaCore<R>);

impl<'a, R: Unsigned> BlockSizeUser for Backend<'a, R> {
    type BlockSize = U64;
}

impl<'a, R: Unsigned> ParBlocksSizeUser for Backend<'a, R> {
    type ParBlocksSize = U1;
}

impl<'a, R: Unsigned> StreamBackend for Backend<'a, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let res = run_rounds::<R>(&self.0.state);
        self.0.set_block_pos(self.0.get_block_pos() + 1);

        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[inline]
#[allow(clippy::many_single_char_names)]
pub(crate) fn quarter_round(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    state: &mut [u32; STATE_WORDS],
) {
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R::USIZE {
        quarter_round(0, 4, 8, 12, &mut res);
        quarter_round(5, 9, 13, 1, &mut res);
        quarter_round(10, 14, 2, 6, &mut res);
        quarter_round(15, 3, 7, 11, &mut res);

        quarter_round(0, 1, 2, 3, &mut res);
        quarter_round(5, 6, 7, 4, &mut res);
        quarter_round(10, 11, 8, 9, &mut res);
        quarter_round(15, 12, 13, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}
