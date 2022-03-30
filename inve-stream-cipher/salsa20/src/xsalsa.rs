use super::{quarter_round, Key, Nonce, SalsaCore, Unsigned, XNonce, CONSTANTS};
use cipher::{
    consts::{U10, U16, U24, U32, U4, U6, U64},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;

pub type XSalsa20 = StreamCipherCoreWrapper<XSalsaCore<U10>>;
pub type XSalsa12 = StreamCipherCoreWrapper<XSalsaCore<U6>>;
pub type XSalsa8 = StreamCipherCoreWrapper<XSalsaCore<U4>>;

pub struct XSalsaCore<R: Unsigned>(SalsaCore<R>);

impl<R: Unsigned> KeySizeUser for XSalsaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for XSalsaCore<R> {
    type IvSize = U24;
}

impl<R: Unsigned> BlockSizeUser for XSalsaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for XSalsaCore<R> {
    #[inline]
    fn new(key: &Key, iv: &XNonce) -> Self {
        let subkey = hsalsa::<R>(key, iv[..16].as_ref().into());
        let mut padded_iv = Nonce::default();
        padded_iv.copy_from_slice(&iv[16..]);
        XSalsaCore(SalsaCore::new(&subkey, &padded_iv))
    }
}

impl<R: Unsigned> StreamCipherCore for XSalsaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        self.0.remaining_blocks()
    }

    #[inline(always)]
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        self.0.process_with_backend(f);
    }
}

impl<R: Unsigned> StreamCipherSeekCore for XSalsaCore<R> {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> u64 {
        self.0.get_block_pos()
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u64) {
        self.0.set_block_pos(pos);
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> ZeroizeOnDrop for XSalsaCore<R> {}

pub fn hsalsa<R: Unsigned>(key: &Key, input: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
    #[inline(always)]
    fn to_u32(chunk: &[u8]) -> u32 {
        u32::from_le_bytes(chunk.try_into().unwrap())
    }

    let mut state = [0u32; 16];
    state[0] = CONSTANTS[0];
    state[1..5]
        .iter_mut()
        .zip(key[0..16].chunks_exact(4))
        .for_each(|(v, chunk)| *v = to_u32(chunk));
    state[5] = CONSTANTS[1];
    state[6..10]
        .iter_mut()
        .zip(input.chunks_exact(4))
        .for_each(|(v, chunk)| *v = to_u32(chunk));
    state[10] = CONSTANTS[2];
    state[11..15]
        .iter_mut()
        .zip(key[16..].chunks_exact(4))
        .for_each(|(v, chunk)| *v = to_u32(chunk));
    state[15] = CONSTANTS[3];

    for _ in 0..R::USIZE {
        quarter_round(0, 4, 8, 12, &mut state);
        quarter_round(5, 9, 13, 1, &mut state);
        quarter_round(10, 14, 2, 6, &mut state);
        quarter_round(15, 3, 7, 11, &mut state);

        quarter_round(0, 1, 2, 3, &mut state);
        quarter_round(5, 6, 7, 4, &mut state);
        quarter_round(10, 11, 8, 9, &mut state);
        quarter_round(15, 12, 13, 14, &mut state);
    }

    let mut output = GenericArray::default();
    let key_idx: [usize; 8] = [0, 5, 10, 15, 6, 7, 8, 9];

    for (i, chunk) in output.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&state[key_idx[i]].to_le_bytes());
    }

    output
}
