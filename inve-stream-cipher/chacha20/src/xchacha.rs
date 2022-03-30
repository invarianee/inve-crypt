use super::{ChaChaCore, Key, Nonce, CONSTANTS, STATE_WORDS};
use cipher::{
    consts::{U10, U16, U24, U32, U4, U6, U64},
    generic_array::{typenum::Unsigned, GenericArray},
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;

pub type XNonce = GenericArray<u8, U24>;

pub type XChaCha20 = StreamCipherCoreWrapper<XChaChaCore<U10>>;
pub type XChaCha12 = StreamCipherCoreWrapper<XChaChaCore<U6>>;
pub type XChaCha8 = StreamCipherCoreWrapper<XChaChaCore<U4>>;

pub struct XChaChaCore<R: Unsigned>(ChaChaCore<R>);

impl<R: Unsigned> KeySizeUser for XChaChaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for XChaChaCore<R> {
    type IvSize = U24;
}

impl<R: Unsigned> BlockSizeUser for XChaChaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for XChaChaCore<R> {
    fn new(key: &Key, iv: &XNonce) -> Self {
        let subkey = hchacha::<R>(key, iv[..16].as_ref().into());
        let mut padded_iv = Nonce::default();
        padded_iv[4..].copy_from_slice(&iv[16..]);
        XChaChaCore(ChaChaCore::new(&subkey, &padded_iv))
    }
}

impl<R: Unsigned> StreamCipherCore for XChaChaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        self.0.remaining_blocks()
    }

    #[inline(always)]
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        self.0.process_with_backend(f);
    }
}

impl<R: Unsigned> StreamCipherSeekCore for XChaChaCore<R> {
    type Counter = u32;

    #[inline(always)]
    fn get_block_pos(&self) -> u32 {
        self.0.get_block_pos()
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u32) {
        self.0.set_block_pos(pos);
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> ZeroizeOnDrop for XChaChaCore<R> {}

pub fn hchacha<R: Unsigned>(key: &Key, input: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
    let mut state = [0u32; STATE_WORDS];
    state[..4].copy_from_slice(&CONSTANTS);

    let key_chunks = key.chunks_exact(4);
    for (v, chunk) in state[4..12].iter_mut().zip(key_chunks) {
        *v = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let input_chunks = input.chunks_exact(4);
    for (v, chunk) in state[12..16].iter_mut().zip(input_chunks) {
        *v = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    for _ in 0..R::USIZE {
        quarter_round(0, 4, 8, 12, &mut state);
        quarter_round(1, 5, 9, 13, &mut state);
        quarter_round(2, 6, 10, 14, &mut state);
        quarter_round(3, 7, 11, 15, &mut state);

        quarter_round(0, 5, 10, 15, &mut state);
        quarter_round(1, 6, 11, 12, &mut state);
        quarter_round(2, 7, 8, 13, &mut state);
        quarter_round(3, 4, 9, 14, &mut state);
    }

    let mut output = GenericArray::default();

    for (chunk, val) in output[..16].chunks_exact_mut(4).zip(&state[..4]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }

    for (chunk, val) in output[16..].chunks_exact_mut(4).zip(&state[12..]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }

    output
}

fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod hchacha20_tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_vector() {
        const KEY: [u8; 32] = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        );

        const INPUT: [u8; 16] = hex!("000000090000004a0000000031415927");

        const OUTPUT: [u8; 32] = hex!(
            "82413b4227b27bfed30e42508a877d73"
            "a0f9e4d58a74a853c12ec41326d3ecdc"
        );

        let actual = hchacha::<U10>(
            GenericArray::from_slice(&KEY),
            &GenericArray::from_slice(&INPUT),
        );
        assert_eq!(actual.as_slice(), &OUTPUT);
    }
}
