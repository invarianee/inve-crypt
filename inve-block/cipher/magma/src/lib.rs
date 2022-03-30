pub use cipher;

use cipher::{
    consts::{U32, U8},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod sboxes;

pub use sboxes::Sbox;

#[derive(Clone)]
pub struct Gost89<S: Sbox> {
    key: [u32; 8],
    _p: PhantomData<S>,
}

impl<S: Sbox> BlockCipher for Gost89<S> {}

impl<S: Sbox> KeySizeUser for Gost89<S> {
    type KeySize = U32;
}

impl<S: Sbox> KeyInit for Gost89<S> {
    fn new(key: &Key<Self>) -> Self {
        let mut key_u32 = [0u32; 8];
        key.chunks_exact(4)
            .zip(key_u32.iter_mut())
            .for_each(|(chunk, v)| *v = to_u32(chunk));
        Self {
            key: key_u32,
            _p: PhantomData,
        }
    }
}

impl<S: Sbox> fmt::Debug for Gost89<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost89<")?;
        f.write_str(S::NAME)?;
        f.write_str("> { ... }")
    }
}

impl<S: Sbox> AlgorithmName for Gost89<S> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost89<")?;
        f.write_str(S::NAME)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<S: Sbox> Drop for Gost89<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<S: Sbox> ZeroizeOnDrop for Gost89<S> {}

cipher::impl_simple_block_encdec!(
    <S: Sbox> Gost89, U8, cipher, block,
    encrypt: {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));
        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
            }
        }
        for i in (0..8).rev() {
            v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
    decrypt: {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));

        for i in 0..8 {
            v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
        }

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
            }
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
);

pub type Magma = Gost89<sboxes::Tc26>;
pub type Gost89Test = Gost89<sboxes::TestSbox>;
pub type Gost89CryptoProA = Gost89<sboxes::CryptoProA>;
pub type Gost89CryptoProB = Gost89<sboxes::CryptoProB>;
pub type Gost89CryptoProC = Gost89<sboxes::CryptoProC>;
pub type Gost89CryptoProD = Gost89<sboxes::CryptoProD>;

#[inline(always)]
fn to_u32(chunk: &[u8]) -> u32 {
    u32::from_be_bytes(chunk.try_into().unwrap())
}
