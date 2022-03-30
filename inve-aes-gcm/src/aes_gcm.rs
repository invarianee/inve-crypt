#![cfg_attr(feature = "heapless", doc = " ```")]
#![cfg_attr(not(feature = "heapless"), doc = " ```ignore")]

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};
pub use cipher::Key;

#[cfg(feature = "aes")]
pub use aes;

use cipher::{
    consts::{U0, U16},
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockEncrypt, BlockSizeUser, InnerIvInit, KeyInit, KeySizeUser, StreamCipherCore,
};
use core::marker::PhantomData;
use ghash::{
    universal_hash::{NewUniversalHash, UniversalHash},
    GHash,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::{cipher::consts::U12, Aes128, Aes256};

pub const A_MAX: u64 = 1 << 36;

pub const P_MAX: u64 = 1 << 36;

pub const C_MAX: u64 = (1 << 36) + 16;

pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

pub type Tag = GenericArray<u8, U16>;

#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes128Gcm = AesGcm<Aes128, U12>;

#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Gcm = AesGcm<Aes256, U12>;

type Block = GenericArray<u8, U16>;

type Ctr32BE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr32BE>;

#[derive(Clone)]
pub struct AesGcm<Aes, NonceSize> {
    cipher: Aes,

    ghash: GHash,

    nonce_size: PhantomData<NonceSize>,
}

impl<Aes, NonceSize> KeySizeUser for AesGcm<Aes, NonceSize>
where
    Aes: KeyInit,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, NonceSize> NewAead for AesGcm<Aes, NonceSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    type KeySize = Aes::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Aes::new(key).into()
    }
}

impl<Aes, NonceSize> From<Aes> for AesGcm<Aes, NonceSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn from(cipher: Aes) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        #[cfg(feature = "zeroize")]
        ghash_key.zeroize();

        Self {
            cipher,
            ghash,
            nonce_size: PhantomData,
        }
    }
}

impl<Aes, NonceSize> AeadCore for AesGcm<Aes, NonceSize>
where
    NonceSize: ArrayLength<u8>,
{
    type NonceSize = NonceSize;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<Aes, NonceSize> AeadInPlace for AesGcm<Aes, NonceSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        ctr.apply_keystream_partial(buffer.into());
        Ok(self.compute_tag(mask, associated_data, buffer))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        let expected_tag = self.compute_tag(mask, associated_data, buffer);
        ctr.apply_keystream_partial(buffer.into());

        use subtle::ConstantTimeEq;
        if expected_tag.ct_eq(tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Aes, NonceSize> AesGcm<Aes, NonceSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    fn init_ctr(&self, nonce: &Nonce<NonceSize>) -> (Ctr32BE<&Aes>, Block) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&block);
            ghash.finalize().into_bytes()
        };

        let mut ctr = Ctr32BE::inner_iv_init(&self.cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);
        (ctr, tag_mask)
    }

    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&block);

        let mut tag = ghash.finalize().into_bytes();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }

        tag
    }
}
