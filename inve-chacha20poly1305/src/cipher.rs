use ::cipher::{StreamCipher, StreamCipherSeek};
use aead::generic_array::GenericArray;
use aead::Error;
use core::convert::TryInto;
use poly1305::{
    universal_hash::{NewUniversalHash, UniversalHash},
    Poly1305,
};
use zeroize::Zeroize;

use super::Tag;

const BLOCK_SIZE: usize = 64;

const MAX_BLOCKS: usize = core::u32::MAX as usize;

pub(crate) struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: Poly1305,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    pub(crate) fn new(mut cipher: C) -> Self {
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut *mac_key);
        let mac = Poly1305::new(GenericArray::from_slice(&*mac_key));
        mac_key.zeroize();

        cipher.seek(BLOCK_SIZE as u64);

        Self { cipher, mac }
    }

    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);

        self.cipher.apply_keystream(buffer);
        self.mac.update_padded(buffer);

        self.authenticate_lengths(associated_data, buffer)?;
        Ok(self.mac.finalize().into_bytes())
    }

    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);
        self.mac.update_padded(buffer);
        self.authenticate_lengths(associated_data, buffer)?;

        if self.mac.verify(tag).is_ok() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn authenticate_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
        block[8..].copy_from_slice(&buffer_len.to_le_bytes());
        self.mac.update(&block);

        Ok(())
    }
}
