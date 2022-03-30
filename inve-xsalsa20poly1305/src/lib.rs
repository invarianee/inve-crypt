pub use aead;
pub use salsa20::{Key, XNonce as Nonce};

use aead::{
    consts::{U0, U16, U24, U32},
    generic_array::GenericArray,
    AeadCore, AeadInPlace, Buffer, Error, NewAead,
};
use poly1305::{universal_hash::NewUniversalHash, Poly1305};
use salsa20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    XSalsa20,
};
use zeroize::Zeroize;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

pub const KEY_SIZE: usize = 32;

pub const NONCE_SIZE: usize = 24;

pub const TAG_SIZE: usize = 16;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub fn generate_nonce<T>(csprng: &mut T) -> Nonce
where
    T: RngCore + CryptoRng,
{
    let mut nonce = [0u8; NONCE_SIZE];
    csprng.fill_bytes(&mut nonce);
    nonce.into()
}

pub type Tag = GenericArray<u8, U16>;

#[derive(Clone)]
pub struct XSalsa20Poly1305 {
    key: Key,
}

impl NewAead for XSalsa20Poly1305 {
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        XSalsa20Poly1305 { key: *key }
    }
}

impl AeadCore for XSalsa20Poly1305 {
    type NonceSize = U24;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for XSalsa20Poly1305 {
    fn encrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        let pt_len = buffer.len();

        buffer.extend_from_slice(Tag::default().as_slice())?;

        buffer.as_mut().copy_within(..pt_len, TAG_SIZE);

        let tag = self.encrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
        )?;
        buffer.as_mut()[..TAG_SIZE].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        if buffer.len() < TAG_SIZE {
            return Err(Error);
        }

        let tag = Tag::clone_from_slice(&buffer.as_ref()[..TAG_SIZE]);
        self.decrypt_in_place_detached(
            nonce,
            associated_data,
            &mut buffer.as_mut()[TAG_SIZE..],
            &tag,
        )?;

        let pt_len = buffer.len() - TAG_SIZE;

        buffer.as_mut().copy_within(TAG_SIZE.., 0);
        buffer.truncate(pt_len);
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(XSalsa20::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl Drop for XSalsa20Poly1305 {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

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

        Self { cipher, mac }
    }

    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if !associated_data.is_empty() {
            return Err(Error);
        }

        self.cipher.apply_keystream(buffer);
        Ok(self.mac.compute_unpadded(buffer).into_bytes())
    }

    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if !associated_data.is_empty() {
            return Err(Error);
        }

        use subtle::ConstantTimeEq;
        let expected_tag = self.mac.compute_unpadded(buffer).into_bytes();

        if expected_tag.ct_eq(tag).unwrap_u8() == 1 {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}
