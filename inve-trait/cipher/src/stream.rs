use crate::errors::{OverflowError, StreamCipherError};
use crate::stream_core::Counter;
use crate::{Block, BlockDecryptMut, BlockEncryptMut};
use inout::{InOutBuf, NotEqualError};

pub trait AsyncStreamCipher: Sized {
    fn encrypt_inout(mut self, data: InOutBuf<'_, '_, u8>)
    where
        Self: BlockEncryptMut,
    {
        let (blocks, mut tail) = data.into_chunks();
        self.encrypt_blocks_inout_mut(blocks);
        let mut block = Block::<Self>::default();
        let n = tail.len();
        if n != 0 {
            block[..n].copy_from_slice(tail.get_in());
            self.encrypt_block_mut(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }

    fn decrypt_inout(mut self, data: InOutBuf<'_, '_, u8>)
    where
        Self: BlockDecryptMut,
    {
        let (blocks, mut tail) = data.into_chunks();
        self.decrypt_blocks_inout_mut(blocks);
        let mut block = Block::<Self>::default();
        let n = tail.len();
        if n != 0 {
            block[..n].copy_from_slice(tail.get_in());
            self.decrypt_block_mut(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }

    fn encrypt(self, buf: &mut [u8])
    where
        Self: BlockEncryptMut,
    {
        self.encrypt_inout(buf.into());
    }

    fn decrypt(self, buf: &mut [u8])
    where
        Self: BlockDecryptMut,
    {
        self.decrypt_inout(buf.into());
    }

    fn encrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError>
    where
        Self: BlockEncryptMut,
    {
        InOutBuf::new(in_buf, out_buf).map(|b| self.encrypt_inout(b))
    }

    fn decrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError>
    where
        Self: BlockDecryptMut,
    {
        InOutBuf::new(in_buf, out_buf).map(|b| self.decrypt_inout(b))
    }
}

pub trait StreamCipher {
    fn try_apply_keystream_inout(
        &mut self,
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError>;

    #[inline]
    fn try_apply_keystream(&mut self, buf: &mut [u8]) -> Result<(), StreamCipherError> {
        self.try_apply_keystream_inout(buf.into())
    }

    #[inline]
    fn apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        self.try_apply_keystream_inout(buf).unwrap();
    }

    #[inline]
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.try_apply_keystream(buf).unwrap();
    }

    #[inline]
    fn apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), StreamCipherError> {
        InOutBuf::new(input, output)
            .map_err(|_| StreamCipherError)
            .and_then(|buf| self.try_apply_keystream_inout(buf))
    }
}

pub trait StreamCipherSeek {
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError>;

    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), StreamCipherError>;

    fn current_pos<T: SeekNum>(&self) -> T {
        self.try_current_pos().unwrap()
    }

    fn seek<T: SeekNum>(&mut self, pos: T) {
        self.try_seek(pos).unwrap()
    }
}

impl<C: StreamCipher> StreamCipher for &mut C {
    #[inline]
    fn try_apply_keystream_inout(
        &mut self,
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        C::try_apply_keystream_inout(self, buf)
    }
}

pub trait SeekNum: Sized {
    fn from_block_byte<T: Counter>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError>;

    fn into_block_byte<T: Counter>(self, bs: u8) -> Result<(T, u8), OverflowError>;
}

macro_rules! impl_seek_num {
    {$($t:ty )*} => {
        $(
            impl SeekNum for $t {
                fn from_block_byte<T: Counter>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError> {
                    debug_assert!(byte < bs);
                    let mut block: Self = block.try_into().map_err(|_| OverflowError)?;
                    if byte != 0 {
                        block -= 1;
                    }
                    let pos = block.checked_mul(bs as Self).ok_or(OverflowError)? + (byte as Self);
                    Ok(pos)
                }

                fn into_block_byte<T: Counter>(self, bs: u8) -> Result<(T, u8), OverflowError> {
                    let bs = bs as Self;
                    let byte = self % bs;
                    let block = T::try_from(self/bs).map_err(|_| OverflowError)?;
                    Ok((block, byte as u8))
                }
            }
        )*
    };
}

impl_seek_num! { i32 u32 u64 u128 usize }
