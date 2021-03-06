pub use generic_array;

use core::{marker::PhantomData, slice};
use generic_array::{
    typenum::{IsLess, Le, NonZero, U256},
    ArrayLength, GenericArray,
};

mod sealed;

pub type Block<BlockSize> = GenericArray<u8, BlockSize>;

pub trait BufferKind: sealed::Sealed {}

#[derive(Copy, Clone, Debug, Default)]
pub struct Eager {}

#[derive(Copy, Clone, Debug, Default)]
pub struct Lazy {}

impl BufferKind for Eager {}
impl BufferKind for Lazy {}

pub type EagerBuffer<B> = BlockBuffer<B, Eager>;
pub type LazyBuffer<B> = BlockBuffer<B, Lazy>;

#[derive(Debug)]
pub struct BlockBuffer<BlockSize, Kind>
where
    BlockSize: ArrayLength<u8> + IsLess<U256>,
    Le<BlockSize, U256>: NonZero,
    Kind: BufferKind,
{
    buffer: Block<BlockSize>,
    pos: u8,
    _pd: PhantomData<Kind>,
}

impl<BlockSize, Kind> Default for BlockBuffer<BlockSize, Kind>
where
    BlockSize: ArrayLength<u8> + IsLess<U256>,
    Le<BlockSize, U256>: NonZero,
    Kind: BufferKind,
{
    fn default() -> Self {
        Self {
            buffer: Default::default(),
            pos: 0,
            _pd: PhantomData,
        }
    }
}

impl<BlockSize, Kind> Clone for BlockBuffer<BlockSize, Kind>
where
    BlockSize: ArrayLength<u8> + IsLess<U256>,
    Le<BlockSize, U256>: NonZero,
    Kind: BufferKind,
{
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            pos: self.pos,
            _pd: PhantomData,
        }
    }
}

impl<BlockSize, Kind> BlockBuffer<BlockSize, Kind>
where
    BlockSize: ArrayLength<u8> + IsLess<U256>,
    Le<BlockSize, U256>: NonZero,
    Kind: BufferKind,
{
    #[inline(always)]
    pub fn new(buf: &[u8]) -> Self {
        let pos = buf.len();
        assert!(Kind::invariant(pos, BlockSize::USIZE));
        let mut buffer = Block::<BlockSize>::default();
        buffer[..pos].copy_from_slice(buf);
        Self {
            buffer,
            pos: pos as u8,
            _pd: PhantomData,
        }
    }

    #[inline]
    pub fn digest_blocks(
        &mut self,
        mut input: &[u8],
        mut compress: impl FnMut(&[Block<BlockSize>]),
    ) {
        let pos = self.get_pos();
        let rem = self.size() - pos;
        let n = input.len();
        if Kind::invariant(n, rem) {
            self.buffer[pos..][..n].copy_from_slice(input);
            self.set_pos_unchecked(pos + n);
            return;
        }
        if pos != 0 {
            let (left, right) = input.split_at(rem);
            input = right;
            self.buffer[pos..].copy_from_slice(left);
            compress(slice::from_ref(&self.buffer));
        }

        let (blocks, leftover) = Kind::split_blocks(input);
        if !blocks.is_empty() {
            compress(blocks);
        }

        let n = leftover.len();
        self.buffer[..n].copy_from_slice(leftover);
        self.set_pos_unchecked(n);
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.set_pos_unchecked(0);
    }

    #[inline(always)]
    pub fn pad_with_zeros(&mut self) -> &mut Block<BlockSize> {
        let pos = self.get_pos();
        self.buffer[pos..].iter_mut().for_each(|b| *b = 0);
        self.set_pos_unchecked(0);
        &mut self.buffer
    }

    #[inline(always)]
    pub fn get_pos(&self) -> usize {
        let pos = self.pos as usize;
        if !Kind::invariant(pos, BlockSize::USIZE) {
            debug_assert!(false);
            unsafe {
                core::hint::unreachable_unchecked();
            }
        }
        pos
    }

    #[inline(always)]
    pub fn get_data(&self) -> &[u8] {
        &self.buffer[..self.get_pos()]
    }

    #[inline]
    pub fn set(&mut self, buf: Block<BlockSize>, pos: usize) {
        assert!(Kind::invariant(pos, BlockSize::USIZE));
        self.buffer = buf;
        self.set_pos_unchecked(pos);
    }

    #[inline(always)]
    pub fn size(&self) -> usize {
        BlockSize::USIZE
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.size() - self.get_pos()
    }

    #[inline(always)]
    fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert!(Kind::invariant(pos, BlockSize::USIZE));
        self.pos = pos as u8;
    }
}

impl<BlockSize> BlockBuffer<BlockSize, Eager>
where
    BlockSize: ArrayLength<u8> + IsLess<U256>,
    Le<BlockSize, U256>: NonZero,
{
    #[inline]
    pub fn set_data(
        &mut self,
        mut data: &mut [u8],
        mut process_blocks: impl FnMut(&mut [Block<BlockSize>]),
    ) {
        let pos = self.get_pos();
        let r = self.remaining();
        let n = data.len();
        if pos != 0 {
            if n < r {
                data.copy_from_slice(&self.buffer[pos..][..n]);
                self.set_pos_unchecked(pos + n);
                return;
            }
            let (left, right) = data.split_at_mut(r);
            data = right;
            left.copy_from_slice(&self.buffer[pos..]);
        }

        let (blocks, leftover) = to_blocks_mut(data);
        process_blocks(blocks);

        let n = leftover.len();
        if n != 0 {
            let mut block = Default::default();
            process_blocks(slice::from_mut(&mut block));
            leftover.copy_from_slice(&block[..n]);
            self.buffer = block;
        }
        self.set_pos_unchecked(n);
    }

    #[inline(always)]
    pub fn digest_pad(
        &mut self,
        delim: u8,
        suffix: &[u8],
        mut compress: impl FnMut(&Block<BlockSize>),
    ) {
        if suffix.len() > BlockSize::USIZE {
            panic!("suffix is too long");
        }
        let pos = self.get_pos();
        self.buffer[pos] = delim;
        for b in &mut self.buffer[pos + 1..] {
            *b = 0;
        }

        let n = self.size() - suffix.len();
        if self.size() - pos - 1 < suffix.len() {
            compress(&self.buffer);
            let mut block = Block::<BlockSize>::default();
            block[n..].copy_from_slice(suffix);
            compress(&block);
        } else {
            self.buffer[n..].copy_from_slice(suffix);
            compress(&self.buffer);
        }
        self.set_pos_unchecked(0)
    }

    #[inline]
    pub fn len64_padding_be(&mut self, data_len: u64, compress: impl FnMut(&Block<BlockSize>)) {
        self.digest_pad(0x80, &data_len.to_be_bytes(), compress);
    }

    #[inline]
    pub fn len64_padding_le(&mut self, data_len: u64, compress: impl FnMut(&Block<BlockSize>)) {
        self.digest_pad(0x80, &data_len.to_le_bytes(), compress);
    }

    #[inline]
    pub fn len128_padding_be(&mut self, data_len: u128, compress: impl FnMut(&Block<BlockSize>)) {
        self.digest_pad(0x80, &data_len.to_be_bytes(), compress);
    }
}

#[inline(always)]
fn to_blocks_mut<N: ArrayLength<u8>>(data: &mut [u8]) -> (&mut [Block<N>], &mut [u8]) {
    let nb = data.len() / N::USIZE;
    let (left, right) = data.split_at_mut(nb * N::USIZE);
    let p = left.as_mut_ptr() as *mut Block<N>;
    let blocks = unsafe { slice::from_raw_parts_mut(p, nb) };
    (blocks, right)
}
