use super::{ArrayLength, Block};
use core::slice;

pub trait Sealed {
    fn invariant(pos: usize, block_size: usize) -> bool;

    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]);
}

impl Sealed for super::Eager {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos < block_size
    }

    #[inline(always)]
    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]) {
        let nb = data.len() / N::USIZE;
        let blocks_len = nb * N::USIZE;
        let tail_len = data.len() - blocks_len;
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block<N>;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}

impl Sealed for super::Lazy {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos <= block_size
    }

    #[inline(always)]
    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]) {
        if data.is_empty() {
            return (&[], &[]);
        }
        let (nb, tail_len) = if data.len() % N::USIZE == 0 {
            (data.len() / N::USIZE - 1, N::USIZE)
        } else {
            let nb = data.len() / N::USIZE;
            (nb, data.len() - nb * N::USIZE)
        };
        let blocks_len = nb * N::USIZE;
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block<N>;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}
