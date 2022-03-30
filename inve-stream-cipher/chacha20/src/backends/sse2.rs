use crate::{Block, StreamClosure, Unsigned, STATE_WORDS};
use cipher::{
    consts::{U1, U64},
    BlockSizeUser, ParBlocksSizeUser, StreamBackend,
};
use core::marker::PhantomData;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn inner<R, F>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Unsigned,
    F: StreamClosure<BlockSize = U64>,
{
    let state_ptr = state.as_ptr() as *const __m128i;
    let mut backend = Backend::<R> {
        v: [
            _mm_loadu_si128(state_ptr.add(0)),
            _mm_loadu_si128(state_ptr.add(1)),
            _mm_loadu_si128(state_ptr.add(2)),
            _mm_loadu_si128(state_ptr.add(3)),
        ],
        _pd: PhantomData,
    };

    f.call(&mut backend);

    state[12] = _mm_cvtsi128_si32(backend.v[3]) as u32;
}

struct Backend<R: Unsigned> {
    v: [__m128i; 4],
    _pd: PhantomData<R>,
}

impl<R: Unsigned> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U1;
}

impl<R: Unsigned> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
        unsafe {
            let res = rounds::<R>(&self.v);
            self.v[3] = _mm_add_epi32(self.v[3], _mm_set_epi32(0, 0, 0, 1));

            let block_ptr = block.as_mut_ptr() as *mut __m128i;
            for i in 0..4 {
                _mm_storeu_si128(block_ptr.add(i), res[i]);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rounds<R: Unsigned>(v: &[__m128i; 4]) -> [__m128i; 4] {
    let mut res = *v;
    for _ in 0..R::USIZE {
        double_quarter_round(&mut res);
    }

    for i in 0..4 {
        res[i] = _mm_add_epi32(res[i], v[i]);
    }

    res
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn double_quarter_round(v: &mut [__m128i; 4]) {
    add_xor_rot(v);
    rows_to_cols(v);
    add_xor_rot(v);
    cols_to_rows(v);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rows_to_cols([a, _, c, d]: &mut [__m128i; 4]) {
    *c = _mm_shuffle_epi32(*c, 0b_00_11_10_01);
    *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10);
    *a = _mm_shuffle_epi32(*a, 0b_10_01_00_11);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn cols_to_rows([a, _, c, d]: &mut [__m128i; 4]) {
    *c = _mm_shuffle_epi32(*c, 0b_10_01_00_11);
    *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10);
    *a = _mm_shuffle_epi32(*a, 0b_00_11_10_01);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn add_xor_rot([a, b, c, d]: &mut [__m128i; 4]) {
    *a = _mm_add_epi32(*a, *b);
    *d = _mm_xor_si128(*d, *a);
    *d = _mm_xor_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));

    *c = _mm_add_epi32(*c, *d);
    *b = _mm_xor_si128(*b, *c);
    *b = _mm_xor_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));

    *a = _mm_add_epi32(*a, *b);
    *d = _mm_xor_si128(*d, *a);
    *d = _mm_xor_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));

    *c = _mm_add_epi32(*c, *d);
    *b = _mm_xor_si128(*b, *c);
    *b = _mm_xor_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
}
