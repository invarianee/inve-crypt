use core::{arch::aarch64::*, mem, slice};

const BLOCK_WORDS: usize = 4;

const WORD_SIZE: usize = 4;

const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline]
pub(super) fn expand_key<const L: usize, const N: usize>(key: &[u8; L]) -> [uint8x16_t; N] {
    assert!((L == 16 && N == 11) || (L == 24 && N == 13) || (L == 32 && N == 15));

    let mut expanded_keys: [uint8x16_t; N] = unsafe { mem::zeroed() };

    let ek_words = unsafe {
        slice::from_raw_parts_mut(expanded_keys.as_mut_ptr() as *mut u32, N * BLOCK_WORDS)
    };

    for (i, chunk) in key.chunks_exact(WORD_SIZE).enumerate() {
        ek_words[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    let nk = L / WORD_SIZE;

    for i in nk..(N * BLOCK_WORDS) {
        let mut word = ek_words[i - 1];

        if i % nk == 0 {
            word = sub_word(word).rotate_right(8) ^ ROUND_CONSTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            word = sub_word(word)
        }

        ek_words[i] = ek_words[i - nk] ^ word;
    }

    expanded_keys
}

#[inline]
pub(super) fn inv_expanded_keys<const N: usize>(expanded_keys: &mut [uint8x16_t; N]) {
    assert!(N == 11 || N == 13 || N == 15);

    for ek in expanded_keys.iter_mut().take(N - 1).skip(1) {
        unsafe { *ek = vaesimcq_u8(*ek) }
    }

    expanded_keys.reverse();
}

#[inline(always)]
fn sub_word(input: u32) -> u32 {
    unsafe {
        let input = vreinterpretq_u8_u32(vdupq_n_u32(input));

        let sub_input = vaeseq_u8(input, vdupq_n_u8(0));

        vgetq_lane_u32(vreinterpretq_u32_u8(sub_input), 0)
    }
}
