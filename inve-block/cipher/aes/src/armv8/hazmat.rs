use crate::{Block, Block8};
use core::arch::aarch64::*;

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn cipher_round(block: &mut Block, round_key: &Block) {
    let b = vld1q_u8(block.as_ptr());
    let k = vld1q_u8(round_key.as_ptr());

    let mut state = vaeseq_u8(b, vdupq_n_u8(0));

    state = vaesmcq_u8(state);

    state = veorq_u8(state, k);

    vst1q_u8(block.as_mut_ptr(), state);
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    for i in 0..8 {
        let mut state = vld1q_u8(blocks[i].as_ptr());

        state = vaeseq_u8(state, vdupq_n_u8(0));

        state = vaesmcq_u8(state);

        state = veorq_u8(state, vld1q_u8(round_keys[i].as_ptr()));

        vst1q_u8(blocks[i].as_mut_ptr(), state);
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    let b = vld1q_u8(block.as_ptr());
    let k = vld1q_u8(round_key.as_ptr());

    let mut state = vaesdq_u8(b, vdupq_n_u8(0));

    state = vaesimcq_u8(state);

    state = veorq_u8(state, k);

    vst1q_u8(block.as_mut_ptr(), state);
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn equiv_inv_cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    for i in 0..8 {
        let mut state = vld1q_u8(blocks[i].as_ptr());

        state = vaesdq_u8(state, vdupq_n_u8(0));

        state = vaesimcq_u8(state);

        state = veorq_u8(state, vld1q_u8(round_keys[i].as_ptr()));

        vst1q_u8(blocks[i].as_mut_ptr(), state);
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn mix_columns(block: &mut Block) {
    let b = vld1q_u8(block.as_ptr());
    let out = vaesmcq_u8(b);
    vst1q_u8(block.as_mut_ptr(), out);
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn inv_mix_columns(block: &mut Block) {
    let b = vld1q_u8(block.as_ptr());
    let out = vaesimcq_u8(b);
    vst1q_u8(block.as_mut_ptr(), out);
}
