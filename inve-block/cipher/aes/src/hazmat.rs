use crate::{soft::fixslice::hazmat as soft, Block, Block8};

#[cfg(all(target_arch = "aarch64", aes_armv8, not(aes_force_soft)))]
use crate::armv8::hazmat as intrinsics;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(aes_force_soft)))]
use crate::ni::hazmat as intrinsics;

#[cfg(all(
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(target_arch = "aarch64", aes_armv8)
    ),
    not(aes_force_soft)
))]
cpufeatures::new!(aes_intrinsics, "aes");

macro_rules! if_intrinsics_available {
    ($body:expr) => {{
        #[cfg(all(
            any(
                target_arch = "x86",
                target_arch = "x86_64",
                all(target_arch = "aarch64", aes_armv8)
            ),
            not(aes_force_soft)
        ))]
        if aes_intrinsics::get() {
            unsafe { $body }
            return;
        }
    }};
}

pub fn cipher_round(block: &mut Block, round_key: &Block) {
    if_intrinsics_available! {
        intrinsics::cipher_round(block, round_key)
    }

    soft::cipher_round(block, round_key);
}

pub fn cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    if_intrinsics_available! {
        intrinsics::cipher_round_par(blocks, round_keys)
    }

    soft::cipher_round_par(blocks, round_keys);
}

pub fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    if_intrinsics_available! {
        intrinsics::equiv_inv_cipher_round(block, round_key)
    }

    soft::equiv_inv_cipher_round(block, round_key);
}

pub fn equiv_inv_cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    if_intrinsics_available! {
        intrinsics::equiv_inv_cipher_round_par(blocks, round_keys)
    }

    soft::equiv_inv_cipher_round_par(blocks, round_keys);
}

pub fn mix_columns(block: &mut Block) {
    if_intrinsics_available! {
        intrinsics::mix_columns(block)
    }

    soft::mix_columns(block);
}

pub fn inv_mix_columns(block: &mut Block) {
    if_intrinsics_available! {
        intrinsics::inv_mix_columns(block)
    }

    soft::inv_mix_columns(block);
}
