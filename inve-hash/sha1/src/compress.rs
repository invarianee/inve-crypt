use crate::{Block, BlockSizeUser, Sha1Core};
use digest::typenum::Unsigned;

cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress as compress_inner;
    } else if #[cfg(all(feature = "asm", target_arch = "aarch64"))] {
        mod soft;
        mod aarch64;
        use aarch64::compress as compress_inner;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(not(feature = "asm"))]
        mod soft;
        #[cfg(feature = "asm")]
        mod soft {
            pub use sha1_asm::compress;
        }
        mod x86;
        use x86::compress as compress_inner;
    } else {
        mod soft;
        use soft::compress as compress_inner;
    }
}

const BLOCK_SIZE: usize = <Sha1Core as BlockSizeUser>::BlockSize::USIZE;

#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress(state: &mut [u32; 5], blocks: &[Block<Sha1Core>]) {
    let blocks: &[[u8; BLOCK_SIZE]] =
        unsafe { &*(blocks as *const _ as *const [[u8; BLOCK_SIZE]]) };
    compress_inner(state, blocks);
}
