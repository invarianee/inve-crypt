#[cfg(feature = "std")]
extern crate std;

pub use universal_hash;

use universal_hash::{
    consts::{U16, U32},
    generic_array::GenericArray,
    NewUniversalHash, UniversalHash,
};

mod backend;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "force-soft"),
    target_feature = "avx2",
    any(fuzzing, test)
))]
mod fuzz;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "force-soft")
))]
use crate::backend::autodetect::State;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "force-soft")
)))]
use crate::backend::soft::State;

pub const KEY_SIZE: usize = 32;

pub const BLOCK_SIZE: usize = 16;

pub type Key = universal_hash::Key<Poly1305>;

pub type Block = universal_hash::Block<Poly1305>;

pub type Tag = universal_hash::Output<Poly1305>;

#[derive(Clone)]
pub struct Poly1305 {
    state: State,
}

impl NewUniversalHash for Poly1305 {
    type KeySize = U32;

    fn new(key: &Key) -> Poly1305 {
        Poly1305 {
            state: State::new(key),
        }
    }
}

impl UniversalHash for Poly1305 {
    type BlockSize = U16;

    fn update(&mut self, block: &Block) {
        self.state.compute_block(block, false);
    }

    fn reset(&mut self) {
        self.state.reset();
    }

    fn finalize(mut self) -> Tag {
        self.state.finalize()
    }
}

impl Poly1305 {
    pub fn compute_unpadded(mut self, data: &[u8]) -> Tag {
        for chunk in data.chunks(BLOCK_SIZE) {
            if chunk.len() == BLOCK_SIZE {
                let block = GenericArray::from_slice(chunk);
                self.state.compute_block(block, false);
            } else {
                let mut block = Block::default();
                block[..chunk.len()].copy_from_slice(chunk);
                block[chunk.len()] = 1;
                self.state.compute_block(&block, true)
            }
        }

        self.state.finalize()
    }
}

opaque_debug::implement!(Poly1305);

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "force-soft"),
    target_feature = "avx2",
    any(fuzzing, test)
))]
pub use crate::fuzz::fuzz_avx2;
