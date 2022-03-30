use universal_hash::generic_array::GenericArray;

use crate::{Block, Key, Tag};

mod helpers;
use self::helpers::*;

#[derive(Copy, Clone)]
struct Initialized {
    p: Aligned4x130,
    m: SpacedMultiplier4x130,
    r4: PrecomputedMultiplier,
}

#[derive(Clone)]
pub(crate) struct State {
    k: AdditionKey,
    r1: PrecomputedMultiplier,
    r2: PrecomputedMultiplier,
    initialized: Option<Initialized>,
    cached_blocks: [Block; 4],
    num_cached_blocks: usize,
    partial_block: Option<Block>,
}

impl State {
    pub(crate) fn new(key: &Key) -> Self {
        let (k, r1) = unsafe { prepare_keys(key) };

        let r2 = (r1 * r1).reduce();

        State {
            k,
            r1,
            r2: r2.into(),
            initialized: None,
            cached_blocks: [Block::default(); 4],
            num_cached_blocks: 0,
            partial_block: None,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.initialized = None;
        self.num_cached_blocks = 0;
    }

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn compute_block(&mut self, block: &Block, partial: bool) {
        if partial {
            assert!(self.partial_block.is_none());
            self.partial_block = Some(*block);
            return;
        }

        self.cached_blocks[self.num_cached_blocks].copy_from_slice(block);
        if self.num_cached_blocks < 3 {
            self.num_cached_blocks += 1;
            return;
        } else {
            self.num_cached_blocks = 0;
        }

        if let Some(inner) = &mut self.initialized {
            inner.p =
                (&inner.p * inner.r4).reduce() + Aligned4x130::from_blocks(&self.cached_blocks);
        } else {
            let p = Aligned4x130::from_blocks(&self.cached_blocks);

            let (m, r4) = SpacedMultiplier4x130::new(self.r1, self.r2);

            self.initialized = Some(Initialized { p, m, r4 })
        }
    }

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn finalize(&mut self) -> Tag {
        assert!(self.num_cached_blocks < 4);
        let mut data = &self.cached_blocks[..];

        let mut p = self
            .initialized
            .take()
            .map(|inner| (inner.p * inner.m).sum().reduce());

        if self.num_cached_blocks >= 2 {
            let mut c = Aligned2x130::from_blocks(data[..2].try_into().unwrap());
            if let Some(p) = p {
                c = c + p;
            }
            p = Some(c.mul_and_sum(self.r1, self.r2).reduce());
            data = &data[2..];
            self.num_cached_blocks -= 2;
        }

        if self.num_cached_blocks == 1 {
            let mut c = Aligned130::from_block(&data[0]);
            if let Some(p) = p {
                c = c + p;
            }
            p = Some((c * self.r1).reduce());
            self.num_cached_blocks -= 1;
        }

        if let Some(block) = &self.partial_block {
            let mut c = Aligned130::from_partial_block(block);
            if let Some(p) = p {
                c = c + p;
            }
            p = Some((c * self.r1).reduce());
        }

        let mut tag = GenericArray::<u8, _>::default();
        let tag_int = if let Some(p) = p {
            self.k + p
        } else {
            self.k.into()
        };
        tag_int.write(tag.as_mut_slice());

        Tag::new(tag)
    }
}
