use crate::InvalidOutputSize;

pub use crypto_common::{AlgorithmName, Block, BlockSizeUser, OutputSizeUser, Reset};

use block_buffer::{BlockBuffer, BufferKind};
use crypto_common::{
    typenum::{IsLess, Le, NonZero, U256},
    Output,
};

mod ct_variable;
mod rt_variable;
mod wrapper;
mod xof_reader;

pub use ct_variable::CtVariableCoreWrapper;
pub use rt_variable::RtVariableCoreWrapper;
pub use wrapper::{CoreProxy, CoreWrapper};
pub use xof_reader::XofReaderCoreWrapper;

pub type Buffer<S> =
    BlockBuffer<<S as BlockSizeUser>::BlockSize, <S as BufferKindUser>::BufferKind>;

pub trait UpdateCore: BlockSizeUser {
    fn update_blocks(&mut self, blocks: &[Block<Self>]);
}

pub trait BufferKindUser: BlockSizeUser {
    type BufferKind: BufferKind;
}

pub trait FixedOutputCore: UpdateCore + BufferKindUser + OutputSizeUser
where
    Self::BlockSize: IsLess<U256>,
    Le<Self::BlockSize, U256>: NonZero,
{
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>);
}

pub trait ExtendableOutputCore: UpdateCore + BufferKindUser
where
    Self::BlockSize: IsLess<U256>,
    Le<Self::BlockSize, U256>: NonZero,
{
    type ReaderCore: XofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore;
}

pub trait XofReaderCore: BlockSizeUser {
    fn read_block(&mut self) -> Block<Self>;
}

pub trait VariableOutputCore: UpdateCore + OutputSizeUser + BufferKindUser + Sized
where
    Self::BlockSize: IsLess<U256>,
    Le<Self::BlockSize, U256>: NonZero,
{
    const TRUNC_SIDE: TruncSide;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize>;

    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>);
}

#[derive(Copy, Clone, Debug)]
pub enum TruncSide {
    Left,
    Right,
}
