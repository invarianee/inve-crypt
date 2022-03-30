pub mod flavors;

mod backend;
mod ctr_core;

pub use cipher;
pub use flavors::CtrFlavor;

use cipher::StreamCipherCoreWrapper;
pub use ctr_core::CtrCore;

pub type Ctr128BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr128BE>>;
pub type Ctr128LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr128LE>>;
pub type Ctr64BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr64BE>>;
pub type Ctr64LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr64LE>>;
pub type Ctr32BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr32BE>>;
pub type Ctr32LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr32LE>>;
