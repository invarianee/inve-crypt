pub use digest::{self, Digest};

use digest::{
    consts::{U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
};

#[rustfmt::skip]
mod consts;
mod core_api;
mod sha256;
mod sha512;

#[cfg(feature = "compress")]
pub use sha256::compress256;
#[cfg(feature = "compress")]
pub use sha512::compress512;

pub use core_api::{Sha256VarCore, Sha512VarCore};

pub type Sha224 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U28>>;
pub type Sha256 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32>>;
pub type Sha512_224 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U28>>;
pub type Sha512_256 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U32>>;
pub type Sha384 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48>>;
pub type Sha512 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U64>>;
