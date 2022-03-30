pub use cipher;
use cipher::{
    consts::{U16, U32},
    generic_array::GenericArray,
};

mod consts;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sse2",
    not(kuznyechik_force_soft),
))]
#[path = "sse2/mod.rs"]
mod imp;

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sse2",
    not(kuznyechik_force_soft),
)))]
#[path = "soft/mod.rs"]
mod imp;

pub use imp::{Kuznyechik, KuznyechikDec, KuznyechikEnc};

type BlockSize = U16;
type KeySize = U32;

pub type Block = GenericArray<u8, U16>;
pub type Key = GenericArray<u8, U32>;
