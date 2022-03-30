#![no_std]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(feature = "simd_backend", feature(stdsimd))]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(all(feature = "nightly", feature = "packed_simd"))]
extern crate packed_simd;

extern crate byteorder;
pub extern crate digest;
extern crate rand_core;
extern crate zeroize;

#[cfg(any(feature = "fiat_u64_backend", feature = "fiat_u32_backend"))]
extern crate fiat_crypto;

extern crate subtle;

#[cfg(all(test, feature = "serde"))]
extern crate bincode;
#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
pub(crate) mod macros;

pub mod scalar;

pub mod montgomery;

pub mod edwards;

pub mod ristretto;

pub mod constants;

pub mod traits;

pub(crate) mod field;

pub(crate) mod backend;

pub(crate) mod prelude;

pub(crate) mod window;
