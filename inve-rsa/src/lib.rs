#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use num_bigint::BigUint;
pub use rand_core;

pub mod algorithms;
pub mod errors;
pub mod hash;
pub mod padding;

mod encoding;
mod key;
mod oaep;
mod pkcs1v15;
mod pss;
mod raw;

pub use pkcs1;
pub use pkcs8;

pub use self::hash::Hash;
pub use self::key::{PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
pub use self::padding::PaddingScheme;

#[cfg(not(feature = "expose-internals"))]
mod internals;

#[cfg(feature = "expose-internals")]
#[cfg_attr(docsrs, doc(cfg(feature = "expose-internals")))]
pub mod internals;
