#[cfg(feature = "std")]
extern crate std;

#[cfg(all(feature = "signature_derive", not(feature = "derive-preview")))]
compile_error!(
    "The `signature_derive` feature should not be enabled directly. \
    Use the `derive-preview` feature instead."
);

#[cfg(all(feature = "digest", not(feature = "digest-preview")))]
compile_error!(
    "The `digest` feature should not be enabled directly. \
    Use the `digest-preview` feature instead."
);

#[cfg(all(feature = "rand_core", not(feature = "rand-preview")))]
compile_error!(
    "The `rand_core` feature should not be enabled directly. \
    Use the `rand-preview` feature instead."
);

#[cfg(feature = "derive-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive-preview")))]
pub use signature_derive::{Signer, Verifier};

#[cfg(feature = "digest-preview")]
pub use digest;

#[cfg(feature = "rand-preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand-preview")))]
pub use rand_core;

mod error;
mod signature;
mod signer;
mod verifier;

pub use crate::{error::*, signature::*, signer::*, verifier::*};
