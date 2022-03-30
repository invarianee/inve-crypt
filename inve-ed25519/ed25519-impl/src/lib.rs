#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

pub extern crate ed25519;

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
extern crate curve25519;
#[cfg(all(
    any(feature = "batch", feature = "batch_deterministic"),
    any(feature = "std", feature = "alloc")
))]
extern crate merlin;
#[cfg(any(feature = "batch", feature = "std", feature = "alloc", test))]
extern crate rand;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;
extern crate sha2;
extern crate zeroize;

#[cfg(all(
    any(feature = "batch", feature = "batch_deterministic"),
    any(feature = "std", feature = "alloc")
))]
mod batch;
mod constants;
mod errors;
mod keypair;
mod public;
mod secret;
mod signature;

pub use curve25519::digest::Digest;

#[cfg(all(
    any(feature = "batch", feature = "batch_deterministic"),
    any(feature = "std", feature = "alloc")
))]
pub use crate::batch::*;
pub use crate::constants::*;
pub use crate::errors::*;
pub use crate::keypair::*;
pub use crate::public::*;
pub use crate::secret::*;

pub use ed25519::signature::{Signer, Verifier};
pub use ed25519::Signature;
