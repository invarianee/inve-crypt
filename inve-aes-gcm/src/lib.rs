pub mod aes_gcm;

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};

pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};
