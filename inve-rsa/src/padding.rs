use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use digest::{Digest, DynDigest};
use rand_core::RngCore;

use crate::hash::Hash;

pub enum PaddingScheme {
    PKCS1v15Encrypt,
    PKCS1v15Sign {
        hash: Option<Hash>,
    },
    OAEP {
        digest: Box<dyn DynDigest>,
        mgf_digest: Box<dyn DynDigest>,
        label: Option<String>,
    },
    PSS {
        salt_rng: Box<dyn RngCore>,
        digest: Box<dyn DynDigest>,
        salt_len: Option<usize>,
    },
}

impl fmt::Debug for PaddingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaddingScheme::PKCS1v15Encrypt => write!(f, "PaddingScheme::PKCS1v15Encrypt"),
            PaddingScheme::PKCS1v15Sign { ref hash } => {
                write!(f, "PaddingScheme::PKCS1v15Sign({:?})", hash)
            }
            PaddingScheme::OAEP { ref label, .. } => {
                write!(f, "PaddingScheme::OAEP({:?})", label)
            }
            PaddingScheme::PSS { ref salt_len, .. } => {
                write!(f, "PaddingScheme::PSS(salt_len: {:?})", salt_len)
            }
        }
    }
}

impl PaddingScheme {
    pub fn new_pkcs1v15_encrypt() -> Self {
        PaddingScheme::PKCS1v15Encrypt
    }

    pub fn new_pkcs1v15_sign(hash: Option<Hash>) -> Self {
        PaddingScheme::PKCS1v15Sign { hash }
    }

    pub fn new_oaep_with_mgf_hash<
        T: 'static + Digest + DynDigest,
        U: 'static + Digest + DynDigest,
    >() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: None,
        }
    }

    pub fn new_oaep<T: 'static + Digest + DynDigest>() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: None,
        }
    }

    pub fn new_oaep_with_mgf_hash_with_label<
        T: 'static + Digest + DynDigest,
        U: 'static + Digest + DynDigest,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    pub fn new_oaep_with_label<T: 'static + Digest + DynDigest, S: AsRef<str>>(label: S) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    pub fn new_pss<T: 'static + Digest + DynDigest, S: 'static + RngCore>(rng: S) -> Self {
        PaddingScheme::PSS {
            salt_rng: Box::new(rng),
            digest: Box::new(T::new()),
            salt_len: None,
        }
    }

    pub fn new_pss_with_salt<T: 'static + Digest + DynDigest, S: 'static + RngCore>(
        rng: S,
        len: usize,
    ) -> Self {
        PaddingScheme::PSS {
            salt_rng: Box::new(rng),
            digest: Box::new(T::new()),
            salt_len: Some(len),
        }
    }
}
