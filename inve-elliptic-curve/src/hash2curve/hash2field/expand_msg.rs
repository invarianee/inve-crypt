pub(super) mod xmd;
pub(super) mod xof;

use crate::{Error, Result};
use digest::{Digest, ExtendableOutput, Update, XofReader};
use generic_array::typenum::{IsLess, U256};
use generic_array::{ArrayLength, GenericArray};

const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";
const MAX_DST_LEN: usize = 255;

pub trait ExpandMsg<'a> {
    type Expander: Expander + Sized;

    fn expand_message(msgs: &[&[u8]], dst: &'a [u8], len_in_bytes: usize)
        -> Result<Self::Expander>;
}

pub trait Expander {
    fn fill_bytes(&mut self, okm: &mut [u8]);
}

pub(crate) enum Domain<'a, L>
where
    L: ArrayLength<u8> + IsLess<U256>,
{
    Hashed(GenericArray<u8, L>),
    Array(&'a [u8]),
}

impl<'a, L> Domain<'a, L>
where
    L: ArrayLength<u8> + IsLess<U256>,
{
    pub fn xof<X>(dst: &'a [u8]) -> Result<Self>
    where
        X: Default + ExtendableOutput + Update,
    {
        if dst.is_empty() {
            Err(Error)
        } else if dst.len() > MAX_DST_LEN {
            let mut data = GenericArray::<u8, L>::default();
            X::default()
                .chain(OVERSIZE_DST_SALT)
                .chain(dst)
                .finalize_xof()
                .read(&mut data);
            Ok(Self::Hashed(data))
        } else {
            Ok(Self::Array(dst))
        }
    }

    pub fn xmd<X>(dst: &'a [u8]) -> Result<Self>
    where
        X: Digest<OutputSize = L>,
    {
        if dst.is_empty() {
            Err(Error)
        } else if dst.len() > MAX_DST_LEN {
            Ok(Self::Hashed({
                let mut hash = X::new();
                hash.update(OVERSIZE_DST_SALT);
                hash.update(dst);
                hash.finalize()
            }))
        } else {
            Ok(Self::Array(dst))
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            Self::Hashed(d) => &d[..],
            Self::Array(d) => *d,
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            Self::Hashed(_) => L::to_u8(),
            Self::Array(d) => u8::try_from(d.len()).expect("length overflow"),
        }
    }

    #[cfg(test)]
    pub fn assert(&self, bytes: &[u8]) {
        assert_eq!(self.data(), &bytes[..bytes.len() - 1]);
        assert_eq!(self.len(), bytes[bytes.len() - 1]);
    }
}
