mod expand_msg;

pub use expand_msg::{xmd::*, xof::*, *};

use crate::Result;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

pub trait FromOkm {
    type Length: ArrayLength<u8>;

    fn from_okm(data: &GenericArray<u8, Self::Length>) -> Self;
}

#[doc(hidden)]
pub fn hash_to_field<'a, E, T>(data: &[&[u8]], domain: &'a [u8], out: &mut [T]) -> Result<()>
where
    E: ExpandMsg<'a>,
    T: FromOkm + Default,
{
    let len_in_bytes = T::Length::to_usize() * out.len();
    let mut tmp = GenericArray::<u8, <T as FromOkm>::Length>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    for o in out.iter_mut() {
        expander.fill_bytes(&mut tmp);
        *o = T::from_okm(&tmp);
    }
    Ok(())
}
