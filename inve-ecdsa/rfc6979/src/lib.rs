use hmac::digest::block_buffer::Eager;
use hmac::digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore};
use hmac::digest::generic_array::typenum::{IsLess, Le, NonZero, U256};
use hmac::digest::generic_array::GenericArray;
use hmac::digest::{FixedOutput, HashMarker, OutputSizeUser};
use hmac::{Hmac, Mac};
use inve_bigint::{ArrayEncoding, ByteArray, Integer};
use zeroize::{Zeroize, Zeroizing};

#[inline]
pub fn generate_k<D, I>(x: &I, n: &I, h: &ByteArray<I>, data: &[u8]) -> Zeroizing<I>
where
    D: CoreProxy + FixedOutput<OutputSize = I::ByteSize>,
    I: ArrayEncoding + Integer + Zeroize,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut x = x.to_be_byte_array();
    let mut hmac_drbg = HmacDrbg::<D>::new(&x, h, data);
    x.zeroize();

    loop {
        let mut bytes = ByteArray::<I>::default();
        hmac_drbg.fill_bytes(&mut bytes);
        let k = I::from_be_byte_array(bytes);

        if (!k.is_zero() & k.ct_lt(n)).into() {
            return Zeroizing::new(k);
        }
    }
}

pub struct HmacDrbg<D>
where
    D: CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    k: Hmac<D>,

    v: GenericArray<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub fn new(entropy_input: &[u8], nonce: &[u8], additional_data: &[u8]) -> Self {
        let mut k = Hmac::new(&Default::default());
        let mut v = GenericArray::default();

        for b in &mut v {
            *b = 0x01;
        }

        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(entropy_input);
            k.update(nonce);
            k.update(additional_data);
            k = Hmac::new_from_slice(&k.finalize().into_bytes()).expect("HMAC error");

            k.update(&v);
            v = k.finalize_reset().into_bytes();
        }

        Self { k, v }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(self.v.len()) {
            self.k.update(&self.v);
            self.v = self.k.finalize_reset().into_bytes();
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        self.k.update(&self.v);
        self.k.update(&[0x00]);
        self.k = Hmac::new_from_slice(&self.k.finalize_reset().into_bytes()).expect("HMAC error");
        self.k.update(&self.v);
        self.v = self.k.finalize_reset().into_bytes();
    }
}
