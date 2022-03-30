#![allow(clippy::upper_case_acronyms)]

use crate::{AeadCore, AeadInPlace, Buffer, Error, Key, NewAead, Result};
use core::ops::{AddAssign, Sub};
use generic_array::{
    typenum::{Unsigned, U4, U5},
    ArrayLength, GenericArray,
};

#[cfg(feature = "alloc")]
use {crate::Payload, alloc::vec::Vec};

pub type Nonce<A, S> = GenericArray<u8, NonceSize<A, S>>;

pub type NonceSize<A, S> =
    <<A as AeadCore>::NonceSize as Sub<<S as StreamPrimitive<A>>::NonceOverhead>>::Output;

pub type EncryptorBE32<A> = Encryptor<A, StreamBE32<A>>;

pub type DecryptorBE32<A> = Decryptor<A, StreamBE32<A>>;

pub type EncryptorLE31<A> = Encryptor<A, StreamLE31<A>>;

pub type DecryptorLE31<A> = Decryptor<A, StreamLE31<A>>;

pub trait NewStream<A>: StreamPrimitive<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<Self::NonceOverhead>,
    NonceSize<A, Self>: ArrayLength<u8>,
{
    fn new(key: &Key<A>, nonce: &Nonce<A, Self>) -> Self
    where
        A: NewAead,
        Self: Sized,
    {
        Self::from_aead(A::new(key), nonce)
    }

    fn from_aead(aead: A, nonce: &Nonce<A, Self>) -> Self;
}

pub trait StreamPrimitive<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<Self::NonceOverhead>,
    NonceSize<A, Self>: ArrayLength<u8>,
{
    type NonceOverhead: ArrayLength<u8>;

    type Counter: AddAssign + Copy + Default + Eq;

    const COUNTER_INCR: Self::Counter;

    const COUNTER_MAX: Self::Counter;

    fn encrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()>;

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn encrypt<'msg, 'aad>(
        &self,
        position: Self::Counter,
        last_block: bool,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = plaintext.into();
        let mut buffer = Vec::with_capacity(payload.msg.len() + A::TagSize::to_usize());
        buffer.extend_from_slice(payload.msg);
        self.encrypt_in_place(position, last_block, payload.aad, &mut buffer)?;
        Ok(buffer)
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn decrypt<'msg, 'aad>(
        &self,
        position: Self::Counter,
        last_block: bool,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let payload = ciphertext.into();
        let mut buffer = Vec::from(payload.msg);
        self.decrypt_in_place(position, last_block, payload.aad, &mut buffer)?;
        Ok(buffer)
    }

    fn encryptor(self) -> Encryptor<A, Self>
    where
        Self: Sized,
    {
        Encryptor::from_stream_primitive(self)
    }

    fn decryptor(self) -> Decryptor<A, Self>
    where
        Self: Sized,
    {
        Decryptor::from_stream_primitive(self)
    }
}

macro_rules! impl_stream_object {
    (
        $name:ident,
        $next_method:tt,
        $next_in_place_method:tt,
        $last_method:tt,
        $last_in_place_method:tt,
        $op:tt,
        $in_place_op:tt,
        $op_desc:expr,
        $obj_desc:expr
    ) => {
        #[doc = "Stateful STREAM object which can"]
        #[doc = $op_desc]
        #[doc = "AEAD messages one-at-a-time."]
        #[doc = ""]
        #[doc = "This corresponds to the "]
        #[doc = $obj_desc]
        #[doc = "object as defined in the paper"]
        #[doc = "[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][1]."]
        #[doc = ""]
        #[doc = "[1]: https://eprint.iacr.org/2015/189.pdf"]
        pub struct $name<A, S>
        where
            A: AeadInPlace,
            S: StreamPrimitive<A>,
            A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
            NonceSize<A, S>: ArrayLength<u8>,
        {
            stream: S,

            position: S::Counter,
        }

        impl<A, S> $name<A, S>
        where
            A: AeadInPlace,
            S: StreamPrimitive<A>,
            A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
            NonceSize<A, S>: ArrayLength<u8>,
        {
            #[doc = "Create a"]
            #[doc = $obj_desc]
            #[doc = "object from the given AEAD key and nonce."]
            pub fn new(key: &Key<A>, nonce: &Nonce<A, S>) -> Self
            where
                A: NewAead,
                S: NewStream<A>,
            {
                Self::from_stream_primitive(S::new(key, nonce))
            }

            #[doc = "Create a"]
            #[doc = $obj_desc]
            #[doc = "object from the given AEAD primitive."]
            pub fn from_aead(aead: A, nonce: &Nonce<A, S>) -> Self
            where
                A: NewAead,
                S: NewStream<A>,
            {
                Self::from_stream_primitive(S::from_aead(aead, nonce))
            }

            #[doc = "Create a"]
            #[doc = $obj_desc]
            #[doc = "object from the given STREAM primitive."]
            pub fn from_stream_primitive(stream: S) -> Self {
                Self {
                    stream,
                    position: Default::default(),
                }
            }

            #[doc = "Use the underlying AEAD to"]
            #[doc = $op_desc]
            #[doc = "the next AEAD message in this STREAM, returning the"]
            #[doc = "result as a [`Vec`]."]
            #[cfg(feature = "alloc")]
            #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
            pub fn $next_method<'msg, 'aad>(
                &mut self,
                payload: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>> {
                if self.position == S::COUNTER_MAX {
                    return Err(Error);
                }

                let result = self.stream.$op(self.position, false, payload)?;

                self.position += S::COUNTER_INCR;
                Ok(result)
            }

            #[doc = "Use the underlying AEAD to"]
            #[doc = $op_desc]
            #[doc = "the next AEAD message in this STREAM in-place."]
            pub fn $next_in_place_method(
                &mut self,
                associated_data: &[u8],
                buffer: &mut dyn Buffer,
            ) -> Result<()> {
                if self.position == S::COUNTER_MAX {
                    return Err(Error);
                }

                self.stream
                    .$in_place_op(self.position, false, associated_data, buffer)?;

                self.position += S::COUNTER_INCR;
                Ok(())
            }

            #[doc = "Use the underlying AEAD to"]
            #[doc = $op_desc]
            #[doc = "the last AEAD message in this STREAM,"]
            #[doc = "consuming the "]
            #[doc = $obj_desc]
            #[doc = "object in order to prevent further use."]
            #[cfg(feature = "alloc")]
            #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
            pub fn $last_method<'msg, 'aad>(
                self,
                payload: impl Into<Payload<'msg, 'aad>>,
            ) -> Result<Vec<u8>> {
                self.stream.$op(self.position, true, payload)
            }

            #[doc = "Use the underlying AEAD to"]
            #[doc = $op_desc]
            #[doc = "the last AEAD message in this STREAM in-place,"]
            #[doc = "consuming the "]
            #[doc = $obj_desc]
            #[doc = "object in order to prevent further use."]
            pub fn $last_in_place_method(
                self,
                associated_data: &[u8],
                buffer: &mut dyn Buffer,
            ) -> Result<()> {
                self.stream
                    .$in_place_op(self.position, true, associated_data, buffer)
            }
        }
    };
}

impl_stream_object!(
    Encryptor,
    encrypt_next,
    encrypt_next_in_place,
    encrypt_last,
    encrypt_last_in_place,
    encrypt,
    encrypt_in_place,
    "encrypt",
    "ℰ STREAM encryptor"
);

impl_stream_object!(
    Decryptor,
    decrypt_next,
    decrypt_next_in_place,
    decrypt_last,
    decrypt_last_in_place,
    decrypt,
    decrypt_in_place,
    "decrypt",
    "𝒟 STREAM decryptor"
);

pub struct StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    aead: A,

    nonce: Nonce<A, Self>,
}

impl<A> NewStream<A> for StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn from_aead(aead: A, nonce: &Nonce<A, Self>) -> Self {
        Self {
            aead,
            nonce: nonce.clone(),
        }
    }
}

impl<A> StreamPrimitive<A> for StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    type NonceOverhead = U5;
    type Counter = u32;
    const COUNTER_INCR: u32 = 1;
    const COUNTER_MAX: u32 = core::u32::MAX;

    fn encrypt_in_place(
        &self,
        position: u32,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block);
        self.aead.encrypt_in_place(&nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block);
        self.aead.decrypt_in_place(&nonce, associated_data, buffer)
    }
}

impl<A> StreamBE32<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn aead_nonce(&self, position: u32, last_block: bool) -> crate::Nonce<A> {
        let mut result = GenericArray::default();

        let (prefix, tail) = result.split_at_mut(NonceSize::<A, Self>::to_usize());
        prefix.copy_from_slice(&self.nonce);

        let (counter, flag) = tail.split_at_mut(4);
        counter.copy_from_slice(&position.to_be_bytes());
        flag[0] = last_block as u8;

        result
    }
}

pub struct StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    aead: A,

    nonce: Nonce<A, Self>,
}

impl<A> NewStream<A> for StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    fn from_aead(aead: A, nonce: &Nonce<A, Self>) -> Self {
        Self {
            aead,
            nonce: nonce.clone(),
        }
    }
}

impl<A> StreamPrimitive<A> for StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    type NonceOverhead = U4;
    type Counter = u32;
    const COUNTER_INCR: u32 = 1;
    const COUNTER_MAX: u32 = 0xfff_ffff;

    fn encrypt_in_place(
        &self,
        position: u32,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block)?;
        self.aead.encrypt_in_place(&nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = self.aead_nonce(position, last_block)?;
        self.aead.decrypt_in_place(&nonce, associated_data, buffer)
    }
}

impl<A> StreamLE31<A>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U4>,
    <<A as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    fn aead_nonce(&self, position: u32, last_block: bool) -> Result<crate::Nonce<A>> {
        if position > Self::COUNTER_MAX {
            return Err(Error);
        }

        let mut result = GenericArray::default();

        let (prefix, tail) = result.split_at_mut(NonceSize::<A, Self>::to_usize());
        prefix.copy_from_slice(&self.nonce);

        let position_with_flag = position | ((last_block as u32) << 31);
        tail.copy_from_slice(&position_with_flag.to_le_bytes());

        Ok(result)
    }
}
