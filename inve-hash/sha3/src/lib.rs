pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    consts::{U104, U136, U144, U168, U200, U28, U32, U48, U64, U72},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        ExtendableOutputCore, FixedOutputCore, OutputSizeUser, Reset, UpdateCore, XofReaderCore,
        XofReaderCoreWrapper,
    },
    HashMarker, Output,
};

#[macro_use]
mod macros;
mod state;

use crate::state::Sha3State;

const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
const SHAKE: u8 = 0x1f;

impl_sha3!(Keccak224Core, Keccak224, U28, U144, KECCAK, "Keccak-224");
impl_sha3!(Keccak256Core, Keccak256, U32, U136, KECCAK, "Keccak-256");
impl_sha3!(Keccak384Core, Keccak384, U48, U104, KECCAK, "Keccak-384");
impl_sha3!(Keccak512Core, Keccak512, U64, U72, KECCAK, "Keccak-512");

impl_sha3!(
    Keccak256FullCore,
    Keccak256Full,
    U200,
    U136,
    KECCAK,
    "SHA-3 CryptoNight variant",
);

impl_sha3!(Sha3_224Core, Sha3_224, U28, U144, SHA3, "SHA-3-224");
impl_sha3!(Sha3_256Core, Sha3_256, U32, U136, SHA3, "SHA-3-256");
impl_sha3!(Sha3_384Core, Sha3_384, U48, U104, SHA3, "SHA-3-384");
impl_sha3!(Sha3_512Core, Sha3_512, U64, U72, SHA3, "SHA-3-512");

impl_shake!(
    Shake128Core,
    Shake128,
    Shake128ReaderCore,
    Shake128Reader,
    U168,
    SHAKE,
    "SHAKE128",
);
impl_shake!(
    Shake256Core,
    Shake256,
    Shake256ReaderCore,
    Shake256Reader,
    U136,
    SHAKE,
    "SHAKE256",
);
