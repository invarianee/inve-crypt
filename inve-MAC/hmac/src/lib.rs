#[cfg(feature = "std")]
extern crate std;

pub use digest;
pub use digest::Mac;

use digest::{
    core_api::{Block, BlockSizeUser},
    Digest,
};

mod optim;
mod simple;

pub use optim::{Hmac, HmacCore};
pub use simple::SimpleHmac;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

fn get_der_key<D: Digest + BlockSizeUser>(key: &[u8]) -> Block<D> {
    let mut der_key = Block::<D>::default();
    if key.len() <= der_key.len() {
        der_key[..key.len()].copy_from_slice(key);
    } else {
        let hash = D::digest(key);
        if hash.len() <= der_key.len() {
            der_key[..hash.len()].copy_from_slice(&hash);
        } else {
            let n = der_key.len();
            der_key.copy_from_slice(&hash[..n]);
        }
    }
    der_key
}
