use crate::{Digest, FixedOutput, FixedOutputReset, HashMarker, Update};
use core::fmt::Debug;

pub fn fixed_reset_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
where
    D: FixedOutputReset + Debug + Clone + Default + Update + HashMarker,
{
    let mut hasher = D::new();
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    if hasher.finalize()[..] != output[..] {
        return Some("whole message");
    }

    hasher2.reset();
    hasher2.update(input);
    if hasher2.finalize_reset()[..] != output[..] {
        return Some("whole message after reset");
    }

    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::new();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        if hasher.finalize()[..] != output[..] {
            return Some("message in chunks");
        }
        if hasher2.finalize_reset()[..] != output[..] {
            return Some("message in chunks");
        }
    }

    None
}

pub fn fixed_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
where
    D: FixedOutput + Default + Debug + Clone,
{
    let mut hasher = D::default();
    hasher.update(input);
    if hasher.finalize_fixed()[..] != output[..] {
        return Some("whole message");
    }

    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::default();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
        }
        if hasher.finalize_fixed()[..] != output[..] {
            return Some("message in chunks");
        }
    }
    None
}
