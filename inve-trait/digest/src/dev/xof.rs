use crate::ExtendableOutputReset;
use core::fmt::Debug;

pub fn xof_reset_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
where
    D: ExtendableOutputReset + Default + Debug + Clone,
{
    let mut hasher = D::default();
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Some("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    hasher2.reset();
    hasher2.update(input);
    hasher2.finalize_xof_reset_into(buf);
    if buf != output {
        return Some("whole message after reset");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::default();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if buf != output {
            return Some("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);

        hasher2.finalize_xof_reset_into(buf);
        if buf != output {
            return Some("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    None
}
