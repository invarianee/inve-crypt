cpufeatures::new!(sha1_hwcap, "sha2");

pub fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) {
    if sha1_hwcap::get() {
        sha1_asm::compress(state, blocks);
    } else {
        super::soft::compress(state, blocks);
    }
}
