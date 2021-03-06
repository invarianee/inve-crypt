cpufeatures::new!(sha2_hwcap, "sha2");

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    if sha2_hwcap::get() {
        sha2_asm::compress256(state, blocks);
    } else {
        super::soft::compress(state, blocks);
    }
}
