use universal_hash::generic_array::GenericArray;

use crate::{backend, Block, Key, BLOCK_SIZE};

pub fn fuzz_avx2(key: &Key, data: &[u8]) {
    let mut avx2 = backend::avx2::State::new(key);
    let mut soft = backend::soft::State::new(key);

    for (_i, chunk) in data.chunks(BLOCK_SIZE).enumerate() {
        if chunk.len() == BLOCK_SIZE {
            let block = GenericArray::from_slice(chunk);
            unsafe {
                avx2.compute_block(block, false);
            }
            soft.compute_block(block, false);
        } else {
            let mut block = Block::default();
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            unsafe {
                avx2.compute_block(&block, true);
            }
            soft.compute_block(&block, true);
        }

        #[cfg(test)]
        assert_eq!(
            (_i + 1, unsafe { avx2.clone().finalize().into_bytes() }),
            (_i + 1, soft.clone().finalize().into_bytes()),
        );
    }

    assert_eq!(
        unsafe { avx2.finalize().into_bytes() },
        soft.finalize().into_bytes()
    );
}

fn avx2_fuzzer_test_case(data: &[u8]) {
    fuzz_avx2(data[0..32].into(), &data[32..]);
}

#[test]
fn crash_0() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000000,sig=06,src=000014,op=flip4,pos=11"
    ));
}

#[test]
fn crash_1() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000001,sig=06,src=000006+000014,op=splice,rep=64"
    ));
}

#[test]
fn crash_2() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000002,sig=06,src=000008+000014,op=splice,rep=32"
    ));
}

#[test]
fn crash_3() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000003,sig=06,src=000003,op=havoc,rep=64"
    ));
}

#[test]
fn crash_4() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000004,sig=06,src=000022+000005,op=splice,rep=32"
    ));
}

#[test]
fn crash_5() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000005,sig=06,src=000008+000007,op=splice,rep=128"
    ));
}

#[test]
fn crash_6() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000006,sig=06,src=000005,op=havoc,rep=8"
    ));
}

#[test]
fn crash_7() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000007,sig=06,src=000024+000000,op=splice,rep=64"
    ));
}

#[test]
fn crash_8() {
    avx2_fuzzer_test_case(include_bytes!(
        "fuzz/id=000008,sig=06,src=000019,time=165655+000011,op=splice,rep=128"
    ));
}
