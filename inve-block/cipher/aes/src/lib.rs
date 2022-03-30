#[cfg(feature = "hazmat")]
pub mod hazmat;

mod soft;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", aes_armv8, not(aes_force_soft)))] {
        mod armv8;
        mod autodetect;
        pub use autodetect::*;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(aes_force_soft)
    ))] {
        mod autodetect;
        mod ni;
        pub use autodetect::*;
    } else {
        pub use soft::*;
    }
}

pub use cipher;
use cipher::{
    consts::{U16, U8},
    generic_array::GenericArray,
};

pub type Block = GenericArray<u8, U16>;
pub type Block8 = GenericArray<Block, U8>;

#[cfg(test)]
mod tests {
    #[cfg(feature = "zeroize")]
    #[test]
    fn zeroize_works() {
        use super::soft;

        fn test_for<T: zeroize::ZeroizeOnDrop>(val: T) {
            use core::mem::{size_of, ManuallyDrop};

            let mut val = ManuallyDrop::new(val);
            let ptr = &val as *const _ as *const u8;
            let len = size_of::<ManuallyDrop<T>>();

            unsafe { ManuallyDrop::drop(&mut val) };

            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

            assert!(slice.iter().all(|&byte| byte == 0));
        }

        let key_128 = [42; 16].into();
        let key_192 = [42; 24].into();
        let key_256 = [42; 32].into();

        use cipher::KeyInit as _;
        test_for(soft::Aes128::new(&key_128));
        test_for(soft::Aes128Enc::new(&key_128));
        test_for(soft::Aes128Dec::new(&key_128));
        test_for(soft::Aes192::new(&key_192));
        test_for(soft::Aes192Enc::new(&key_192));
        test_for(soft::Aes192Dec::new(&key_192));
        test_for(soft::Aes256::new(&key_256));
        test_for(soft::Aes256Enc::new(&key_256));
        test_for(soft::Aes256Dec::new(&key_256));

        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(aes_force_soft)))]
        {
            use super::ni;

            cpufeatures::new!(aes_intrinsics, "aes");
            if aes_intrinsics::get() {
                test_for(ni::Aes128::new(&key_128));
                test_for(ni::Aes128Enc::new(&key_128));
                test_for(ni::Aes128Dec::new(&key_128));
                test_for(ni::Aes192::new(&key_192));
                test_for(ni::Aes192Enc::new(&key_192));
                test_for(ni::Aes192Dec::new(&key_192));
                test_for(ni::Aes256::new(&key_256));
                test_for(ni::Aes256Enc::new(&key_256));
                test_for(ni::Aes256Dec::new(&key_256));
            }
        }

        #[cfg(all(target_arch = "aarch64", aes_armv8, not(aes_force_soft)))]
        {
            use super::armv8;

            cpufeatures::new!(aes_intrinsics, "aes");
            if aes_intrinsics::get() {
                test_for(armv8::Aes128::new(&key_128));
                test_for(armv8::Aes128Enc::new(&key_128));
                test_for(armv8::Aes128Dec::new(&key_128));
                test_for(armv8::Aes192::new(&key_192));
                test_for(armv8::Aes192Enc::new(&key_192));
                test_for(armv8::Aes192Dec::new(&key_192));
                test_for(armv8::Aes256::new(&key_256));
                test_for(armv8::Aes256Enc::new(&key_256));
                test_for(armv8::Aes256Dec::new(&key_256));
            }
        }
    }
}
