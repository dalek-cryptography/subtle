#![no_main]
use libfuzzer_sys::fuzz_target;
use core::intrinsics::transmute;
use subtle::ConditionallySelectable;

fuzz_target!(|data: &[u8]| {
    let chunk_size: usize = 16;

    if data.len() % chunk_size != 0 {
        return;
    }

    for bytes in data.chunks(chunk_size) {
        unsafe {
            let mut x: i128 = 0;
            let y: i128 = transmute::<[u8; 16], i128>([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]);

            x.conditional_assign(&y, 0.into());
            assert_eq!(x, 0);

            x.conditional_assign(&y, 1.into());
            assert_eq!(x, y);
        }
    }
});
