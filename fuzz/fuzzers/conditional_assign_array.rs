#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate subtle;
extern crate core;

use core::convert::TryFrom;

use subtle::ConditionallySelectable;

fuzz_target!(|data: &[u8]| {
    let chunk_size: usize = 16;

    if data.len() % chunk_size != 0 {
        return;
    }

    for bytes in data.chunks(chunk_size) {
        let mut x = [0u8; 16];
        let y = <[u8; 16]>::try_from(bytes).unwrap();

        x.conditional_assign(&y, 0.into());
        assert_eq!(x, [0u8; 16]);

        x.conditional_assign(&y, 1.into());
        assert_eq!(x, y);
    }
});
