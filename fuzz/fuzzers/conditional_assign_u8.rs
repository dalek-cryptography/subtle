#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate subtle;
extern crate core;

use subtle::ConditionallySelectable;

fuzz_target!(|data: &[u8]| {
    for y in data.iter() {
        let mut x: u8 = 0;

        x.conditional_assign(y, 0.into());
        assert_eq!(x, 0);

        x.conditional_assign(y, 1.into());
        assert_eq!(x, *y);
    }
});
