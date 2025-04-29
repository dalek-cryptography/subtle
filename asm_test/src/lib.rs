#![no_std]

use subtle::{Choice, ConditionallySelectable};

#[inline(never)]
pub fn select_byte(a: u8, b: u8) -> u8 {
    ConditionallySelectable::conditional_select(&a, &b, Choice::from(1))
}
