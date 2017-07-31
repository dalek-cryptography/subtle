// -*- mode: rust; -*-
//
// To the extent possible under law, the authors have waived all copyright and
// related or neighboring rights to subtle, using the Creative Commons "CC0"
// public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/.0/> for full details.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Pure-Rust traits and utilities for constant-time cryptographic implementations.

#![cfg_attr(not(feature = "std"), no_std)]

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(fat_ptr_transmutes)]

#![cfg_attr(feature = "nightly", feature(i128_type))]


#[cfg(feature = "std")]
extern crate core;

#[cfg(feature = "std")]
extern crate num_traits;


#[cfg(feature = "std")]
use core::ops::BitAnd;
#[cfg(feature = "std")]
use core::ops::BitOr;
#[cfg(feature = "std")]
use core::ops::Not;
#[cfg(feature = "std")]
use core::ops::Sub;

use core::ops::Neg;

#[cfg(feature = "std")]
use num_traits::One;
#[cfg(feature = "std")]
use num_traits::Signed;

/// A `Mask` represents a choice which is not a boolean.
pub type Mask = u8;

/// Trait for items which can be conditionally assigned in constant time.
pub trait ConditionallyAssignable {
    /// Conditionally assign `other` to `self` in constant time.
    ///
    /// If `choice == 1`, assign `other` to `self`.  Otherwise, leave `self`
    /// unchanged.
    ///
    /// # Examples
    ///
    /// Several implementations of constant-time conditional assignment are
    /// provided within `subtle`.
    ///
    /// ## Integer Types
    ///
    /// This crate includes implementations of `ConditionallyAssignable` for the
    /// following integer types:
    ///
    ///  * `u8`,
    ///  * `u16`,
    ///  * `u32`,
    ///  * `u64`,
    ///  * `i8`,
    ///  * `i16`,
    ///  * `i32`, and
    ///  * `i64`.
    ///
    /// ```
    /// # use subtle;
    /// # use subtle::ConditionallyAssignable;
    /// #
    /// let mut x: u8 = 13;
    /// let y:     u8 = 42;
    ///
    /// x.conditional_assign(&y, 0);
    /// assert_eq!(x, 13);
    /// x.conditional_assign(&y, 1);
    /// assert_eq!(x, 42);
    /// ```
    ///
    /// If you need conditional assignment for `u128` or`i128` on Rust nightly,
    /// these definitions are provided if you compile `subtle` with the
    /// `nightly` feature:
    ///
    /// ```ignore
    /// [dependencies.subtle]
    /// features = ["nightly"]
    /// ```
    ///
    /// # Integer Arrays
    ///
    /// Additionally, `subtle` provides implementations of conditional
    /// assignment for fixed-size arrays (between [1, 32] elements in length,
    /// inclusive) of integers (for the integer types listed above):
    ///
    /// ```
    /// # use subtle;
    /// # use subtle::ConditionallyAssignable;
    /// #
    /// let mut x: [u32; 17] = [13; 17];
    /// let y:     [u32; 17] = [42; 17];
    ///
    /// x.conditional_assign(&y, 0);
    /// assert_eq!(x, [13; 17]);
    /// x.conditional_assign(&y, 1);
    /// assert_eq!(x, [42; 17]);
    /// ```
    ///
    /// If you need conditional assignment for `u128` or`i128` on Rust nightly,
    /// these definitions are provided if you compile `subtle` with the
    /// `nightly` feature (as above).
    fn conditional_assign(&mut self, other: &Self, choice: Mask);
}

macro_rules! generate_integer_conditional_assign {
    ($($t:ty)*) => ($(
        impl ConditionallyAssignable for $t {
            #[inline(always)]
            fn conditional_assign(&mut self, other: &$t, choice: Mask) {
                // if choice = 0u8, mask = (-0i8) as u8 = 00000000
                // if choice = 1u8, mask = (-1i8) as u8 = 11111111
                let mask = -(choice as i8) as u8;
                *self = *self ^ ((mask as $t) & (*self ^ *other));
            }
         }
    )*)
}

generate_integer_conditional_assign!(u8 u16 u32 u64);
generate_integer_conditional_assign!(i8 i16 i32 i64);

#[cfg(feature = "nightly")]
generate_integer_conditional_assign!(u128 i128);

/// Generate a constant time `conditional_assign()` method for an array of type
/// `[$t; $n]`, where `$t` is a type which implements `core::ops::BitAnd` and
/// `core::ops::BitXor` and `$n` is an expression which evaluates to an integer.
#[macro_export]
macro_rules! generate_array_conditional_assign {
    ($([$t:ty; $n:expr]),*) => ($(
        impl ConditionallyAssignable for [$t; $n] {
            #[inline(always)]
            fn conditional_assign(&mut self, other: &[$t; $n], choice: Mask) {
                // if choice = 0u8, mask = (-0i8) as u8 = 00000000
                // if choice = 1u8, mask = (-1i8) as u8 = 11111111
                let mask = -(choice as i8) as u8;
                for i in 0 .. $n {
                    self[i] = self[i] ^ ((mask as $t) & (self[i] ^ other[i]));
                }
            }
         }
    )*)
}

generate_array_conditional_assign!([u8;  1], [u8;  2], [u8;  3], [u8;  4]);
generate_array_conditional_assign!([u8;  5], [u8;  6], [u8;  7], [u8;  8]);
generate_array_conditional_assign!([u8;  9], [u8; 10], [u8; 11], [u8; 12]);
generate_array_conditional_assign!([u8; 13], [u8; 14], [u8; 15], [u8; 16]);
generate_array_conditional_assign!([u8; 17], [u8; 18], [u8; 19], [u8; 20]);
generate_array_conditional_assign!([u8; 21], [u8; 22], [u8; 23], [u8; 24]);
generate_array_conditional_assign!([u8; 25], [u8; 26], [u8; 27], [u8; 28]);
generate_array_conditional_assign!([u8; 29], [u8; 30], [u8; 31], [u8; 32]);

generate_array_conditional_assign!([u16;  1], [u16;  2], [u16;  3], [u16;  4]);
generate_array_conditional_assign!([u16;  5], [u16;  6], [u16;  7], [u16;  8]);
generate_array_conditional_assign!([u16;  9], [u16; 10], [u16; 11], [u16; 12]);
generate_array_conditional_assign!([u16; 13], [u16; 14], [u16; 15], [u16; 16]);
generate_array_conditional_assign!([u16; 17], [u16; 18], [u16; 19], [u16; 20]);
generate_array_conditional_assign!([u16; 21], [u16; 22], [u16; 23], [u16; 24]);
generate_array_conditional_assign!([u16; 25], [u16; 26], [u16; 27], [u16; 28]);
generate_array_conditional_assign!([u16; 29], [u16; 30], [u16; 31], [u16; 32]);

generate_array_conditional_assign!([u32;  1], [u32;  2], [u32;  3], [u32;  4]);
generate_array_conditional_assign!([u32;  5], [u32;  6], [u32;  7], [u32;  8]);
generate_array_conditional_assign!([u32;  9], [u32; 10], [u32; 11], [u32; 12]);
generate_array_conditional_assign!([u32; 13], [u32; 14], [u32; 15], [u32; 16]);
generate_array_conditional_assign!([u32; 17], [u32; 18], [u32; 19], [u32; 20]);
generate_array_conditional_assign!([u32; 21], [u32; 22], [u32; 23], [u32; 24]);
generate_array_conditional_assign!([u32; 25], [u32; 26], [u32; 27], [u32; 28]);
generate_array_conditional_assign!([u32; 29], [u32; 30], [u32; 31], [u32; 32]);

generate_array_conditional_assign!([u64;  1], [u64;  2], [u64;  3], [u64;  4]);
generate_array_conditional_assign!([u64;  5], [u64;  6], [u64;  7], [u64;  8]);
generate_array_conditional_assign!([u64;  9], [u64; 10], [u64; 11], [u64; 12]);
generate_array_conditional_assign!([u64; 13], [u64; 14], [u64; 15], [u64; 16]);
generate_array_conditional_assign!([u64; 17], [u64; 18], [u64; 19], [u64; 20]);
generate_array_conditional_assign!([u64; 21], [u64; 22], [u64; 23], [u64; 24]);
generate_array_conditional_assign!([u64; 25], [u64; 26], [u64; 27], [u64; 28]);
generate_array_conditional_assign!([u64; 29], [u64; 30], [u64; 31], [u64; 32]);

generate_array_conditional_assign!([i8;  1], [i8;  2], [i8;  3], [i8;  4]);
generate_array_conditional_assign!([i8;  5], [i8;  6], [i8;  7], [i8;  8]);
generate_array_conditional_assign!([i8;  9], [i8; 10], [i8; 11], [i8; 12]);
generate_array_conditional_assign!([i8; 13], [i8; 14], [i8; 15], [i8; 16]);
generate_array_conditional_assign!([i8; 17], [i8; 18], [i8; 19], [i8; 20]);
generate_array_conditional_assign!([i8; 21], [i8; 22], [i8; 23], [i8; 24]);
generate_array_conditional_assign!([i8; 25], [i8; 26], [i8; 27], [i8; 28]);
generate_array_conditional_assign!([i8; 29], [i8; 30], [i8; 31], [i8; 32]);

generate_array_conditional_assign!([i16;  1], [i16;  2], [i16;  3], [i16;  4]);
generate_array_conditional_assign!([i16;  5], [i16;  6], [i16;  7], [i16;  8]);
generate_array_conditional_assign!([i16;  9], [i16; 10], [i16; 11], [i16; 12]);
generate_array_conditional_assign!([i16; 13], [i16; 14], [i16; 15], [i16; 16]);
generate_array_conditional_assign!([i16; 17], [i16; 18], [i16; 19], [i16; 20]);
generate_array_conditional_assign!([i16; 21], [i16; 22], [i16; 23], [i16; 24]);
generate_array_conditional_assign!([i16; 25], [i16; 26], [i16; 27], [i16; 28]);
generate_array_conditional_assign!([i16; 29], [i16; 30], [i16; 31], [i16; 32]);

generate_array_conditional_assign!([i32;  1], [i32;  2], [i32;  3], [i32;  4]);
generate_array_conditional_assign!([i32;  5], [i32;  6], [i32;  7], [i32;  8]);
generate_array_conditional_assign!([i32;  9], [i32; 10], [i32; 11], [i32; 12]);
generate_array_conditional_assign!([i32; 13], [i32; 14], [i32; 15], [i32; 16]);
generate_array_conditional_assign!([i32; 17], [i32; 18], [i32; 19], [i32; 20]);
generate_array_conditional_assign!([i32; 21], [i32; 22], [i32; 23], [i32; 24]);
generate_array_conditional_assign!([i32; 25], [i32; 26], [i32; 27], [i32; 28]);
generate_array_conditional_assign!([i32; 29], [i32; 30], [i32; 31], [i32; 32]);

generate_array_conditional_assign!([i64;  1], [i64;  2], [i64;  3], [i64;  4]);
generate_array_conditional_assign!([i64;  5], [i64;  6], [i64;  7], [i64;  8]);
generate_array_conditional_assign!([i64;  9], [i64; 10], [i64; 11], [i64; 12]);
generate_array_conditional_assign!([i64; 13], [i64; 14], [i64; 15], [i64; 16]);
generate_array_conditional_assign!([i64; 17], [i64; 18], [i64; 19], [i64; 20]);
generate_array_conditional_assign!([i64; 21], [i64; 22], [i64; 23], [i64; 24]);
generate_array_conditional_assign!([i64; 25], [i64; 26], [i64; 27], [i64; 28]);
generate_array_conditional_assign!([i64; 29], [i64; 30], [i64; 31], [i64; 32]);

#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128;  1], [u128;  2], [u128;  3], [u128;  4]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128;  5], [u128;  6], [u128;  7], [u128;  8]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128;  9], [u128; 10], [u128; 11], [u128; 12]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128; 13], [u128; 14], [u128; 15], [u128; 16]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128; 17], [u128; 18], [u128; 19], [u128; 20]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128; 21], [u128; 22], [u128; 23], [u128; 24]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128; 25], [u128; 26], [u128; 27], [u128; 28]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([u128; 29], [u128; 30], [u128; 31], [u128; 32]);

#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128;  1], [i128;  2], [i128;  3], [i128;  4]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128;  5], [i128;  6], [i128;  7], [i128;  8]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128;  9], [i128; 10], [i128; 11], [i128; 12]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128; 13], [i128; 14], [i128; 15], [i128; 16]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128; 17], [i128; 18], [i128; 19], [i128; 20]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128; 21], [i128; 22], [i128; 23], [i128; 24]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128; 25], [i128; 26], [i128; 27], [i128; 28]);
#[cfg(feature = "nightly")]
generate_array_conditional_assign!([i128; 29], [i128; 30], [i128; 31], [i128; 32]);


/// Trait for items whose equality to another item may be tested in constant time.
pub trait CTEq {
    /// Determine if two items are equal in constant time.
    ///
    /// # Returns
    ///
    /// `1u8` if the two items are equal, and `0u8` otherwise.
    fn ct_eq(&self, other: &Self) -> Mask;
}

/// Trait for items which can be conditionally negated in constant time.
///
/// Note: it is not necessary to implement this trait, as a generic
/// implementation is provided.
pub trait CTNegatable {
    /// Conditionally negate an element if `choice == 1u8`.
    fn conditional_negate(&mut self, choice: Mask);
}

impl<T> CTNegatable for T
    where T: ConditionallyAssignable, for<'a> &'a T: Neg<Output=T>
{
    fn conditional_negate(&mut self, choice: Mask) {
        // Need to cast to eliminate mutability
        let self_neg: T = -(self as &T);
        self.conditional_assign(&self_neg, choice);
    }
}

/// Select `a` if `choice == 1` or select `b` if `choice == 0`, in constant time.
///
/// # Inputs
///
/// * `a`, `b`, and `choice` must be types for which bitwise-AND, and
///   bitwise-OR, bitwise-complement, subtraction, multiplicative identity,
///   copying, partial equality, and partial order comparison are defined.
/// * `choice`: If `choice` is equal to the multiplicative identity of the type
///   (i.e. `1u8` for `u8`, etc.), then `a` is returned.  If `choice` is equal
///   to the additive identity (i.e. `0u8` for `u8`, etc.) then `b` is returned.
///
/// # Warning
///
/// The behaviour of this function is undefined if `choice` is something other
/// than a multiplicative identity or additive identity (i.e. `1u8` or `0u8`).
///
/// If you somehow manage to design a type which is not a signed integer, and
/// yet implements all the requisite trait bounds for this generic, it's your
/// problem if something breaks.
///
/// # Examples
///
/// This function should work for signed integer types:
///
/// ```
/// # extern crate subtle;
/// # use subtle::conditional_select;
/// # fn main() {
/// let a: i32 = 5;
/// let b: i32 = 13;
///
/// assert!(conditional_select(a, b, 0) == 13);
/// assert!(conditional_select(a, b, 1) == 5);
///
/// let c: i64 = 2343249123;
/// let d: i64 = 8723884895;
///
/// assert!(conditional_select(c, d, 0) == d);
/// assert!(conditional_select(c, d, 1) == c);
/// # }
/// ```
///
/// It does not work with `i128`s, however, because the `num` crate doesn't
/// implement `num::traits::Signed` for `i128`.
///
/// # TODO
///
/// Once `#[feature(specialization)]` is finished, we should rewrite this.  Or
/// find some other way to only implement it for types which we know work
/// correctly.
#[inline(always)]
#[cfg(feature = "std")]
pub fn conditional_select<T>(a: T, b: T, choice: T) -> T
    where T: PartialEq + PartialOrd + Copy +
             One + Signed + Sub<T, Output = T> + Not<Output = T> +
             BitAnd<T, Output = T> + BitOr<T, Output = T> {
    (!(choice - T::one()) & a) | ((choice - T::one()) & b)
}

/// Check equality of two bytes in constant time.
///
/// # Return
///
/// Returns `1u8` if `a == b` and `0u8` otherwise.
///
/// # Examples
///
/// ```
/// # extern crate subtle;
/// # use subtle::bytes_equal;
/// # fn main() {
/// let a: u8 = 0xDE;
/// let b: u8 = 0xAD;
///
/// assert_eq!(bytes_equal(a, b), 0);
/// assert_eq!(bytes_equal(a, a), 1);
/// # }
/// ```
#[inline(always)]
pub fn bytes_equal(a: u8, b: u8) -> Mask {
    let mut x: u8;

    x  = !(a ^ b);
    x &= x >> 4;
    x &= x >> 2;
    x &= x >> 1;
    x
}

/// Test if a byte is non-zero in constant time.
///
/// ```
/// # extern crate subtle;
/// # use subtle::byte_is_nonzero;
/// # fn main() {
/// let mut x: u8;
/// x = 0;
/// assert!(byte_is_nonzero(x) == 0);
/// x = 3;
/// assert!(byte_is_nonzero(x) == 1);
/// # }
/// ```
///
/// # Return
///
/// * If `b != 0`, returns `1u8`.
/// * If `b == 0`, returns `0u8`.
#[inline(always)]
pub fn byte_is_nonzero(b: u8) -> Mask {
    let mut x = b;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    (x & 1)
}

/// Check equality of two slices, `a` and `b`, in constant time.
///
/// There is an `assert!` that the two slices are of equal length.  For
/// example, the following code is a programming error and will panic:
///
/// ```rust,ignore
/// let a: [u8; 3] = [0, 0, 0];
/// let b: [u8; 4] = [0, 0, 0, 0];
///
/// assert!(slices_equal(&a, &b) == 1);
/// ```
///
/// However, if the slices are equal length, but their contents do *not* match,
/// `0u8` will be returned:
///
/// ```
/// # extern crate subtle;
/// # use subtle::slices_equal;
/// # fn main() {
/// let a: [u8; 3] = [0, 1, 2];
/// let b: [u8; 3] = [1, 2, 3];
///
/// assert!(slices_equal(&a, &b) == 0);
/// # }
/// ```
///
/// And finally, if the contents *do* match, `1u8` is returned:
///
/// ```
/// # extern crate subtle;
/// # use subtle::slices_equal;
/// # fn main() {
/// let a: [u8; 3] = [0, 1, 2];
/// let b: [u8; 3] = [0, 1, 2];
///
/// assert!(slices_equal(&a, &b) == 1);
/// # }
/// ```
///
/// This function is commonly used in various cryptographic applications, such
/// as [signature verification](https://github.com/isislovecruft/ed25519-dalek/blob/0.3.2/src/ed25519.rs#L280),
/// among many other applications.
///
/// # Return
///
/// Returns `1u8` if `a == b` and `0u8` otherwise.
#[inline(always)]
pub fn slices_equal(a: &[u8], b: &[u8]) -> Mask {
    assert_eq!(a.len(), b.len());

    let mut x: u8 = 0;

    for i in 0 .. a.len() {
        x |= a[i] ^ b[i];
    }
    bytes_equal(x, 0)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn slices_equal_different_lengths() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        assert!(slices_equal(&a, &b) == 1);
    }

    #[test]
    #[cfg(feature = "std")]
    fn conditional_select_i32() {
        let a: i32 = 5;
        let b: i32 = 13;

        assert_eq!(conditional_select(a, b, 0), 13);
        assert_eq!(conditional_select(a, b, 1), 5);
    }

    #[test]
    #[cfg(feature = "std")]
    fn conditional_select_i64() {
        let c: i64 = 2343249123;
        let d: i64 = 8723884895;

        assert_eq!(conditional_select(c, d, 0), d);
        assert_eq!(conditional_select(c, d, 1), c);
    }

    macro_rules! generate_integer_conditional_assign_tests {
        ($($t:ty)*) => ($(
            let mut x: $t = 13;
            let     y: $t = 42;

            x.conditional_assign(&y, 0);
            assert_eq!(x, 13);
            x.conditional_assign(&y, 1);
            assert_eq!(x, 42);
        )*)
    }

    #[test]
    fn integer_conditional_assign() {
        generate_integer_conditional_assign_tests!(u8 u16 u32 u64);
        generate_integer_conditional_assign_tests!(i8 i16 i32 i64);

        #[cfg(feature = "nightly")]
        generate_integer_conditional_assign_tests!(u128 i128);
    }

    macro_rules! generate_array_conditional_assign_tests {
        ($([$t:ty; $n:expr]),*) => ($(
            let mut x: [$t; $n] = [13; $n];
            let     y: [$t; $n] = [42; $n];

            x.conditional_assign(&y, 0);
            assert_eq!(x, [13; $n]);
            x.conditional_assign(&y, 1);
            assert_eq!(x, [42; $n]);
        )*)
    }

    #[test]
    fn array_conditional_assign() {
        generate_array_conditional_assign_tests!([u8;  1], [u8;  2], [u8;  3], [u8;  4]);
        generate_array_conditional_assign_tests!([u8;  5], [u8;  6], [u8;  7], [u8;  8]);
        generate_array_conditional_assign_tests!([u8;  9], [u8; 10], [u8; 11], [u8; 12]);
        generate_array_conditional_assign_tests!([u8; 13], [u8; 14], [u8; 15], [u8; 16]);
        generate_array_conditional_assign_tests!([u8; 17], [u8; 18], [u8; 19], [u8; 20]);
        generate_array_conditional_assign_tests!([u8; 21], [u8; 22], [u8; 23], [u8; 24]);
        generate_array_conditional_assign_tests!([u8; 25], [u8; 26], [u8; 27], [u8; 28]);
        generate_array_conditional_assign_tests!([u8; 29], [u8; 30], [u8; 31], [u8; 32]);

        generate_array_conditional_assign_tests!([u16;  1], [u16;  2], [u16;  3], [u16;  4]);
        generate_array_conditional_assign_tests!([u16;  5], [u16;  6], [u16;  7], [u16;  8]);
        generate_array_conditional_assign_tests!([u16;  9], [u16; 10], [u16; 11], [u16; 12]);
        generate_array_conditional_assign_tests!([u16; 13], [u16; 14], [u16; 15], [u16; 16]);
        generate_array_conditional_assign_tests!([u16; 17], [u16; 18], [u16; 19], [u16; 20]);
        generate_array_conditional_assign_tests!([u16; 21], [u16; 22], [u16; 23], [u16; 24]);
        generate_array_conditional_assign_tests!([u16; 25], [u16; 26], [u16; 27], [u16; 28]);
        generate_array_conditional_assign_tests!([u16; 29], [u16; 30], [u16; 31], [u16; 32]);

        generate_array_conditional_assign_tests!([u32;  1], [u32;  2], [u32;  3], [u32;  4]);
        generate_array_conditional_assign_tests!([u32;  5], [u32;  6], [u32;  7], [u32;  8]);
        generate_array_conditional_assign_tests!([u32;  9], [u32; 10], [u32; 11], [u32; 12]);
        generate_array_conditional_assign_tests!([u32; 13], [u32; 14], [u32; 15], [u32; 16]);
        generate_array_conditional_assign_tests!([u32; 17], [u32; 18], [u32; 19], [u32; 20]);
        generate_array_conditional_assign_tests!([u32; 21], [u32; 22], [u32; 23], [u32; 24]);
        generate_array_conditional_assign_tests!([u32; 25], [u32; 26], [u32; 27], [u32; 28]);
        generate_array_conditional_assign_tests!([u32; 29], [u32; 30], [u32; 31], [u32; 32]);

        generate_array_conditional_assign_tests!([u64;  1], [u64;  2], [u64;  3], [u64;  4]);
        generate_array_conditional_assign_tests!([u64;  5], [u64;  6], [u64;  7], [u64;  8]);
        generate_array_conditional_assign_tests!([u64;  9], [u64; 10], [u64; 11], [u64; 12]);
        generate_array_conditional_assign_tests!([u64; 13], [u64; 14], [u64; 15], [u64; 16]);
        generate_array_conditional_assign_tests!([u64; 17], [u64; 18], [u64; 19], [u64; 20]);
        generate_array_conditional_assign_tests!([u64; 21], [u64; 22], [u64; 23], [u64; 24]);
        generate_array_conditional_assign_tests!([u64; 25], [u64; 26], [u64; 27], [u64; 28]);
        generate_array_conditional_assign_tests!([u64; 29], [u64; 30], [u64; 31], [u64; 32]);

        generate_array_conditional_assign_tests!([i8;  1], [i8;  2], [i8;  3], [i8;  4]);
        generate_array_conditional_assign_tests!([i8;  5], [i8;  6], [i8;  7], [i8;  8]);
        generate_array_conditional_assign_tests!([i8;  9], [i8; 10], [i8; 11], [i8; 12]);
        generate_array_conditional_assign_tests!([i8; 13], [i8; 14], [i8; 15], [i8; 16]);
        generate_array_conditional_assign_tests!([i8; 17], [i8; 18], [i8; 19], [i8; 20]);
        generate_array_conditional_assign_tests!([i8; 21], [i8; 22], [i8; 23], [i8; 24]);
        generate_array_conditional_assign_tests!([i8; 25], [i8; 26], [i8; 27], [i8; 28]);
        generate_array_conditional_assign_tests!([i8; 29], [i8; 30], [i8; 31], [i8; 32]);

        generate_array_conditional_assign_tests!([i16;  1], [i16;  2], [i16;  3], [i16;  4]);
        generate_array_conditional_assign_tests!([i16;  5], [i16;  6], [i16;  7], [i16;  8]);
        generate_array_conditional_assign_tests!([i16;  9], [i16; 10], [i16; 11], [i16; 12]);
        generate_array_conditional_assign_tests!([i16; 13], [i16; 14], [i16; 15], [i16; 16]);
        generate_array_conditional_assign_tests!([i16; 17], [i16; 18], [i16; 19], [i16; 20]);
        generate_array_conditional_assign_tests!([i16; 21], [i16; 22], [i16; 23], [i16; 24]);
        generate_array_conditional_assign_tests!([i16; 25], [i16; 26], [i16; 27], [i16; 28]);
        generate_array_conditional_assign_tests!([i16; 29], [i16; 30], [i16; 31], [i16; 32]);

        generate_array_conditional_assign_tests!([i32;  1], [i32;  2], [i32;  3], [i32;  4]);
        generate_array_conditional_assign_tests!([i32;  5], [i32;  6], [i32;  7], [i32;  8]);
        generate_array_conditional_assign_tests!([i32;  9], [i32; 10], [i32; 11], [i32; 12]);
        generate_array_conditional_assign_tests!([i32; 13], [i32; 14], [i32; 15], [i32; 16]);
        generate_array_conditional_assign_tests!([i32; 17], [i32; 18], [i32; 19], [i32; 20]);
        generate_array_conditional_assign_tests!([i32; 21], [i32; 22], [i32; 23], [i32; 24]);
        generate_array_conditional_assign_tests!([i32; 25], [i32; 26], [i32; 27], [i32; 28]);
        generate_array_conditional_assign_tests!([i32; 29], [i32; 30], [i32; 31], [i32; 32]);

        generate_array_conditional_assign_tests!([i64;  1], [i64;  2], [i64;  3], [i64;  4]);
        generate_array_conditional_assign_tests!([i64;  5], [i64;  6], [i64;  7], [i64;  8]);
        generate_array_conditional_assign_tests!([i64;  9], [i64; 10], [i64; 11], [i64; 12]);
        generate_array_conditional_assign_tests!([i64; 13], [i64; 14], [i64; 15], [i64; 16]);
        generate_array_conditional_assign_tests!([i64; 17], [i64; 18], [i64; 19], [i64; 20]);
        generate_array_conditional_assign_tests!([i64; 21], [i64; 22], [i64; 23], [i64; 24]);
        generate_array_conditional_assign_tests!([i64; 25], [i64; 26], [i64; 27], [i64; 28]);
        generate_array_conditional_assign_tests!([i64; 29], [i64; 30], [i64; 31], [i64; 32]);

        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128;  1], [u128;  2], [u128;  3], [u128;  4]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128;  5], [u128;  6], [u128;  7], [u128;  8]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128;  9], [u128; 10], [u128; 11], [u128; 12]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128; 13], [u128; 14], [u128; 15], [u128; 16]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128; 17], [u128; 18], [u128; 19], [u128; 20]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128; 21], [u128; 22], [u128; 23], [u128; 24]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128; 25], [u128; 26], [u128; 27], [u128; 28]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([u128; 29], [u128; 30], [u128; 31], [u128; 32]);

        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128;  1], [i128;  2], [i128;  3], [i128;  4]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128;  5], [i128;  6], [i128;  7], [i128;  8]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128;  9], [i128; 10], [i128; 11], [i128; 12]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128; 13], [i128; 14], [i128; 15], [i128; 16]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128; 17], [i128; 18], [i128; 19], [i128; 20]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128; 21], [i128; 22], [i128; 23], [i128; 24]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128; 25], [i128; 26], [i128; 27], [i128; 28]);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_tests!([i128; 29], [i128; 30], [i128; 31], [i128; 32]);
    }
}
