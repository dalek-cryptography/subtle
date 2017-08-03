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
#![cfg_attr(feature = "bench",   feature(test))]

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

/// Trait for items whose equality to another item may be tested in constant time.
pub trait Equal {
    /// Determine if two items are equal in constant time.
    ///
    /// # Returns
    ///
    /// `1u8` if the two items are equal, and `0u8` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # use subtle::Equal;
    /// let x: u8 = 5;
    /// let y: u8 = 13;
    ///
    /// assert!(x.ct_eq(&y) == 0);
    /// assert!(x.ct_eq(&5) == 1);
    fn ct_eq(&self, other: &Self) -> Mask;
}

/// Generate a constant time equality testing method for integer of type $t,
/// where `$t` is an unsigned integer type which implements `core::ops::Not`,
/// `core::ops::Shr`, `core::ops::BitAndAssign`, `core::ops::Xor`, and
/// `core::ops::Div`.
macro_rules! generate_integer_equal {
    ($t:ty, $maxshift:expr) => (
        impl Equal for $t {
            #[inline(always)]
            fn ct_eq(&self, other: &$t) -> Mask {
                let mut x: $t = !(self ^ other);
                let mut shift: $t = $maxshift;

                /// e.g. for a u8, do:
                ///
                ///    x &= x >> 4;
                ///    x &= x >> 2;
                ///    x &= x >> 1;
                ///
                /// This is variable only in the max size of the integer.
                while shift >= 1 {
                    x &= x >> shift;
                    shift /= 2;
                }
                x as Mask
            }
         }
    )
}

generate_integer_equal!( u8,  4u8);
generate_integer_equal!(u16,  8u16);
generate_integer_equal!(u32, 16u32);
generate_integer_equal!(u64, 32u64);

#[cfg(feature = "nightly")]
generate_integer_equal!(u128, 64u128);

// Implement Equal for all slices over T where T implements Equal
impl<T: Equal> Equal for [T] {
    #[inline(always)]
    fn ct_eq(&self, other: &[T]) -> Mask {
        assert_eq!(self.len(), other.len());

        // AND all the elements together
        self.iter().zip(other.iter()).fold(1u8, |x, (a, b)| x & a.ct_eq(b))
    }
}

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

macro_rules! generate_array_conditional_assign_1_through_32 {
    ($($t:ty),*) => ($(
        generate_array_conditional_assign!([$t;  1], [$t;  2], [$t;  3], [$t;  4]);
        generate_array_conditional_assign!([$t;  5], [$t;  6], [$t;  7], [$t;  8]);
        generate_array_conditional_assign!([$t;  9], [$t; 10], [$t; 11], [$t; 12]);
        generate_array_conditional_assign!([$t; 13], [$t; 14], [$t; 15], [$t; 16]);
        generate_array_conditional_assign!([$t; 17], [$t; 18], [$t; 19], [$t; 20]);
        generate_array_conditional_assign!([$t; 21], [$t; 22], [$t; 23], [$t; 24]);
        generate_array_conditional_assign!([$t; 25], [$t; 26], [$t; 27], [$t; 28]);
        generate_array_conditional_assign!([$t; 29], [$t; 30], [$t; 31], [$t; 32]);
    )*)
}

generate_array_conditional_assign_1_through_32!(u8, u16, u32, u64);
#[cfg(feature = "nightly")]
generate_array_conditional_assign_1_through_32!(u128);

/// Generate a constant time equality testing method for an array of type
/// `[$t; $n]`, where `$t` is a type which implements `core::ops::BitXor`
/// and `core::ops::BitOrAssign`, and `$n` is an expression which evaluates to
/// an integer.
macro_rules! generate_arrays_equal {
    ($([$t:ty; $n:expr]),*) => ($(
        impl Equal for [$t; $n] {
            #[inline(always)]
            fn ct_eq(&self, other: &[$t; $n]) -> Mask {
                let mut x: $t = 0;

                for i in 0 .. $n {
                    x |= self[i] ^ other[i];
                }
                x.ct_eq(&0)
            }
         }
    )*)
}

macro_rules! generate_arrays_equal_1_through_32 {
    ($($t:ty),*) => ($(
        generate_arrays_equal!([$t;  1], [$t;  2], [$t;  3], [$t;  4]);
        generate_arrays_equal!([$t;  5], [$t;  6], [$t;  7], [$t;  8]);
        generate_arrays_equal!([$t;  9], [$t; 10], [$t; 11], [$t; 12]);
        generate_arrays_equal!([$t; 13], [$t; 14], [$t; 15], [$t; 16]);
        generate_arrays_equal!([$t; 17], [$t; 18], [$t; 19], [$t; 20]);
        generate_arrays_equal!([$t; 21], [$t; 22], [$t; 23], [$t; 24]);
        generate_arrays_equal!([$t; 25], [$t; 26], [$t; 27], [$t; 28]);
        generate_arrays_equal!([$t; 29], [$t; 30], [$t; 31], [$t; 32]);
    )*)
}

generate_arrays_equal_1_through_32!(u8, u16, u32, u64);
#[cfg(feature = "nightly")]
generate_arrays_equal_1_through_32!(u128);

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
    a.ct_eq(&b)
}

/// Trait for items which can be conditionally negated in constant time.
///
/// Note: it is not necessary to implement this trait, as a generic
/// implementation is provided.
pub trait ConditionallyNegatable {
    /// Conditionally negate an element if `choice == 1u8`.
    fn conditional_negate(&mut self, choice: Mask);
}

impl<T> ConditionallyNegatable for T
    where T: ConditionallyAssignable, for<'a> &'a T: Neg<Output = T>
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

/// Trait for testing if something is non-zero in constant time.
pub trait IsNonZero {
    /// Test if `self` is non-zero in constant time.
    ///
    /// # TODO
    ///
    /// * Implement `IsNonZero` for builtin types.
    /// * Rewrite `byte_is_nonzero()` to use `IsNonZero`.
    ///
    /// # Returns
    ///
    /// * If `self != 0`, returns `1`.
    /// * If `self == 0`, returns `0`.
    fn is_nonzero(&self) -> Mask;
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
///
/// let empty: [u8; 0] = [];
///
/// assert!(slices_equal(&empty, &empty) == 1);
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

    // These useless slices make the optimizer elide the bounds checks.
    // See the comment in clone_from_slice() added on Rust commit 6a7bc47.
    let len = a.len();
    let a = &a[..len];
    let b = &b[..len];

    for i in 0 .. len {
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

    macro_rules! generate_array_conditional_assign_1_through_32_tests {
        ($($t:ty),*) => ($(
            generate_array_conditional_assign_tests!([$t;  1], [$t;  2], [$t;  3], [$t;  4]);
            generate_array_conditional_assign_tests!([$t;  5], [$t;  6], [$t;  7], [$t;  8]);
            generate_array_conditional_assign_tests!([$t;  9], [$t; 10], [$t; 11], [$t; 12]);
            generate_array_conditional_assign_tests!([$t; 13], [$t; 14], [$t; 15], [$t; 16]);
            generate_array_conditional_assign_tests!([$t; 17], [$t; 18], [$t; 19], [$t; 20]);
            generate_array_conditional_assign_tests!([$t; 21], [$t; 22], [$t; 23], [$t; 24]);
            generate_array_conditional_assign_tests!([$t; 25], [$t; 26], [$t; 27], [$t; 28]);
            generate_array_conditional_assign_tests!([$t; 29], [$t; 30], [$t; 31], [$t; 32]);
        )*)
    }

    #[test]
    fn array_conditional_assign() {
        generate_array_conditional_assign_1_through_32_tests!(u8, u16, u32, u64);
        #[cfg(feature = "nightly")]
        generate_array_conditional_assign_1_through_32_tests!(u128);
    }

    macro_rules! generate_integer_equal_tests {
        ($($t:ty),*) => ($(
            let x: $t = 13;
            let y: $t = 42;
            let z: $t = 13;

            assert_eq!(x.ct_eq(&y), 0);
            assert_eq!(x.ct_eq(&z), 1);
        )*)
    }

    #[test]
    fn integer_equal() {
        generate_integer_equal_tests!(u8, u16, u32, u64);
        #[cfg(feature = "nightly")]
        generate_integer_equal_tests!(u128);
    }

    macro_rules! generate_arrays_equal_tests {
        ($([$t:ty; $n:expr]),*) => ($(
            let x: [$t; $n] = [13; $n];
            let y: [$t; $n] = [42; $n];
            let z: [$t; $n] = [13; $n];

            assert_eq!(x.ct_eq(&y), 0);
            assert_eq!(x.ct_eq(&z), 1);
        )*)
    }

    macro_rules! generate_arrays_equal_1_through_32_tests {
        ($($t:ty),*) => ($(
            generate_arrays_equal_tests!([$t;  1], [$t;  2], [$t;  3], [$t;  4]);
            generate_arrays_equal_tests!([$t;  5], [$t;  6], [$t;  7], [$t;  8]);
            generate_arrays_equal_tests!([$t;  9], [$t; 10], [$t; 11], [$t; 12]);
            generate_arrays_equal_tests!([$t; 13], [$t; 14], [$t; 15], [$t; 16]);
            generate_arrays_equal_tests!([$t; 17], [$t; 18], [$t; 19], [$t; 20]);
            generate_arrays_equal_tests!([$t; 21], [$t; 22], [$t; 23], [$t; 24]);
            generate_arrays_equal_tests!([$t; 25], [$t; 26], [$t; 27], [$t; 28]);
            generate_arrays_equal_tests!([$t; 29], [$t; 30], [$t; 31], [$t; 32]);
        )*)
    }

    #[test]
    fn arrays_equal() {
        generate_arrays_equal_1_through_32_tests!(u8, u16, u32, u64);
        #[cfg(feature = "nightly")]
        generate_arrays_equal_1_through_32_tests!(u128);
    }
}

#[cfg(all(test, feature = "bench"))]
mod bench {
    extern crate test;

    use self::test::Bencher;
    use super::*;

    #[bench]
    fn slices_equal_unequal(b: &mut Bencher) {
        let x: [u8; 100_000] = [13; 100_000];
        let y: [u8; 100_000] = [42; 100_000];

        b.iter(| | slices_equal(&x, &y));
    }

    #[bench]
    fn slices_equal_equal(b: &mut Bencher) {
        let x: [u8; 100_000] = [13; 100_000];
        let y: [u8; 100_000] = [13; 100_000];

        b.iter(| | slices_equal(&x, &y));
    }
}
