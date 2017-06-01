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


#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(fat_ptr_transmutes)]


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
pub trait CTAssignable {
    /// Conditionally assign `other` to `self` in constant time.
    ///
    /// If `choice == 1u8`, assign `other` to `self`.  Otherwise, leave `self`
    /// unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// # use subtle;
    /// # use subtle::CTAssignable;
    /// #
    /// let mut x: u8 = 13;
    /// let y:     u8 = 42;
    ///
    /// x.conditional_assign(&y, 0);
    /// assert_eq!(x, 13);
    /// x.conditional_assign(&y, 1);
    /// assert_eq!(x, 42);
    /// ```
    fn conditional_assign(&mut self, other: &Self, choice: Mask);
}

macro_rules! generate_integer_conditional_assign {
    ($($t:ty)*) => ($(
        impl CTAssignable for $t {
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
    where T: CTAssignable, for<'a> &'a T: Neg<Output=T>
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

/// Check equality of two arrays, `a` and `b`, in constant time.
///
/// There is an `assert!` that the two arrays are of equal length.  For
/// example, the following code is a programming error and will panic:
///
/// ```rust,ignore
/// let a: [u8; 3] = [0, 0, 0];
/// let b: [u8; 4] = [0, 0, 0, 0];
///
/// assert!(arrays_equal(&a, &b) == 1);
/// ```
///
/// However, if the arrays are equal length, but their contents do *not* match,
/// `0u8` will be returned:
///
/// ```
/// # extern crate subtle;
/// # use subtle::arrays_equal;
/// # fn main() {
/// let a: [u8; 3] = [0, 1, 2];
/// let b: [u8; 3] = [1, 2, 3];
///
/// assert!(arrays_equal(&a, &b) == 0);
/// # }
/// ```
///
/// And finally, if the contents *do* match, `1u8` is returned:
///
/// ```
/// # extern crate subtle;
/// # use subtle::arrays_equal;
/// # fn main() {
/// let a: [u8; 3] = [0, 1, 2];
/// let b: [u8; 3] = [0, 1, 2];
///
/// assert!(arrays_equal(&a, &b) == 1);
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
pub fn arrays_equal(a: &[u8], b: &[u8]) -> Mask {
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
    fn arrays_equal_different_lengths() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        assert!(arrays_equal(&a, &b) == 1);
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
    }
}
