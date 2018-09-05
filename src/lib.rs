// -*- mode: rust; -*-
//
// This file is part of subtle, part of the dalek cryptography project.
// Copyright (c) 2016-2018 isis lovecruft, Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![no_std]
#![cfg_attr(feature = "nightly", feature(asm))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]

//! Note that docs will only build on nightly Rust until
//! [RFC 1990 stabilizes](https://github.com/rust-lang/rust/issues/44732).

#[cfg(feature = "std")]
extern crate std;

use core::ops::{BitAnd, BitOr, BitXor, Not};

#[cfg(feature = "generic-impls")]
use core::ops::Neg;

/// The `Choice` struct represents a choice for use in conditional
/// assignment.
///
/// It is a wrapper around a `u8`, which should have the value either
/// `1` (true) or `0` (false).
///
/// With the `nightly` feature enabled, the conversion from `u8` to
/// `Choice` passes the value through an optimization barrier, as a
/// best-effort attempt to prevent the compiler from inferring that the
/// `Choice` value is a boolean.  This strategy is based on Tim
/// Maclean's [work on `rust-timing-shield`][rust-timing-shield],
/// which attempts to provide a more comprehensive approach for
/// preventing software side-channels in Rust code.
///
/// The `Choice` struct implements operators for AND, OR, XOR, and
/// NOT, to allow combining `Choice` values.
/// These operations do not short-circuit.
///
/// [rust-timing-shield]: https://www.chosenplaintext.ca/open-source/rust-timing-shield/security
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Unwrap the `Choice` wrapper to reveal the underlying `u8`.
    ///
    /// # Note
    ///
    /// This function only exists as an escape hatch for the rare case
    /// where it's not possible to use one of the `subtle`-provided
    /// trait impls.
    #[inline]
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }

    /// Unwrap the `Choice wrapper into a `bool`, depending on whether
    /// the underlying `u8` was a `0` or a `1`.
    ///
    /// # Note
    ///
    /// This function exists to avoid having higher-level cryptographic protocol
    /// implementations duplicating this pattern.  Users should be advised that
    /// it's safest to keep the value as a `Choice` for as long as possible and
    /// use the arithmetic methods provided on that `Choice`, rather than
    /// branching on `bool`s.
    #[inline]
    pub fn unwrap_bool(&self) -> bool {
        debug_assert!(self.0 == 0u8 || self.0 == 1u8);

        match self.0 {
            0 => return false,
            1 => return true,
            _ => unsafe { ::core::hint::unreachable_unchecked() },
        }
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        (self.0 & rhs.0).into()
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        (self.0 | rhs.0).into()
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        (self.0 ^ rhs.0).into()
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        (1u8 & (!self.0)).into()
    }
}

/// This function is a best-effort attempt to prevent the compiler
/// from knowing anything about the value of the returned `u8`, other
/// than its type.
///
/// Uses inline asm when available, otherwise it's a no-op.
#[cfg(all(
    feature = "nightly",
    not(any(target_arch = "asmjs", target_arch = "wasm32"))
))]
fn black_box(input: u8) -> u8 {
    debug_assert!(input == 0u8 || input == 1u8);

    // Pretend to access a register containing the input.  We "volatile" here
    // because some optimisers treat assembly templates without output operands
    // as "volatile" while others do not.
    unsafe { asm!("" :: "r"(&input) :: "volatile") }

    input
}
#[cfg(any(
    target_arch = "asmjs",
    target_arch = "wasm32",
    not(feature = "nightly")
))]
#[inline(never)]
fn black_box(input: u8) -> u8 {
    debug_assert!(input == 0u8 || input == 1u8);
    // We don't have access to inline assembly or test::black_box or ...
    //
    // Bailing out, hopefully the compiler doesn't use the fact that `input` is 0 or 1.
    input
}

impl From<u8> for Choice {
    #[inline]
    fn from(input: u8) -> Choice {
        // Our goal is to prevent the compiler from inferring that the value held inside the
        // resulting `Choice` struct is really an `i1` instead of an `i8`.
        Choice(black_box(input))
    }
}

/// An `Eq`-like trait that produces a `Choice` instead of a `bool`.
///
/// # Example
///
/// ```
/// use subtle::ConstantTimeEq;
/// let x: u8 = 5;
/// let y: u8 = 13;
///
/// assert_eq!(x.ct_eq(&y).unwrap_u8(), 0);
/// assert_eq!(x.ct_eq(&x).unwrap_u8(), 1);
/// ```
pub trait ConstantTimeEq {
    /// Determine if two items are equal.
    ///
    /// The `ct_eq` function should execute in constant time.
    ///
    /// # Returns
    ///
    /// * `Choice(1u8)` if `self == other`;
    /// * `Choice(0u8)` if `self != other`.
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice;
}

impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    /// Check whether two slices of `ConstantTimeEq` types are equal.
    ///
    /// # Note
    ///
    /// This function short-circuits if the lengths of the input slices
    /// are different.  Otherwise, it should execute in time independent
    /// of the slice contents.
    ///
    /// Since arrays coerce to slices, this function works with fixed-size arrays:
    ///
    /// ```
    /// # use subtle::ConstantTimeEq;
    /// #
    /// let a: [u8; 8] = [0,1,2,3,4,5,6,7];
    /// let b: [u8; 8] = [0,1,2,3,0,1,2,3];
    ///
    /// let a_eq_a = a.ct_eq(&a);
    /// let a_eq_b = a.ct_eq(&b);
    ///
    /// assert_eq!(a_eq_a.unwrap_u8(), 1);
    /// assert_eq!(a_eq_b.unwrap_u8(), 0);
    /// ```
    #[inline]
    fn ct_eq(&self, _rhs: &[T]) -> Choice {
        let len = self.len();

        // Short-circuit on the *lengths* of the slices, not their
        // contents.
        if len != _rhs.len() {
            return Choice::from(0);
        }

        // This loop shouldn't be shortcircuitable, since the compiler
        // shouldn't be able to reason about the value of the `u8`
        // unwrapped from the `ct_eq` result.
        let mut x = 1u8;
        for (ai, bi) in self.iter().zip(_rhs.iter()) {
            x &= ai.ct_eq(bi).unwrap_u8();
        }

        x.into()
    }
}

/// Given the bit-width `$bit_width` and the corresponding primitive
/// unsigned and signed types `$t_u` and `$t_i` respectively, generate
/// an `ConstantTimeEq` implementation.
macro_rules! generate_integer_equal {
    ($t_u:ty, $t_i:ty, $bit_width:expr) => {
        impl ConstantTimeEq for $t_u {
            #[inline]
            fn ct_eq(&self, other: &$t_u) -> Choice {
                // First construct x such that self == other iff all bits of x are 1
                let mut x: $t_u = !(self ^ other);

                // Now compute the and of all bits of x.
                //
                // e.g. for a u8, do:
                //
                //    x &= x >> 4;
                //    x &= x >> 2;
                //    x &= x >> 1;
                //
                let mut shift: usize = $bit_width / 2;
                while shift >= 1 {
                    x &= x >> shift;
                    shift /= 2;
                }

                (x as u8).into()
            }
        }
        impl ConstantTimeEq for $t_i {
            #[inline]
            fn ct_eq(&self, other: &$t_i) -> Choice {
                // Bitcast to unsigned and call that implementation.
                (*self as $t_u).ct_eq(&(*other as $t_u))
            }
        }
    };
}

generate_integer_equal!(u8, i8, 8);
generate_integer_equal!(u16, i16, 16);
generate_integer_equal!(u32, i32, 32);
generate_integer_equal!(u64, i64, 64);
generate_integer_equal!(u128, i128, 128);

/// Select one of two inputs according to a `Choice` in constant time.
///
/// # Examples
///
/// ```
/// # use subtle;
/// use subtle::ConditionallySelectable;
/// use subtle::Choice;
/// let a: i32 = 5;
/// let b: i32 = 13;
///
/// assert_eq!(i32::conditional_select(&a, &b, Choice::from(0)), a);
/// assert_eq!(i32::conditional_select(&a, &b, Choice::from(1)), b);
/// ```
pub trait ConditionallySelectable {
    /// Select `a` or `b` according to `choice`.
    ///
    /// # Returns
    ///
    /// * `a` if `choice == Choice(0)`;
    /// * `b` if `choice == Choice(1)`.
    ///
    /// This function should execute in constant time.
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;
}

macro_rules! to_signed_int {
    (u8) => {
        i8
    };
    (u16) => {
        i16
    };
    (u32) => {
        i32
    };
    (u64) => {
        i64
    };
    (u128) => {
        i128
    };
    (i8) => {
        i8
    };
    (i16) => {
        i16
    };
    (i32) => {
        i32
    };
    (i64) => {
        i64
    };
    (i128) => {
        i128
    };
}

macro_rules! generate_integer_conditional_select {
    ($($t:tt)*) => ($(
        impl ConditionallySelectable for $t {
            #[inline]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                // if choice = 0, mask = (-0) = 0000...0000
                // if choice = 1, mask = (-1) = 1111...1111
                let mask = -(choice.unwrap_u8() as to_signed_int!($t)) as $t;
                a ^ ((mask) & (a ^ b))
            }
         }
    )*)
}

generate_integer_conditional_select!(  u8   i8);
generate_integer_conditional_select!( u16  i16);
generate_integer_conditional_select!( u32  i32);
generate_integer_conditional_select!( u64  i64);
generate_integer_conditional_select!(u128 i128);

/// A type which can be conditionally negated in constant time.
///
/// # Note
///
/// A generic implementation of `ConditionallyNegatable` is provided for types
/// which are `ConditionallyNegatable` + `Neg`, but this generic implementation
/// is feature-gated on the `generic-impls` feature in order to allow users to
/// make custom implementations without clashing with the orphan rules.
pub trait ConditionallyNegatable {
    /// Negate `self` if `choice == Choice(1)`; otherwise, leave it
    /// unchanged.
    ///
    /// This function should execute in constant time.
    #[inline]
    fn conditional_negate(&mut self, choice: Choice);
}

#[cfg(feature = "generic-impls")]
impl<T> ConditionallyNegatable for T
where
    T: ConditionallyAssignable,
    for<'a> &'a T: Neg<Output = T>,
{
    #[inline]
    fn conditional_negate(&mut self, choice: Choice) {
        // Need to cast to eliminate mutability
        let self_neg: T = -(self as &T);
        self.conditional_assign(&self_neg, choice);
    }
}

/// A type which can be conditionally assigned in constant time.
pub trait ConditionallyAssignable {
    /// Conditionally assign `other` to `self`, according to `choice`.
    ///
    /// This function should execute in constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate subtle;
    /// use subtle::ConditionallyAssignable;
    /// #
    /// # #[cfg(features = "generic-impls")]
    /// # fn do_test() {
    /// let mut x: u8 = 13;
    /// let y:     u8 = 42;
    ///
    /// x.conditional_assign(&y, 0.into());
    /// assert_eq!(x, 13);
    /// x.conditional_assign(&y, 1.into());
    /// assert_eq!(x, 42);
    /// # }
    /// # #[cfg(not(features = "generic-impls"))]
    /// # fn main () { }
    /// ```
    ///
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice);
}

#[cfg(feature = "generic-impls")]
impl<T> ConditionallyAssignable for T
where
    T: ConditionallySelectable,
{
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = T::conditional_select(self, other, choice);
    }
}

/// A type which is conditionally swappable in constant time.
pub trait ConditionallySwappable {
    /// Conditionally swap `self` and `other` if `choice == 1`; otherwise,
    /// reassign both unto themselves.
    ///
    /// # Note
    ///
    /// This trait is generically implemented for any type which implements
    /// `ConditionallyAssignable` + `Copy`, but is feature-gated on the
    /// "generic-impls" feature, in order to allow more fast/efficient
    /// implementations without clashing with the orphan rules.
    #[inline]
    fn conditional_swap(&mut self, other: &mut Self, choice: Choice);
}

#[cfg(feature = "generic-impls")]
impl<T> ConditionallySwappable for T
where
    T: ConditionallyAssignable + Copy,
{
    #[inline]
    fn conditional_swap(&mut self, other: &mut T, choice: Choice) {
        let temp: T = *self;
        self.conditional_assign(&other, choice);
        other.conditional_assign(&temp, choice);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn slices_equal_different_lengths() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        assert_eq!((&a).ct_eq(&b).unwrap_u8(), 1);
    }

    #[test]
    fn slices_equal() {
        let a: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: [u8; 8] = [1, 2, 3, 4, 4, 3, 2, 1];

        let a_eq_a = (&a).ct_eq(&a);
        let a_eq_b = (&a).ct_eq(&b);

        assert_eq!(a_eq_a.unwrap_u8(), 1);
        assert_eq!(a_eq_b.unwrap_u8(), 0);

        let c: [u8; 16] = [0u8; 16];

        let a_eq_c = (&a).ct_eq(&c);
        assert_eq!(a_eq_c.unwrap_u8(), 0);
    }

    #[test]
    #[cfg(feature = "generic-impls")]
    fn conditional_assign_i32() {
        let mut a: i32 = 5;
        let b: i32 = 13;

        a.conditional_assign(&b, 0.into());
        assert_eq!(a, 5);
        a.conditional_assign(&b, 1.into());
        assert_eq!(a, 13);
    }

    #[test]
    #[cfg(feature = "generic-impls")]
    fn conditional_assign_i64() {
        let mut c: i64 = 2343249123;
        let d: i64 = 8723884895;

        c.conditional_assign(&d, 0.into());
        assert_eq!(c, 2343249123);
        c.conditional_assign(&d, 1.into());
        assert_eq!(c, 8723884895);
    }

    macro_rules! generate_integer_conditional_select_tests {
        ($($t:ty)*) => ($(
            let x: $t = 0;  // all 0 bits
            let y: $t = !0; // all 1 bits

            assert_eq!(<$t>::conditional_select(&x, &y, 0.into()), 0);
            assert_eq!(<$t>::conditional_select(&x, &y, 1.into()), y);
        )*)
    }

    #[test]
    fn integer_conditional_select() {
        generate_integer_conditional_select_tests!(u8 u16 u32 u64 u128);
        generate_integer_conditional_select_tests!(i8 i16 i32 i64 i128);
    }

    #[test]
    fn custom_conditional_select_i16() {
        let x: i16 = 257;
        let y: i16 = 514;

        assert_eq!(i16::conditional_select(&x, &y, 0.into()), 257);
        assert_eq!(i16::conditional_select(&x, &y, 1.into()), 514);
    }

    macro_rules! generate_integer_equal_tests {
        ($($t:ty),*) => ($(
            let y: $t = 0;  // all 0 bits
            let z: $t = !0; // all 1 bits

            let x = z;

            assert_eq!(x.ct_eq(&y).unwrap_u8(), 0);
            assert_eq!(x.ct_eq(&z).unwrap_u8(), 1);
        )*)
    }

    #[test]
    fn integer_equal() {
        generate_integer_equal_tests!(u8, u16, u32, u64, u128);
        generate_integer_equal_tests!(i8, i16, i32, i64, i128);
    }

    #[test]
    fn unwrap_bool() {
        let choice_true: Choice = Choice::from(1);

        assert!(choice_true.unwrap_bool());

        let choice_false: Choice = Choice::from(0);

        assert!(!choice_false.unwrap_bool());
    }
}
