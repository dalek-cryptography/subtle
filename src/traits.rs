use crate::Choice;
use core::cmp;
use core::ops::Neg;

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
//
// #[inline] is specified on these function prototypes to signify that they
#[allow(unused_attributes)] // should be in the actual implementation
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
    #[allow(unused_attributes)]
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Determine if two items are NOT equal.
    ///
    /// The `ct_ne` function should execute in constant time.
    ///
    /// # Returns
    ///
    /// * `Choice(0u8)` if `self == other`;
    /// * `Choice(1u8)` if `self != other`.
    #[inline]
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
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
                // x == 0 if and only if self == other
                let x: $t_u = self ^ other;

                // If x == 0, then x and -x are both equal to zero;
                // otherwise, one or both will have its high bit set.
                let y: $t_u = (x | x.wrapping_neg()) >> ($bit_width - 1);

                // Result is the opposite of the high bit (now shifted to low).
                ((y ^ (1 as $t_u)) as u8).into()
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
generate_integer_equal!(usize, isize, ::core::mem::size_of::<usize>() * 8);

/// `Ordering` is `#[repr(i8)]` making it possible to leverage `i8::ct_eq`.
impl ConstantTimeEq for cmp::Ordering {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        (*self as i8).ct_eq(&(*other as i8))
    }
}

/// A type which can be conditionally selected in constant time.
///
/// This trait also provides generic implementations of conditional
/// assignment and conditional swaps.
//
// #[inline] is specified on these function prototypes to signify that they
#[allow(unused_attributes)] // should be in the actual implementation
pub trait ConditionallySelectable: Copy {
    /// Select `a` or `b` according to `choice`.
    ///
    /// # Returns
    ///
    /// * `a` if `choice == Choice(0)`;
    /// * `b` if `choice == Choice(1)`.
    ///
    /// This function should execute in constant time.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConditionallySelectable;
    /// #
    /// # fn main() {
    /// let x: u8 = 13;
    /// let y: u8 = 42;
    ///
    /// let z = u8::conditional_select(&x, &y, 0.into());
    /// assert_eq!(z, x);
    /// let z = u8::conditional_select(&x, &y, 1.into());
    /// assert_eq!(z, y);
    /// # }
    /// ```
    #[inline]
    #[allow(unused_attributes)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Conditionally assign `other` to `self`, according to `choice`.
    ///
    /// This function should execute in constant time.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConditionallySelectable;
    /// #
    /// # fn main() {
    /// let mut x: u8 = 13;
    /// let mut y: u8 = 42;
    ///
    /// x.conditional_assign(&y, 0.into());
    /// assert_eq!(x, 13);
    /// x.conditional_assign(&y, 1.into());
    /// assert_eq!(x, 42);
    /// # }
    /// ```
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }

    /// Conditionally swap `self` and `other` if `choice == 1`; otherwise,
    /// reassign both unto themselves.
    ///
    /// This function should execute in constant time.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConditionallySelectable;
    /// #
    /// # fn main() {
    /// let mut x: u8 = 13;
    /// let mut y: u8 = 42;
    ///
    /// u8::conditional_swap(&mut x, &mut y, 0.into());
    /// assert_eq!(x, 13);
    /// assert_eq!(y, 42);
    /// u8::conditional_swap(&mut x, &mut y, 1.into());
    /// assert_eq!(x, 42);
    /// assert_eq!(y, 13);
    /// # }
    /// ```
    #[inline]
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let t: Self = *a;
        a.conditional_assign(b, choice);
        b.conditional_assign(&t, choice);
    }
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
                a ^ (mask & (a ^ b))
            }

            #[inline]
            fn conditional_assign(&mut self, other: &Self, choice: Choice) {
                // if choice = 0, mask = (-0) = 0000...0000
                // if choice = 1, mask = (-1) = 1111...1111
                let mask = -(choice.unwrap_u8() as to_signed_int!($t)) as $t;
                *self ^= mask & (*self ^ *other);
            }

            #[inline]
            fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
                // if choice = 0, mask = (-0) = 0000...0000
                // if choice = 1, mask = (-1) = 1111...1111
                let mask = -(choice.unwrap_u8() as to_signed_int!($t)) as $t;
                let t = mask & (*a ^ *b);
                *a ^= t;
                *b ^= t;
            }
         }
    )*)
}

generate_integer_conditional_select!(  u8   i8);
generate_integer_conditional_select!( u16  i16);
generate_integer_conditional_select!( u32  i32);
generate_integer_conditional_select!( u64  i64);
generate_integer_conditional_select!(u128 i128);

/// `Ordering` is `#[repr(i8)]` where:
///
/// - `Less` => -1
/// - `Equal` => 0
/// - `Greater` => 1
///
/// Given this, it's possible to operate on orderings as if they're integers,
/// which allows leveraging conditional masking for predication.
impl ConditionallySelectable for cmp::Ordering {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a = *a as i8;
        let b = *b as i8;
        let ret = i8::conditional_select(&a, &b, choice);

        // SAFETY: `Ordering` is `#[repr(i8)]` and `ret` has been assigned to
        // a value which was originally a valid `Ordering` then cast to `i8`
        unsafe { *((&ret as *const _) as *const cmp::Ordering) }
    }
}

impl<T, const N: usize> ConditionallySelectable for [T; N]
where
    T: ConditionallySelectable,
{
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut output = *a;
        output.conditional_assign(b, choice);
        output
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        for (a_i, b_i) in self.iter_mut().zip(other) {
            a_i.conditional_assign(b_i, choice)
        }
    }
}

/// A type which can be conditionally negated in constant time.
///
/// # Note
///
/// A generic implementation of `ConditionallyNegatable` is provided
/// for types `T` which are `ConditionallySelectable` and have `Neg`
/// implemented on `&T`.
//
// #[inline] is specified on these function prototypes to signify that they
#[allow(unused_attributes)] // should be in the actual implementation
pub trait ConditionallyNegatable {
    /// Negate `self` if `choice == Choice(1)`; otherwise, leave it
    /// unchanged.
    ///
    /// This function should execute in constant time.
    #[inline]
    #[allow(unused_attributes)]
    fn conditional_negate(&mut self, choice: Choice);
}

impl<T> ConditionallyNegatable for T
where
    T: ConditionallySelectable,
    for<'a> &'a T: Neg<Output = T>,
{
    #[inline]
    fn conditional_negate(&mut self, choice: Choice) {
        // Need to cast to eliminate mutability
        let self_neg: T = -(self as &T);
        self.conditional_assign(&self_neg, choice);
    }
}

/// A type which can be compared in some manner and be determined to be greater
/// than another of the same type.
pub trait ConstantTimeGreater {
    /// Determine whether `self > other`.
    ///
    /// The bitwise-NOT of the return value of this function should be usable to
    /// determine if `self <= other`.
    ///
    /// This function should execute in constant time.
    ///
    /// # Returns
    ///
    /// A `Choice` with a set bit if `self > other`, and with no set bits
    /// otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConstantTimeGreater;
    ///
    /// let x: u8 = 13;
    /// let y: u8 = 42;
    ///
    /// let x_gt_y = x.ct_gt(&y);
    ///
    /// assert_eq!(x_gt_y.unwrap_u8(), 0);
    ///
    /// let y_gt_x = y.ct_gt(&x);
    ///
    /// assert_eq!(y_gt_x.unwrap_u8(), 1);
    ///
    /// let x_gt_x = x.ct_gt(&x);
    ///
    /// assert_eq!(x_gt_x.unwrap_u8(), 0);
    /// ```
    fn ct_gt(&self, other: &Self) -> Choice;
}

macro_rules! generate_unsigned_integer_greater {
    ($t_u: ty, $bit_width: expr) => {
        impl ConstantTimeGreater for $t_u {
            /// Returns Choice::from(1) iff x > y, and Choice::from(0) iff x <= y.
            ///
            /// # Note
            ///
            /// This algoritm would also work for signed integers if we first
            /// flip the top bit, e.g. `let x: u8 = x ^ 0x80`, etc.
            #[inline]
            fn ct_gt(&self, other: &$t_u) -> Choice {
                let gtb = self & !other; // All the bits in self that are greater than their corresponding bits in other.
                let mut ltb = !self & other; // All the bits in self that are less than their corresponding bits in other.
                let mut pow = 1;

                // Less-than operator is okay here because it's dependent on the bit-width.
                while pow < $bit_width {
                    ltb |= ltb >> pow; // Bit-smear the highest set bit to the right.
                    pow += pow;
                }
                let mut bit = gtb & !ltb; // Select the highest set bit.
                let mut pow = 1;

                while pow < $bit_width {
                    bit |= bit >> pow; // Shift it to the right until we end up with either 0 or 1.
                    pow += pow;
                }
                // XXX We should possibly do the above flattening to 0 or 1 in the
                //     Choice constructor rather than making it a debug error?
                Choice::from((bit & 1) as u8)
            }
        }
    };
}

generate_unsigned_integer_greater!(u8, 8);
generate_unsigned_integer_greater!(u16, 16);
generate_unsigned_integer_greater!(u32, 32);
generate_unsigned_integer_greater!(u64, 64);
generate_unsigned_integer_greater!(u128, 128);

impl ConstantTimeGreater for cmp::Ordering {
    #[inline]
    fn ct_gt(&self, other: &Self) -> Choice {
        // No impl of `ConstantTimeGreater` for `i8`, so use `u8`
        let a = (*self as i8) + 1;
        let b = (*other as i8) + 1;
        (a as u8).ct_gt(&(b as u8))
    }
}

/// A type which can be compared in some manner and be determined to be less
/// than another of the same type.
pub trait ConstantTimeLess: ConstantTimeEq + ConstantTimeGreater {
    /// Determine whether `self < other`.
    ///
    /// The bitwise-NOT of the return value of this function should be usable to
    /// determine if `self >= other`.
    ///
    /// A default implementation is provided and implemented for the unsigned
    /// integer types.
    ///
    /// This function should execute in constant time.
    ///
    /// # Returns
    ///
    /// A `Choice` with a set bit if `self < other`, and with no set bits
    /// otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConstantTimeLess;
    ///
    /// let x: u8 = 13;
    /// let y: u8 = 42;
    ///
    /// let x_lt_y = x.ct_lt(&y);
    ///
    /// assert_eq!(x_lt_y.unwrap_u8(), 1);
    ///
    /// let y_lt_x = y.ct_lt(&x);
    ///
    /// assert_eq!(y_lt_x.unwrap_u8(), 0);
    ///
    /// let x_lt_x = x.ct_lt(&x);
    ///
    /// assert_eq!(x_lt_x.unwrap_u8(), 0);
    /// ```
    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        !self.ct_gt(other) & !self.ct_eq(other)
    }
}

impl ConstantTimeLess for u8 {}
impl ConstantTimeLess for u16 {}
impl ConstantTimeLess for u32 {}
impl ConstantTimeLess for u64 {}
impl ConstantTimeLess for u128 {}

impl ConstantTimeLess for cmp::Ordering {
    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        // No impl of `ConstantTimeLess` for `i8`, so use `u8`
        let a = (*self as i8) + 1;
        let b = (*other as i8) + 1;
        (a as u8).ct_lt(&(b as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
    use core::cmp;
    use rand::{RngCore, TryRngCore, rngs::OsRng};

    #[test]
    #[should_panic]
    fn slices_equal_different_lengths() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    }

    #[test]
    fn slices_equal() {
        let a: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: [u8; 8] = [1, 2, 3, 4, 4, 3, 2, 1];

        let a_eq_a = a.ct_eq(&a);
        let a_eq_b = a.ct_eq(&b);

        assert_eq!(a_eq_a.unwrap_u8(), 1);
        assert_eq!(a_eq_b.unwrap_u8(), 0);

        let c: [u8; 16] = [0u8; 16];

        let a_eq_c = a.ct_eq(&c);
        assert_eq!(a_eq_c.unwrap_u8(), 0);
    }

    #[test]
    fn conditional_assign_i32() {
        let mut a: i32 = 5;
        let b: i32 = 13;

        a.conditional_assign(&b, 0.into());
        assert_eq!(a, 5);
        a.conditional_assign(&b, 1.into());
        assert_eq!(a, 13);
    }

    #[test]
    fn conditional_assign_i64() {
        let mut c: i64 = 2343249123;
        let d: i64 = 8723884895;

        c.conditional_assign(&d, 0.into());
        assert_eq!(c, 2343249123);
        c.conditional_assign(&d, 1.into());
        assert_eq!(c, 8723884895);
    }

    macro_rules! generate_integer_conditional_select_tests {
    ($($t:ty),*) => ($(
        let x: $t = 0;  // all 0 bits
        let y: $t = !0; // all 1 bits

        assert_eq!(<$t>::conditional_select(&x, &y, 0.into()), x);
        assert_eq!(<$t>::conditional_select(&x, &y, 1.into()), y);

        let mut z = x;
        let mut w = y;

        <$t>::conditional_swap(&mut z, &mut w, 0.into());
        assert_eq!(z, x);
        assert_eq!(w, y);
        <$t>::conditional_swap(&mut z, &mut w, 1.into());
        assert_eq!(z, y);
        assert_eq!(w, x);

        z.conditional_assign(&x, 1.into());
        w.conditional_assign(&y, 0.into());
        assert_eq!(z, x);
        assert_eq!(w, x);
    )*)
}

    #[test]
    fn integer_conditional_select() {
        generate_integer_conditional_select_tests!(u8, u16, u32, u64, i128);
        generate_integer_conditional_select_tests!(i8, i16, i32, i64, u128);
    }

    #[test]
    fn custom_conditional_select_i16() {
        let x: i16 = 257;
        let y: i16 = 514;

        assert_eq!(i16::conditional_select(&x, &y, 0.into()), 257);
        assert_eq!(i16::conditional_select(&x, &y, 1.into()), 514);
    }

    #[test]
    fn ordering_conditional_select() {
        assert_eq!(
            cmp::Ordering::conditional_select(
                &cmp::Ordering::Less,
                &cmp::Ordering::Greater,
                0.into()
            ),
            cmp::Ordering::Less
        );

        assert_eq!(
            cmp::Ordering::conditional_select(
                &cmp::Ordering::Less,
                &cmp::Ordering::Greater,
                1.into()
            ),
            cmp::Ordering::Greater
        );
    }

    macro_rules! generate_integer_equal_tests {
    ($($t:ty),*) => ($(
        let y: $t = 0;  // all 0 bits
        let z: $t = !0; // all 1 bits

        let x = z;

        assert_eq!(x.ct_eq(&y).unwrap_u8(), 0);
        assert_eq!(x.ct_eq(&z).unwrap_u8(), 1);
        assert_eq!(x.ct_ne(&y).unwrap_u8(), 1);
        assert_eq!(x.ct_ne(&z).unwrap_u8(), 0);
    )*)
}

    #[test]
    fn integer_equal() {
        generate_integer_equal_tests!(u8, u16, u32, u64, u128, usize);
        generate_integer_equal_tests!(i8, i16, i32, i64, i128, isize);
    }

    #[test]
    fn ordering_equal() {
        let a = cmp::Ordering::Equal;
        let b = cmp::Ordering::Greater;
        let c = a;

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 0);
        assert_eq!(a.ct_eq(&c).unwrap_u8(), 1);
    }

    macro_rules! generate_greater_than_test {
        ($ty: ty) => {
            for _ in 0..100 {
                let mut rng = OsRng.unwrap_err();
                let x = rng.next_u64() as $ty;
                let y = rng.next_u64() as $ty;
                let z = x.ct_gt(&y);

                if x < y {
                    assert!(z.unwrap_u8() == 0);
                } else if x == y {
                    assert!(z.unwrap_u8() == 0);
                } else if x > y {
                    assert!(z.unwrap_u8() == 1);
                }
            }
        };
    }

    #[test]
    fn greater_than_u8() {
        generate_greater_than_test!(u8);
    }

    #[test]
    fn greater_than_u16() {
        generate_greater_than_test!(u16);
    }

    #[test]
    fn greater_than_u32() {
        generate_greater_than_test!(u32);
    }

    #[test]
    fn greater_than_u64() {
        generate_greater_than_test!(u64);
    }

    #[test]
    fn greater_than_u128() {
        generate_greater_than_test!(u128);
    }

    #[test]
    fn greater_than_ordering() {
        assert_eq!(
            cmp::Ordering::Less
                .ct_gt(&cmp::Ordering::Greater)
                .unwrap_u8(),
            0
        );
        assert_eq!(
            cmp::Ordering::Greater
                .ct_gt(&cmp::Ordering::Less)
                .unwrap_u8(),
            1
        );
    }

    #[test]
    /// Test that the two's compliment min and max, i.e. 0000...0001 < 1111...1110,
    /// gives the correct result. (This fails using the bit-twiddling algorithm that
    /// go/crypto/subtle uses.)
    fn less_than_twos_compliment_minmax() {
        let z = 1u32.ct_lt(&(2u32.pow(31) - 1));

        assert!(z.unwrap_u8() == 1);
    }

    macro_rules! generate_less_than_test {
        ($ty: ty) => {
            for _ in 0..100 {
                let mut rng = OsRng.unwrap_err();
                let x = rng.next_u64() as $ty;
                let y = rng.next_u64() as $ty;
                let z = x.ct_gt(&y);

                if x < y {
                    assert!(z.unwrap_u8() == 0);
                } else if x == y {
                    assert!(z.unwrap_u8() == 0);
                } else if x > y {
                    assert!(z.unwrap_u8() == 1);
                }
            }
        };
    }

    #[test]
    fn less_than_u8() {
        generate_less_than_test!(u8);
    }

    #[test]
    fn less_than_u16() {
        generate_less_than_test!(u16);
    }

    #[test]
    fn less_than_u32() {
        generate_less_than_test!(u32);
    }

    #[test]
    fn less_than_u64() {
        generate_less_than_test!(u64);
    }

    #[test]
    fn less_than_u128() {
        generate_less_than_test!(u128);
    }

    #[test]
    fn less_than_ordering() {
        assert_eq!(
            cmp::Ordering::Greater
                .ct_lt(&cmp::Ordering::Less)
                .unwrap_u8(),
            0
        );
        assert_eq!(
            cmp::Ordering::Less
                .ct_lt(&cmp::Ordering::Greater)
                .unwrap_u8(),
            1
        );
    }
}
