use crate::{ConditionallySelectable, ConstantTimeEq};
use core::hint::black_box;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// The `Choice` struct represents a choice for use in conditional assignment.
///
/// It is a wrapper around a `u8`, which should have the value either `1` (true)
/// or `0` (false).
///
/// The conversion from `u8` to `Choice` passes the value through an optimization
/// barrier, as a best-effort attempt to prevent the compiler from inferring that
/// the `Choice` value is a boolean. This strategy is based on Tim Maclean's
/// [work on `rust-timing-shield`][rust-timing-shield], which attempts to provide
/// a more comprehensive approach for preventing software side-channels in Rust
/// code.
///
/// The `Choice` struct implements operators for AND, OR, XOR, and NOT, to allow
/// combining `Choice` values. These operations do not short-circuit.
///
/// [rust-timing-shield]:
/// https://www.chosenplaintext.ca/open-source/rust-timing-shield/security
#[derive(Copy, Clone, Debug)]
pub struct Choice(pub(crate) u8);

impl Choice {
    /// Unwrap the `Choice` wrapper to reveal the underlying `u8`.
    ///
    /// # Note
    ///
    /// This function only exists as an **escape hatch** for the rare case
    /// where it's not possible to use one of the `subtle`-provided
    /// trait impls.
    ///
    /// **To convert a `Choice` to a `bool`, use the `From` implementation instead.**
    #[inline]
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl From<Choice> for bool {
    /// Convert the `Choice` wrapper into a `bool`, depending on whether
    /// the underlying `u8` was a `0` or a `1`.
    ///
    /// # Note
    ///
    /// This function exists to avoid having higher-level cryptographic protocol
    /// implementations duplicating this pattern.
    ///
    /// The intended use case for this conversion is at the _end_ of a
    /// higher-level primitive implementation: for example, in checking a keyed
    /// MAC, where the verification should happen in constant-time (and thus use
    /// a `Choice`) but it is safe to return a `bool` at the end of the
    /// verification.
    #[inline]
    fn from(source: Choice) -> bool {
        debug_assert!((source.0 == 0u8) | (source.0 == 1u8));
        source.0 != 0
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        (self.0 & rhs.0).into()
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Choice) {
        *self = *self & rhs;
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        (self.0 | rhs.0).into()
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Choice) {
        *self = *self | rhs;
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        (self.0 ^ rhs.0).into()
    }
}

impl BitXorAssign for Choice {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Choice) {
        *self = *self ^ rhs;
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        (1u8 & (!self.0)).into()
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(input: u8) -> Choice {
        debug_assert!((input == 0u8) | (input == 1u8));

        // Our goal is to prevent the compiler from inferring that the value held inside the
        // resulting `Choice` struct is really a `bool` instead of a `u8`.
        Choice(black_box(input))
    }
}

impl ConditionallySelectable for Choice {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Choice(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Choice {
    #[inline]
    fn ct_eq(&self, rhs: &Choice) -> Choice {
        !(*self ^ *rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Choice, ConditionallySelectable, ConstantTimeEq};

    #[test]
    fn choice_into_bool() {
        let choice_true: bool = Choice::from(1).into();
        assert!(choice_true);

        let choice_false: bool = Choice::from(0).into();
        assert!(!choice_false);
    }

    #[test]
    fn conditional_select_choice() {
        let t = Choice::from(1);
        let f = Choice::from(0);

        assert!(bool::from(Choice::conditional_select(&t, &f, f)));
        assert!(!bool::from(Choice::conditional_select(&t, &f, t)));
        assert!(!bool::from(Choice::conditional_select(&f, &t, f)));
        assert!(bool::from(Choice::conditional_select(&f, &t, t)));
    }

    #[test]
    fn choice_equal() {
        assert_eq!(Choice::from(0).ct_eq(&Choice::from(0)).unwrap_u8(), 1);
        assert_eq!(Choice::from(0).ct_eq(&Choice::from(1)).unwrap_u8(), 0);
        assert_eq!(Choice::from(1).ct_eq(&Choice::from(0)).unwrap_u8(), 0);
        assert_eq!(Choice::from(1).ct_eq(&Choice::from(1)).unwrap_u8(), 1);
    }
}
