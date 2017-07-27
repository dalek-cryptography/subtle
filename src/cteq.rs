use common::Mask;

/// Trait for items whose equality to another item may be tested in constant time.
pub trait CTEq {
    /// Determine if two items are equal in constant time.
    ///
    /// # Returns
    ///
    /// `1u8` if the two items are equal, and `0u8` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() {
    /// # use subtle::CTEq;
    ///
    /// // Note, if x and y are different lengths, `ct_eq` will panic
    /// let x = [1, 2, 3];
    /// let y = [1, 2, 4];
    /// assert_eq!(x.ct_eq(&y), 0u8);
    ///
    /// let x = 10u16;
    /// let y = x;
    /// assert_eq!(x.ct_eq(&y), 1u8);
    /// # }
    fn ct_eq(&self, other: &Self) -> Mask;
}

impl CTEq for u8 {
    #[inline(always)]
    fn ct_eq(&self, other: &u8) -> Mask {
        let mut x: u8;

        x  = !(self ^ other);
        x &= x >> 4;
        x &= x >> 2;
        x &= x >> 1;
        x
    }
}

impl CTEq for i8 {
    #[inline(always)]
    fn ct_eq(&self, other: &i8) -> Mask {
        (*self as u8).ct_eq(&(*other as u8))
    }
}

impl CTEq for u16 {
    #[inline(always)]
    fn ct_eq(&self, other: &u16) -> Mask {
        let mut x: u16;

        x  = !(self ^ other);
        x &= x >> 8;
        x &= x >> 4;
        x &= x >> 2;
        x &= x >> 1;
        x as u8
    }
}

impl CTEq for i16 {
    #[inline(always)]
    fn ct_eq(&self, other: &i16) -> Mask {
        (*self as u16).ct_eq(&(*other as u16))
    }
}

impl CTEq for u32 {
    #[inline(always)]
    fn ct_eq(&self, other: &u32) -> Mask {
        let mut x: u32;

        x  = !(self ^ other);
        x &= x >> 16;
        x &= x >> 8;
        x &= x >> 4;
        x &= x >> 2;
        x &= x >> 1;
        x as u8
    }
}

impl CTEq for i32 {
    #[inline(always)]
    fn ct_eq(&self, other: &i32) -> Mask {
        (*self as u32).ct_eq(&(*other as u32))
    }
}

impl CTEq for u64 {
    #[inline(always)]
    fn ct_eq(&self, other: &u64) -> Mask {
        let mut x: u64;

        x  = !(self ^ other);
        x &= x >> 32;
        x &= x >> 16;
        x &= x >> 8;
        x &= x >> 4;
        x &= x >> 2;
        x &= x >> 1;
        x as u8
    }
}

impl CTEq for i64 {
    #[inline(always)]
    fn ct_eq(&self, other: &i64) -> Mask {
        (*self as u64).ct_eq(&(*other as u64))
    }
}

#[cfg(target_pointer_width = "64")]
impl CTEq for usize {
    #[inline(always)]
    fn ct_eq(&self, other: &usize) -> Mask {
        (*self as u64).ct_eq(&(*other as u64))
    }
}

#[cfg(target_pointer_width = "32")]
impl CTEq for usize {
    #[inline(always)]
    fn ct_eq(&self, other: &usize) -> Mask {
        (*self as u32).ct_eq(&(*other as u32))
    }
}

impl<T: CTEq> CTEq for [T] {
    #[inline(always)]
    fn ct_eq(&self, other: &[T]) -> Mask {
        assert_eq!(self.len(), other.len());

        // AND all the elements together
        self.iter().zip(other.iter()).fold(1u8, |x, (a, b)| x & a.ct_eq(b))
    }
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
#[deprecated(since="0.1.1", note="Use a.ct_eq(b) instead")]
#[inline(always)]
pub fn arrays_equal(a: &[u8], b: &[u8]) -> Mask {
    a.ct_eq(b)
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use self::rand::Rng;

    #[test]
    #[should_panic]
    fn test_arrays_diff_len() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        // This should panic
        &a.ct_eq(&b);
    }

    #[test]
    fn test_arrays_neq() {
        let a: [u8; 1] = [13];
        let b: [u8; 1] = [5];

        assert_eq!(a.ct_eq(&b), 0u8);
    }

    #[test]
    fn test_arrays_eq() {
        let a: [u8; 5] = [1, 2, 3, 4, 5];
        let b: [u8; 5] = [1, 2, 3, 4, 5];

        assert_eq!(a.ct_eq(&b), 1u8);
    }

    #[test]
    fn test_u8_eq_correctness() {
        // Test every pair of bytes
        for a in 0..256 {
            for b in 0..256 {
                let a = a as u8;
                let b = b as u8;
                let is_eq = (a == b) as u8;

                assert_eq!(a.ct_eq(&b), is_eq);
            }
        }
    }

    macro_rules! rand_correctness_test {
        ( $name:ident, $t:ty ) => {
            #[test]
            fn $name() {
                let mut rng = rand::thread_rng();
                // Do 100k trials
                for _ in 0..100_000 {
                    let is_eq = rng.gen::<bool>();
                    let (a, b) = if is_eq {
                            let x = rng.gen::<$t>();
                            (x, x)
                        }
                        else {
                            let x = rng.gen::<$t>();
                            // Break with value is currently unstable :(
                            let mut y = rng.gen::<$t>();
                            // Loop until we have two different values
                            while x == y {
                                y = rng.gen::<$t>();
                            }

                            (x, y)
                        };
                    assert_eq!(a.ct_eq(&b), is_eq as u8, "(a, b) == ({}, {})", a, b);
                }
            }
        };
    }

    rand_correctness_test!(test_u16_eq_correctness, u16);
    rand_correctness_test!(test_i16_eq_correctness, i16);
    rand_correctness_test!(test_u32_eq_correctness, u32);
    rand_correctness_test!(test_i32_eq_correctness, i32);
    rand_correctness_test!(test_u64_eq_correctness, u64);
    rand_correctness_test!(test_i64_eq_correctness, i64);
}
