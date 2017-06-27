use common::Mask;

/// Trait for items whose equality to another item may be tested in constant time.
pub trait CTEq {
    /// Determine if two items are equal in constant time.
    ///
    /// # Returns
    ///
    /// `1u8` if the two items are equal, and `0u8` otherwise.
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

#[cfg(test)]
mod test {
    use super::*;

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
    fn test_bytes_eq_correctness() {
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
}
