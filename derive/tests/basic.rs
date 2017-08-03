extern crate subtle;
#[macro_use]
extern crate subtle_derive;

use subtle::Equal;

#[derive(Copy, Clone, Equal)]
struct SimpleStruct {
    a: u8,
    b: u8,
}

#[derive(Copy, Clone, Equal)]
struct TupleStruct(u8, u8);

#[derive(Copy, Clone, Equal)]
struct ComplexStruct {
    a: SimpleStruct,
    b: TupleStruct,
    c: [u16; 4],
}

#[derive(Copy, Clone, Equal)]
struct GenericStruct<'a, 'b, T> where T: 'a + Equal + Sized, 'a : 'b  {
    a: &'a [T],
    b: &'b [u8],
    c: T,
}

#[test]
fn test_struct_eq() {
    let f = SimpleStruct { a: 10, b: 11 };
    let g = f.clone();

    assert_eq!(f.ct_eq(&g), 1u8);
}

#[test]
fn test_struct_neq() {
    let f = SimpleStruct { a: 10, b: 11 };
    let g = SimpleStruct { a: 10, b: 12 };

    assert_eq!(f.ct_eq(&g), 0u8);
}

#[test]
fn test_tuple_eq() {
    let f = TupleStruct(10, 11);
    let g = f.clone();

    assert_eq!(f.ct_eq(&g), 1u8);
}

#[test]
fn test_tuple_neq() {
    let f = TupleStruct(10, 11);
    let g = TupleStruct(10, 12);

    assert_eq!(f.ct_eq(&g), 0u8);
}

#[test]
fn test_nested_eq() {
    let f = ComplexStruct {
        a: SimpleStruct {
            a: 10,
            b: 20,
        },
        b: TupleStruct(30, 40),
        c: [1, 2, 3, 4],
    };
    let g = f.clone();

    assert_eq!(f.ct_eq(&g), 1u8);
}

#[test]
fn test_nested_neq() {
    let f = ComplexStruct {
        a: SimpleStruct {
            a: 10,
            b: 20,
        },
        b: TupleStruct(30, 40),
        c: [1, 2, 3, 4],
    };
    let mut g = f.clone();
    g.c[2] = 0;

    assert_eq!(f.ct_eq(&g), 0u8);
}

#[should_panic]
#[test]
fn test_generics_bad() {
    let f = GenericStruct {
        a: &[1, 2, 3],
        b: &[4, 5, 6],
        c: 10u8,
    };
    let g = GenericStruct {
        a: &[1, 3],
        b: &[4, 5, 6],
        c: 10u8,
    };

    // Testing slices with nonequal length panics
    f.ct_eq(&g);
}

#[test]
fn test_generics_eq() {
    let f = GenericStruct {
        a: &[1, 2, 3],
        b: &[4, 5, 6],
        c: 10u8,
    };
    let g = f.clone();

    assert_eq!(f.ct_eq(&g), 1u8);
}

#[test]
fn test_generics_neq() {
    let f = GenericStruct {
        a: &[1, 2, 3],
        b: &[4, 5, 6],
        c: 10u8,
    };
    let g = GenericStruct {
        a: &[1, 2, 3],
        b: &[4, 0, 6],
        c: 10u8,
    };

    assert_eq!(f.ct_eq(&g), 0u8);
}
