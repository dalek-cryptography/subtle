#![cfg(feature = "subtle-derive")]

use subtle_derive::ConstantTimeEq;

#[derive(Clone, Copy, ConstantTimeEq)]
struct NamedField {
    data: [u8; 16],
}

#[derive(ConstantTimeEq)]
struct NamedFields {
    data1: [u8; 16],
    data2: u64,
}

#[derive(ConstantTimeEq)]
struct NamedFieldsLifetime<'a> {
    data1: &'a [u8],
    data2: u64,
}

#[derive(ConstantTimeEq)]
struct NamedFieldsMultipleLifetime<'a, 'b> {
    data1: &'a [u8],
    data2: &'b [u8],
}

#[derive(ConstantTimeEq)]
struct NamedFieldUnnamedFieldData {
    data: UnnamedField,
}

#[derive(ConstantTimeEq)]
struct NamedFieldUnnamedFieldsData {
    data: UnnamedFields,
}

#[derive(ConstantTimeEq)]
struct NamedFieldUnnamedArrayField {
    data: UnnamedArrayField,
}

#[derive(ConstantTimeEq)]
struct NamedFieldsUnnamedFieldsData {
    data1: UnnamedFields,
    data2: u64,
}

#[derive(ConstantTimeEq)]
struct NamedFieldsUnnamedFieldData {
    data1: UnnamedField,
    data2: u64,
}

#[derive(ConstantTimeEq)]
struct NamedFieldsUnnamedArrayFieldData {
    data1: UnnamedArrayField,
    data2: u64,
}

#[derive(Clone, Copy, ConstantTimeEq)]
struct UnnamedField(NamedField);

#[derive(Clone, Copy, ConstantTimeEq)]
struct UnnamedArrayField([u8; 8]);

#[derive(Clone, Copy, ConstantTimeEq)]
struct UnnamedFields(u32, u64, u32);

#[derive(Eq, PartialEq, ConstantTimeEq)]
enum EnumFields {
    Field1,
    Field2,
}

#[cfg(test)]
mod test {
    use crate::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn ct_eq_named_field() {
        let first = NamedField { data: [3u8; 16] };
        let second = NamedField { data: [3u8; 16] };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field() {
        let first = NamedField { data: [45u8; 16] };
        let second = NamedField { data: [87u8; 16] };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_fields() {
        let first = NamedFields {
            data1: [45u8; 16],
            data2: 3,
        };
        let second = NamedFields {
            data1: [45u8; 16],
            data2: 3,
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_fields() {
        let first = NamedFields {
            data1: [45u8; 16],
            data2: 2,
        };
        let second = NamedFields {
            data1: [87u8; 16],
            data2: 3,
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_unnamed_array_field() {
        let first = UnnamedArrayField([3u8; 8]);
        let second = UnnamedArrayField([3u8; 8]);
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_unnamed_array_field() {
        let first = UnnamedArrayField([75u8; 8]);
        let second = UnnamedArrayField([22u8; 8]);
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_unnamed_field() {
        let first = UnnamedField(NamedField { data: [23u8; 16] });
        let second = UnnamedField(NamedField { data: [23u8; 16] });
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_unnamed_field() {
        let first = UnnamedField(NamedField { data: [33u8; 16] });
        let second = UnnamedField(NamedField { data: [83u8; 16] });
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_unnamed_fields() {
        let first = UnnamedFields(109, 2, 35);
        let second = UnnamedFields(109, 2, 35);
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_unnamed_fields() {
        let first = UnnamedFields(12, 2, 34);
        let second = UnnamedFields(37, 7, 95);
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_field_with_unnamed_data() {
        let first = NamedFieldUnnamedFieldData {
            data: UnnamedField(NamedField { data: [23u8; 16] }),
        };
        let second = NamedFieldUnnamedFieldData {
            data: UnnamedField(NamedField { data: [23u8; 16] }),
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field_with_unnamed_data() {
        let first = NamedFieldUnnamedFieldData {
            data: UnnamedField(NamedField { data: [3u8; 16] }),
        };
        let second = NamedFieldUnnamedFieldData {
            data: UnnamedField(NamedField { data: [53u8; 16] }),
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_field_with_unnamed_fields_data() {
        let first = NamedFieldUnnamedFieldsData {
            data: UnnamedFields(109, 2, 35),
        };
        let second = NamedFieldUnnamedFieldsData {
            data: UnnamedFields(109, 2, 35),
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field_with_unnamed_fields_data() {
        let first = NamedFieldUnnamedFieldsData {
            data: UnnamedFields(109, 4, 109),
        };
        let second = NamedFieldUnnamedFieldsData {
            data: UnnamedFields(109, 7, 23),
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_field_with_unnamed_array_fields_data() {
        let first = NamedFieldUnnamedArrayField {
            data: UnnamedArrayField([75u8; 8]),
        };
        let second = NamedFieldUnnamedArrayField {
            data: UnnamedArrayField([75u8; 8]),
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field_with_unnamed_array_fields_data() {
        let first = NamedFieldUnnamedArrayField {
            data: UnnamedArrayField([86u8; 8]),
        };
        let second = NamedFieldUnnamedArrayField {
            data: UnnamedArrayField([32u8; 8]),
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_fields_with_unnamed_data() {
        let first = NamedFieldsUnnamedFieldData {
            data1: UnnamedField(NamedField { data: [23u8; 16] }),
            data2: 3,
        };
        let second = NamedFieldsUnnamedFieldData {
            data1: UnnamedField(NamedField { data: [23u8; 16] }),
            data2: 3,
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_fields_with_unnamed_data() {
        let first = NamedFieldsUnnamedFieldData {
            data1: UnnamedField(NamedField { data: [3u8; 16] }),
            data2: 5,
        };
        let second = NamedFieldsUnnamedFieldData {
            data1: UnnamedField(NamedField { data: [53u8; 16] }),
            data2: 6,
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_fields_with_unnamed_fields_data() {
        let first = NamedFieldsUnnamedFieldsData {
            data1: UnnamedFields(109, 2, 35),
            data2: 8,
        };
        let second = NamedFieldsUnnamedFieldsData {
            data1: UnnamedFields(109, 2, 35),
            data2: 8,
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_fields_with_unnamed_fields_data() {
        let first = NamedFieldsUnnamedFieldsData {
            data1: UnnamedFields(109, 4, 109),
            data2: 3,
        };
        let second = NamedFieldsUnnamedFieldsData {
            data1: UnnamedFields(109, 7, 23),
            data2: 4,
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_fields_with_unnamed_array_fields_data() {
        let first = NamedFieldsUnnamedArrayFieldData {
            data1: UnnamedArrayField([75u8; 8]),
            data2: 5,
        };
        let second = NamedFieldsUnnamedArrayFieldData {
            data1: UnnamedArrayField([75u8; 8]),
            data2: 5,
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_fields_with_unnamed_array_fields_data() {
        let first = NamedFieldsUnnamedArrayFieldData {
            data1: UnnamedArrayField([86u8; 8]),
            data2: 11,
        };
        let second = NamedFieldsUnnamedArrayFieldData {
            data1: UnnamedArrayField([32u8; 8]),
            data2: 9,
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_enum_fields() {
        let first = EnumFields::Field2;
        let second = EnumFields::Field2;
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_enum_fields() {
        let first = EnumFields::Field1;
        let second = EnumFields::Field2;
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_field_lifetime() {
        let first = NamedFieldsLifetime {
            data1: &[75u8; 16],
            data2: 5,
        };
        let second = NamedFieldsLifetime {
            data1: &[75u8; 16],
            data2: 5,
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field_lifetime() {
        let first = NamedFieldsLifetime {
            data1: &[75u8; 16],
            data2: 5,
        };
        let second = NamedFieldsLifetime {
            data1: &[2u8; 16],
            data2: 9,
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_eq_named_field_multiple_lifetime() {
        let first = NamedFieldsMultipleLifetime {
            data1: &[75u8; 16],
            data2: &[38u8; 16],
        };
        let second = NamedFieldsMultipleLifetime {
            data1: &[75u8; 16],
            data2: &[38u8; 16],
        };
        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_eq_named_field_multiple_lifetime() {
        let first = NamedFieldsMultipleLifetime {
            data1: &[75u8; 16],
            data2: &[75u8; 16],
        };
        let second = NamedFieldsMultipleLifetime {
            data1: &[2u8; 16],
            data2: &[86u8; 16],
        };
        assert!(bool::from(!first.ct_eq(&second)));
    }
}
