// Copyright (c) 2023 The MobileCoin Foundation

//! # subtle
//!
//! [![Crates.io][crate-image]][crate-link]<!--
//! -->[![Docs Status][docs-image]][docs-link]
//!
//! **Procedural macros for deriving [subtle] trait implementations.**
//!
//! Derive macro implemented for traits:
//! - [x] ConstantTimeEq
//! - [ ] ConstantTimeGreater
//! - [ ] ConstantTimeLesser
//!
//! ## Documentation
//!
//! Documentation is available [here][subtle-docs].
//!
//! # Installation
//! To install, add the following to the dependencies section of your project's `Cargo.toml`:
//!
//! ```toml
//! subtle = { version = "2.6", features = ["derive"] }
//! ```
//!
//! [crate-image]: https://img.shields.io/crates/v/subtle-derive?style=flat-square
//! [crate-link]: https://crates.io/crates/subtle-derive
//! [docs-image]: https://img.shields.io/docsrs/subtle-derive?style=flat-square
//! [docs-link]: https://docs.rs/crate/subtle-derive
//! [subtle]: https://crates.io/crates/subtle
//! [subtle-docs]: https://docs.rs/subtle

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Fields, GenericParam, Generics};

#[proc_macro_derive(ConstantTimeEq)]
pub fn constant_time_eq(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_ct_eq(&input)
}


fn parse_fields(fields: &Fields) -> Result<proc_macro2::TokenStream, &'static str> {
    match &fields {
        Fields::Named(fields_named) => {
            let mut token_stream = quote!();
            let mut iter = fields_named.named.iter().peekable();

            while let Some(field) = iter.next() {
                let ident = &field.ident;
                match iter.peek() {
                    None => token_stream.extend(quote! { {self.#ident}.ct_eq(&{other.#ident}) }),
                    Some(_) => {
                        token_stream.extend(quote! { {self.#ident}.ct_eq(&{other.#ident}) & })
                    }
                }
            }
            Ok(token_stream)
        }
        Fields::Unnamed(unnamed_fields) => {
            let mut token_stream = quote!();
            let mut iter = unnamed_fields.unnamed.iter().peekable();
            let mut idx = 0;
            while let Some(_) = iter.next() {
                let i = syn::Index::from(idx);
                match iter.peek() {
                    None => token_stream.extend(quote! { {self.#i}.ct_eq(&{other.#i}) }),
                    Some(_) => {
                        token_stream.extend(quote! { {self.#i}.ct_eq(&{other.#i}) & });
                        idx += 1;
                    }
                }
            }

            Ok(token_stream)
        }
        Fields::Unit => Err("Constant time cannot be derived for unit fields"),
    }
}

fn parse_enum(data_enum: &DataEnum) -> Result<proc_macro2::TokenStream, &'static str> {
    for variant in data_enum.variants.iter() {
        if let Fields::Unnamed(_) = variant.fields {
            panic!("Cannot derive ct_eq for fields in enums")
        }
    }
    let token_stream = quote! {
        ::subtle::Choice::from((self == other) as u8)
    };

    Ok(token_stream)
}

fn parse_data(data: &Data) -> Result<proc_macro2::TokenStream, &'static str> {
    match data {
        Data::Struct(variant_data) => parse_fields(&variant_data.fields),
        Data::Enum(data_enum) => parse_enum(data_enum),
        Data::Union(..) => Err("Constant time cannot be derived for a union"),
    }
}

fn parse_lifetime(generics: &Generics) -> u32 {
    let mut count = 0;
    for i in generics.params.iter() {
        if let GenericParam::Lifetime(_) = i {
            count += 1;
        }
    }
    count
}

fn derive_ct_eq(input: &DeriveInput) -> TokenStream {
    let ident = &input.ident;
    let data = &input.data;
    let generics = &input.generics;
    let is_lifetime = parse_lifetime(generics);
    let ct_eq_stream: proc_macro2::TokenStream =
        parse_data(data).expect("Failed to parse DeriveInput data");
    let data_ident = if is_lifetime != 0 {
        let mut s = format!("{}<'_", ident);

        for _ in 1..is_lifetime {
            s.push_str(", '_");
        }
        s.push('>');

        s
    } else {
        ident.to_string()
    };
    let ident_stream: proc_macro2::TokenStream =
        data_ident.parse().expect("Should be valid lifetime tokens");

    let expanded: proc_macro2::TokenStream = quote! {
            impl ::subtle::ConstantTimeEq for #ident_stream {
                fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                    use ::subtle::ConstantTimeEq;
                    return #ct_eq_stream
                }
            }
    };

    expanded.into()
}
