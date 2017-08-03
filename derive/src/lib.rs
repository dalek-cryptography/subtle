extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

#[proc_macro_derive(Equal)]
pub fn derive_cteq(input: TokenStream) -> TokenStream {
    let s = input.to_string();

    let ast = syn::parse_derive_input(&s).unwrap();
    let typename = ast.ident;
    let generics = ast.generics;

    match ast.body {
        syn::Body::Struct(vdata) => {
            let gen = match vdata {
                syn::VariantData::Unit => impl_cteq_unit(typename, generics),
                syn::VariantData::Tuple(fields) => impl_cteq_fields(typename, fields, generics),
                syn::VariantData::Struct(fields) => impl_cteq_fields(typename, fields, generics),
            };
            gen.parse().unwrap()
        }

        // Enums can't be compared in constant time. Consider
        //
        // enum Foo {
        //     A,
        //     B(usize, usize, usize),
        // }
        //
        // If a = A, and b = B(0,0,0). Then comparing a to b is immediately false, since a and b
        // are different variants. Then consider a = B(0,0,1) and b = B(0,0,0). Now a and b are
        // compared field-by-field, which breaks the constant-time guarantee. A workaround might be
        // to force every variant to take as long as the longest-running variant, but that's pretty
        // unlikely.
        syn::Body::Enum(_) =>
            panic!("Equal can only be derived on struct, but {} is an enum", typename),
    }
}

fn impl_cteq_unit(typename: syn::Ident, generics: syn::Generics) -> quote::Tokens {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        // Unit structs are always equal
        impl #impl_generics Equal for #typename #ty_generics #where_clause {
            #[inline(always)]
            fn ct_eq(&self, other: &#typename #ty_generics) -> subtle::Mask {
                1u8
            }
        }
    }
}

fn impl_cteq_fields(typename: syn::Ident, fields: Vec<syn::Field>, generics: syn::Generics)
        -> quote::Tokens {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Member names are either the field names (when we're in a normal struct) or numbers (when
    // we're in a tuple struct)
    let membernames1 = fields.into_iter()
                             .enumerate()
                             .map(|(i, f)| f.ident.unwrap_or(syn::Ident::from(&*i.to_string())))
                             .collect::<Vec<syn::Ident>>();

    // We make a clone because the member names are mentioned twice in the repetition clause in the
    // impl. quote! doesn't like using the same identifier twice, but it will happily zip two lists
    // of the same length. So we make those two lists identical and use that.
    let membernames2 = membernames1.clone();

    quote! {
        impl #impl_generics Equal for #typename #ty_generics #where_clause {
            #[inline(always)]
            fn ct_eq(&self, other: &#typename #ty_generics) -> subtle::Mask {
                // Go through each member, ANDing together their equality results
                let mut x = 1u8;
                #(x &= self.#membernames1.ct_eq(&other.#membernames2);)*
                x
            }
        }
    }
}
