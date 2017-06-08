extern crate proc_macro;
extern crate syn;

#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

#[proc_macro_derive(CTAssignable)]
pub fn conditional_assign(input: TokenStream) -> TokenStream {
    // Construct a string representation of the type definition
    let s: String = input.to_string();

    // Parse the string representation
    let ast: syn::MacroInput = syn::parse_macro_input(&s).unwrap();

    // Build the impl
    let gen: quote::Tokens = impl_conditional_assign(&ast);

    // Return the generated impl
    gen.parse().unwrap()
}

fn impl_conditional_assign(ast: &syn::MacroInput) -> quote::Tokens {
    let name: &syn::Ident = &ast.ident;

    // If we're decorating a struct…
    if let syn::Body::Struct(syn::VariantData::Struct(Vec<syn::Field>) = ast.body {
        let strukt = ast.body;
        let fields: Vec<syn::Field> = strukt.0.fields();

        // …for each field in the struct, determine which implementation of
        // conditional_assign() to use
        for field in ast.body.fields() {
            let field_type = field.ty;

            if let syn::Ty::Array(_, _) = field_type { // If the field is an array type
                quote! {
                    impl CTAssignable for #field_type {
                        #[inline(always)]
                        fn conditional_assign(&mut self, other &#field_type, choice: Mask) {
                            let mask = -(choice as i8) as u8;
                            for i in 0 .. self.len() { // XXX ↓ how to do access #field_type(Box<Ty>, ConstExpr)?
                                self[i] = self[i] ^ ((mask as #field_type) & (self[i] ^ other[i]))
                            }
                        }
                    }
                }
            //} else if let syn::IntTy(_) = field_type { // If the field is an integer type
                // quote! {
                //     impl CTAssignable for #field_type {
                //         #[inline(always)]
                //         fn conditional_assign(&mut self, other: &#field_type, choice: Mask) {
                //             let mask = -(choice as i8) as u8;
                //             self = self ^ ((mask as #field_type) & (self ^ other));
                //         }
                //     }
                // }
            } else {
                panic!("#[derive(CTAssignable)] currently can only handle structs \
                       whose fields are either array types or integer types.")
            }
        }
    } else {
        panic!("#[derive(CTAssignable)] is currently only supported for structs, not enums!");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
