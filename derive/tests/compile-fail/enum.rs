extern crate subtle;
#[macro_use]
extern crate subtle_derive;

use subtle::Equal;

#[derive(Equal)]
//~^ ERROR proc-macro derive panicked
//~^^ HELP Equal can only be derived on struct, but Bad is an enum
enum Bad {
    A,
    B
}

fn main() {}
