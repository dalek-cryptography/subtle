
# subtle  [![](https://img.shields.io/crates/v/subtle-derive.svg)](https://crates.io/crate/subtle-derive) [![](https://docs.rs/subtle-derive/badge.svg)](https://docs.rs/subtle-derive) [![](https://travis-ci.org/isislovecruft/subtle.svg?branch=master)](https://travis-ci.org/isislovecruft/subtle)

**Procedural macros for deriving [subtle](https://github.com/isislovecruft/subtle) trait implementations.**

## Warning

This code has **not** yet received sufficient peer review by other qualified
cryptographers to be considered in any way, shape, or form, safe.  Further, this
library does **not** provide much in the way of assurance against deliberate
misuse.  Instead, it is a low-level library, mostly of bit-flipping tricks,
intended for other cryptographers who would like to implement their own
constant-time libraries.  (For an example usage of this library, please see
[curve25519-dalek](https://github.com/isislovecruft/curve25519-dalek) and
[ed25519-dalek](https://github.com/isislovecruft/ed25519-dalek).)

**USE AT YOUR OWN RISK**

## Documentation

Extensive documentation is available [here](https://docs.rs/subtle-derive).

# Installation

To install, add the following to the dependencies section of your project's
`Cargo.toml`:

    subtle-derive = "^0.1"

Then, in your library or executable source, add:

    #[macro_use]
    extern crate subtle_derive

