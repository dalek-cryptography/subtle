
# subtle  [![](https://img.shields.io/crates/v/subtle.svg)](https://crates.io/crate/subtle) [![](https://docs.rs/subtle/badge.svg)](https://docs.rs/subtle) [![](https://travis-ci.org/isislovecruft/subtle.svg?branch=master)](https://travis-ci.org/isislovecruft/subtle)

**Pure-Rust traits and utilities for constant-time cryptographic implementations.**

Significant portions of this code are based upon Golang's "crypto/subtle"
module, and this library aims to be that library's Rust equivalent¹, plus more.

¹ The only function in Golang's "crypto/subtle" module which we do not implement
is `ConstantTimeLessOrEq`.  This is for two reasons: first, that
`ConstantTimeLessOrEq`, as far as this author knows, is only used to implement
the RSA encryption padding scheme defined in the (now outdated) PKCS#1 v1.5
standard (superseded by the newer RSA-OAEP mode).  Not only should use of this
outdated mode cease to continue, it is known to be dangerous for encrypting
anything other than a symmetric session key.  Second, without other constant-time
comparison functions (e.g. "greater or equal"), this author feels that
providing solely `ConstantTimeLessOrEq` would provide a
weird/incomplete API.

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

Extensive documentation is available [here](https://docs.rs/subtle).

# Installation

To install, add the following to the dependencies section of your project's
`Cargo.toml`:

    subtle = "^0.1"

Then, in your library or executable source, add:

    extern crate subtle
