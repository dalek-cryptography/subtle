# subtle  [![](https://img.shields.io/crates/v/subtle.svg)](https://crates.io/crates/subtle) [![](https://docs.rs/subtle/badge.svg)](https://docs.rs/subtle) [![](https://travis-ci.org/dalek-cryptography/subtle.svg?branch=master)](https://travis-ci.org/dalek-cryptography/subtle)

**Pure-Rust traits and utilities for constant-time cryptographic implementations.**

This crate represents a "best-effort" attempt, since side-channels
are ultimately a property of a deployed cryptographic system
including the hardware it runs on, not just of software.

It consists of a `Choice` type, a wrapper around a `u8` that holds a
`0` or `1`, and a collection of traits using `Choice` instead of
`bool`.  Implementations of these traits are provided for primitive
types.

```toml
[dependencies.subtle]
version = "^0.5"
features = ["nightly"]
```

## Features

* The `nightly` feature enables `u128`/`i128` support and the use of
the `test::black_box` optimization barrier to protect the `Choice`
type.

* The `generic-impls` feature (enabled by default) provides generic
impls of some traits.  It can be disabled to allow specialized impls
without impl conflicts.

## Documentation

Documentation is available [here](https://docs.rs/subtle).

## About

Significant portions of this code were based upon Golang's "crypto/subtle"
module, and this library aims to be that library's Rust equivalent.

## Warning

This code has **not** yet received sufficient peer review by other qualified
cryptographers to be considered in any way, shape, or form, safe.  Further, this
library does **not** provide much in the way of assurance against deliberate
misuse.  Instead, it is a low-level library, mostly of bit-flipping tricks,
intended for other cryptographers who would like to implement their own
constant-time libraries.  (For an example usage of this library, please see
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) and
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek).)

**USE AT YOUR OWN RISK**

