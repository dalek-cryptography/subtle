# subtle

[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]

**Procedural macros for deriving [subtle] trait implementations.**

Derive macro implemented for traits:
- [x] ConstantTimeEq
- [ ] ConstantTimeGreater
- [ ] ConstantTimeLesser

## Documentation

Documentation is available [here][subtle-docs].

# Installation
To install, add the following to the dependencies section of your project's `Cargo.toml`:

```toml
subtle = { version = "2.6", features = ["derive"] }
```

[crate-image]: https://img.shields.io/crates/v/subtle-derive?style=flat-square
[crate-link]: https://crates.io/crates/subtle-derive
[docs-image]: https://img.shields.io/docsrs/subtle-derive?style=flat-square
[docs-link]: https://docs.rs/crate/subtle-derive
[subtle]: https://crates.io/crates/subtle
[subtle-docs]: https://docs.rs/subtle