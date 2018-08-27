#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]
// put this after the #![doc(..)] so it appears as a footer:
//! Note that docs will only build on nightly Rust until
//! [RFC 1990 stabilizes](https://github.com/rust-lang/rust/issues/44732).

extern crate byteorder;
extern crate clear_on_drop;
extern crate core;
extern crate keccak;
extern crate rand;
extern crate rand_core;

#[cfg(test)]
extern crate curve25519_dalek;
#[cfg(test)]
extern crate strobe_rs;

mod strobe;
mod transcript;

pub use transcript::Transcript;
pub use transcript::TranscriptRng;
pub use transcript::TranscriptRngConstructor;
