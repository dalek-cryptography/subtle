#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]
// put this after the #![doc(..)] so it appears as a footer:
//! Note that docs will only build on nightly Rust until
//! [RFC 1990 stabilizes](https://github.com/rust-lang/rust/issues/44732).

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets, since I didn't
have one to test correctness on.  If you're seeing this message,
please file an issue!
"#
);

extern crate byteorder;
extern crate clear_on_drop;
extern crate core;
extern crate keccak;
extern crate rand;
extern crate rand_core;

#[cfg(test)]
extern crate curve25519_dalek;
#[cfg(test)]
extern crate rand_chacha;
#[cfg(test)]
extern crate strobe_rs;

mod constants;
mod strobe;
mod transcript;

pub use transcript::Transcript;
pub use transcript::TranscriptRng;
pub use transcript::TranscriptRngBuilder;
