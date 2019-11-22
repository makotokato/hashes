//! An implementation of the [SHA-2][1] cryptographic hash algorithms.
//!
//! There are 2 standard algorithms specified in the SHA-2 standard:
//!
//! * `Sha224`, which is the 32-bit `Sha256` algorithm with the result truncated
//! to 224 bits.
//! * `Sha256`, which is the 32-bit `Sha256` algorithm.
//!
//! Algorithmically, there are only 1 core algorithms: `Sha256`.
//! All other algorithms are just applications of these with different initial
//! hash values, and truncated to different digest bit lengths.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate sha2_armv8;
//! # fn main() {
//! use sha2_armv8::{Sha256, Digest};
//!
//! // create a Sha256 object
//! let mut hasher = Sha256::new();
//!
//! // write input message
//! hasher.input(b"hello world");
//!
//! // read hash digest and consume hasher
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("
//!     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
//! ")[..]);
//! }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-2
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![feature(
  aarch64_target_feature,
  asm,
  stdsimd,
)]
extern crate block_buffer;
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
#[cfg(feature = "std")]
extern crate std;
#[cfg(not(feature = "nocheck"))]
mod target_checks;

mod consts;
mod sha256_utils;
mod sha256;

pub use digest::Digest;
pub use sha256::{Sha256, Sha224};
