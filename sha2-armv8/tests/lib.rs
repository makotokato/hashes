#![no_std]
#[macro_use]
extern crate digest;
extern crate sha2_armv8 as sha2;

use digest::dev::{one_million_a, digest_test};

new_test!(sha224_main, "sha224", sha2::Sha224, digest_test);
new_test!(sha256_main, "sha256", sha2::Sha256, digest_test);

#[test]
fn sha256_1million_a() {
    let output = include_bytes!("data/sha256_one_million_a.bin");
    one_million_a::<sha2::Sha256>(output);
}
