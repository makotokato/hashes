#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate sha1_armv8 as sha1;

bench!(sha1::Sha1);
