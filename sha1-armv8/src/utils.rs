#![allow(unused_assignments)]

use consts::{K0, K1, K2, K3};
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vsha1cq_u32, vsha1h_u32, vsha1mq_u32, vsha1pq_u32, vsha1su0q_u32,
    vsha1su1q_u32,
};
use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;

type Block = GenericArray<u8, U64>;

// Some NEON simd functions are missing.
#[inline(always)]
unsafe fn vld1q_u32(mem: *const uint32x4_t) -> uint32x4_t {
    core::ptr::read_unaligned(mem)
}

#[inline(always)]
unsafe fn vst1q_u32(mem: *mut uint32x4_t, value: uint32x4_t) {
    core::ptr::write_unaligned(mem, value);
}

#[inline(always)]
unsafe fn vrev32q_u8(value: uint32x4_t) -> uint32x4_t {
    let ret: uint32x4_t;
    asm!("rev32 $0.16b, $1.16b" : "=w"(ret) : "w"(value) :);
    ret
}

#[inline(always)]
unsafe fn vdupq_n_u32(value: u32) -> uint32x4_t {
    let r: [u32; 4] = [value, value, value, value];
    core::mem::transmute(r)
}

#[inline(always)]
unsafe fn vgetq_lane_u32(value: uint32x4_t, index: usize) -> u32 {
    let r: [u32; 4] = core::mem::transmute(value);
    r[index]
}

macro_rules! round1 {
    ($abcd:expr, $e:expr, $e1:expr, $t:expr) => {
        $e1 = vsha1h_u32(vgetq_lane_u32($abcd, 0));
        $abcd = vsha1cq_u32($abcd, $e, $t);
    };
}

macro_rules! round2 {
    ($abcd:expr, $e:expr, $e1:expr, $t:expr) => {
        $e1 = vsha1h_u32(vgetq_lane_u32($abcd, 0));
        $abcd = vsha1pq_u32($abcd, $e, $t);
    };
}

macro_rules! round3 {
    ($abcd:expr, $e:expr, $e1:expr, $t:expr) => {
        $e1 = vsha1h_u32(vgetq_lane_u32($abcd, 0));
        $abcd = vsha1mq_u32($abcd, $e, $t);
    };
}

macro_rules! schedule {
    ($w0:expr, $w1:expr, $w2:expr, $w3:expr) => {
        $w0 = vsha1su1q_u32($w0, $w3);
        $w1 = vsha1su0q_u32($w1, $w2, $w3);
    };
}

/// Process a block with the SHA-1 algorithm.
///
pub fn compress(state: &mut [u32; 5], block: &Block) {
    unsafe {
        let block: &[u8; 64] = core::mem::transmute(block);
        let k0: uint32x4_t = vdupq_n_u32(K0);
        let k1: uint32x4_t = vdupq_n_u32(K1);
        let k2: uint32x4_t = vdupq_n_u32(K2);
        let k3: uint32x4_t = vdupq_n_u32(K3);

        let mut abcd = vld1q_u32(state.as_ptr() as *const uint32x4_t);
        let mut e = state[4];

        let orig_abcd = abcd;
        let orig_e = e;

        let mut w0 = vld1q_u32(block.as_ptr() as *const uint32x4_t);
        let mut w1 = vld1q_u32(block[16..].as_ptr() as *const uint32x4_t);
        let mut w2 = vld1q_u32(block[32..].as_ptr() as *const uint32x4_t);
        let mut w3 = vld1q_u32(block[48..].as_ptr() as *const uint32x4_t);
        w0 = vrev32q_u8(w0);
        w1 = vrev32q_u8(w1);
        w2 = vrev32q_u8(w2);
        w3 = vrev32q_u8(w3);

        let mut t0 = vaddq_u32(w0, k0);
        let mut t1 = vaddq_u32(w1, k0);
        let mut e1;

        // Round 0..3
        round1!(abcd, e, e1, t0);
        t0 = vaddq_u32(w2, k0);
        w0 = vsha1su0q_u32(w0, w1, w2);
        // Round 4..7
        round1!(abcd, e1, e, t1);
        t1 = vaddq_u32(w3, k0);
        schedule!(w0, w1, w2, w3);
        // Round 8..11
        round1!(abcd, e, e1, t0);
        t0 = vaddq_u32(w0, k0);
        schedule!(w1, w2, w3, w0);
        // Round 12..15
        round1!(abcd, e1, e, t1);
        t1 = vaddq_u32(w1, k1);
        schedule!(w2, w3, w0, w1);
        // Round 16..19
        round1!(abcd, e, e1, t0);
        t0 = vaddq_u32(w2, k1);
        schedule!(w3, w0, w1, w2);
        // Round 20..23
        round2!(abcd, e1, e, t1);
        t1 = vaddq_u32(w3, k1);
        schedule!(w0, w1, w2, w3);
        // Round 24..27
        round2!(abcd, e, e1, t0);
        t0 = vaddq_u32(w0, k1);
        schedule!(w1, w2, w3, w0);
        // Round 28..31
        round2!(abcd, e1, e, t1);
        t1 = vaddq_u32(w1, k1);
        schedule!(w2, w3, w0, w1);
        // Round 32..35
        round2!(abcd, e, e1, t0);
        t0 = vaddq_u32(w2, k2);
        schedule!(w3, w0, w1, w2);
        // Round 36..39
        round2!(abcd, e1, e, t1);
        t1 = vaddq_u32(w3, k2);
        schedule!(w0, w1, w2, w3);
        // Round 40..43
        round3!(abcd, e, e1, t0);
        t0 = vaddq_u32(w0, k2);
        schedule!(w1, w2, w3, w0);
        // Round 44..47
        round3!(abcd, e1, e, t1);
        t1 = vaddq_u32(w1, k2);
        schedule!(w2, w3, w0, w1);
        // Round 48..51
        round3!(abcd, e, e1, t0);
        t0 = vaddq_u32(w2, k2);
        schedule!(w3, w0, w1, w2);
        // Round 52..55
        round3!(abcd, e1, e, t1);
        t1 = vaddq_u32(w3, k3);
        schedule!(w0, w1, w2, w3);
        // Round 56..59
        round3!(abcd, e, e1, t0);
        t0 = vaddq_u32(w0, k3);
        schedule!(w1, w2, w3, w0);
        // Round 60..63
        round2!(abcd, e1, e, t1);
        t1 = vaddq_u32(w1, k3);
        schedule!(w2, w3, w0, w1);
        // Round 64..67
        round2!(abcd, e, e1, t0);
        t0 = vaddq_u32(w2, k3);
        schedule!(w3, w0, w1, w2);
        // Round 68..71
        round2!(abcd, e1, e, t1);
        t1 = vaddq_u32(w3, k3);
        // Round 72..75
        round2!(abcd, e, e1, t0);
        // Round 76..79
        round2!(abcd, e1, e, t1);

        abcd = vaddq_u32(orig_abcd, abcd);
        e = e.wrapping_add(orig_e);

        vst1q_u32(state.as_ptr() as *mut uint32x4_t, abcd);
        state[4] = e;
    }
}
