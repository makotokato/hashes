#![allow(unused_assignments)]

use consts::K32;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32,
};

// Some NEON simd functions are missing.
#[inline(always)]
unsafe fn vld1q_u32(mem: *const uint32x4_t) -> uint32x4_t {
    core::ptr::read_unaligned(mem)
}

#[inline]
unsafe fn vst1q_u32(mem: *mut uint32x4_t, value: uint32x4_t) {
    core::ptr::write_unaligned(mem, value);
}

#[inline]
unsafe fn vrev32q_u8(value: uint32x4_t) -> uint32x4_t {
    let ret: uint32x4_t;
    asm!("rev32 $0.16b, $1.16b" : "=w"(ret) : "w"(value) :);
    ret
}

macro_rules! round {
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr, $w0:expr, $w1:expr) => {
        let k = vld1q_u32(K32[$n * 4..].as_ptr() as *const uint32x4_t);
        let t = vaddq_u32($a, k);
        let wt = $w0;
        $w0 = vsha256hq_u32($w0, $w1, t);
        $w1 = vsha256h2q_u32($w1, wt, t);
        if $n < 12 {
            $a = vsha256su0q_u32($a, $b);
            $a = vsha256su1q_u32($a, $c, $d);
        }
    };
}

/// Process a block with the SHA-256 algorithm.
///
pub fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    unsafe {
        let h0 = vld1q_u32(state.as_ptr() as *const uint32x4_t);
        let h1 = vld1q_u32(state[4..].as_ptr() as *const uint32x4_t);
        let mut w0 = h0;
        let mut w1 = h1;

        let mut a = vld1q_u32(block[0..].as_ptr() as *const uint32x4_t);
        let mut b = vld1q_u32(block[16..].as_ptr() as *const uint32x4_t);
        let mut c = vld1q_u32(block[32..].as_ptr() as *const uint32x4_t);
        let mut d = vld1q_u32(block[48..].as_ptr() as *const uint32x4_t);
        a = vrev32q_u8(a);
        b = vrev32q_u8(b);
        c = vrev32q_u8(c);
        d = vrev32q_u8(d);

        round!(0, a, b, c, d, w0, w1);
        round!(1, b, c, d, a, w0, w1);
        round!(2, c, d, a, b, w0, w1);
        round!(3, d, a, b, c, w0, w1);
        round!(4, a, b, c, d, w0, w1);
        round!(5, b, c, d, a, w0, w1);
        round!(6, c, d, a, b, w0, w1);
        round!(7, d, a, b, c, w0, w1);
        round!(8, a, b, c, d, w0, w1);
        round!(9, b, c, d, a, w0, w1);
        round!(10, c, d, a, b, w0, w1);
        round!(11, d, a, b, c, w0, w1);
        round!(12, a, b, c, d, w0, w1);
        round!(13, b, c, d, a, w0, w1);
        round!(14, c, d, a, b, w0, w1);
        round!(15, d, a, b, c, w0, w1);

        vst1q_u32(state.as_mut_ptr() as *mut uint32x4_t, vaddq_u32(h0, w0));
        vst1q_u32(
            state[4..].as_mut_ptr() as *mut uint32x4_t,
            vaddq_u32(h1, w1),
        );
    }
}
