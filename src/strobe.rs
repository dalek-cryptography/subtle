//! Minimal implementatation of (parts of) Strobe.

use keccak;

/// Strobe R value; security level 128 is hardcoded
const STROBE_R: u8 = 166;

const FLAG_I: u8 = 1 << 0;
const FLAG_A: u8 = 1 << 1;
const FLAG_C: u8 = 1 << 2;
const FLAG_T: u8 = 1 << 3;
const FLAG_M: u8 = 1 << 4;
const FLAG_K: u8 = 1 << 5;

/// A Strobe context for the 128-bit security level.
///
/// Only `meta-AD`, `AD`, and `PRF` operations are supported.
pub struct Strobe128 {
    state: [u8; 200],
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,
}

impl Strobe128 {
    pub fn new(protocol_label: &[u8]) -> Strobe128 {
        let initial_state = {
            let mut st = [0u8; 200];
            st[0..6].copy_from_slice(&[1, STROBE_R + 2, 1, 0, 1, 96]);
            st[6..18].copy_from_slice(b"STROBEv1.0.2");
            keccak::f1600(unsafe { ::std::mem::transmute(&mut st) });

            st
        };

        let mut strobe = Strobe128 {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };

        strobe.meta_ad(protocol_label, false);

        strobe
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data, false);
    }

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data, false);
    }

    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data, false);
    }
}

impl Strobe128 {
    fn run_f(&mut self) {
        self.state[self.pos as usize] ^= self.pos_begin;
        self.state[(self.pos + 1) as usize] ^= 0x04;
        self.state[(STROBE_R + 1) as usize] ^= 0x80;
        keccak::f1600(unsafe { ::std::mem::transmute(&mut self.state) });
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn absorb(&mut self, data: &[u8], force_f: bool) {
        for byte in data {
            self.state[self.pos as usize] ^= byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    fn squeeze(&mut self, data: &mut [u8], force_f: bool) {
        for byte in data {
            *byte = self.state[self.pos as usize];
            self.state[self.pos as usize] = 0;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    fn begin_op(&mut self, flags: u8, more: bool) {
        // Check if we're continuing an operation
        if more {
            assert_eq!(
                self.cur_flags, flags,
                "You tried to continue op {:#b} but changed flags to {:#b}",
                self.cur_flags, flags,
            );
            return;
        }

        // Skip adjusting direction information (we just use AD, PRF)

        // Force running F if C or K is set
        let force_f = 0 != (flags & (FLAG_C | FLAG_K));

        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;

        self.absorb(&[old_begin, flags], force_f);
    }
}
