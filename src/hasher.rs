use core::default::Default;
use core::fmt;
use core::fmt::Write;
use arrayvec::{ArrayVec};
use nanos_sdk::bindings::*;
use zeroize::{Zeroize, Zeroizing};
use base64;

pub trait Hasher<const N: usize> {
    fn new() -> Self;
    fn update(&mut self, bytes: &[u8]);
    fn finalize(&mut self) -> Zeroizing<Hash<N>>;
    fn clear(&mut self);
}

#[derive(Clone, Copy)]
pub struct Hash<const N: usize>(pub [u8; N]);

impl <const N: usize> fmt::Display for Hash<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Select a sufficiently large buf size for handling hashes of upto 64 bytes
        const OUT_BUF_SIZE: usize = (66/3)*4;
        let mut buf: [u8; OUT_BUF_SIZE] = [0; OUT_BUF_SIZE];
        let bytes_written = base64::encode_config_slice(self.0, base64::URL_SAFE_NO_PAD, &mut buf);
        let str = core::str::from_utf8(&buf[0..bytes_written]).or(Err(core::fmt::Error))?;
        write!(f, "{}", str)
    }
}

impl <const N: usize> Zeroize for Hash<N> {
    fn zeroize(&mut self) { self.0.zeroize(); }
}

impl Write for Blake2b {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // Using s directly causes segfault on qemu, so we copy.
        // Issue #5 is getting to the bottom of this and avoiding this workaround.
        let mut buffer: ArrayVec<u8, 256> = ArrayVec::new();
        match buffer.try_extend_from_slice(s.as_bytes()) {
            Ok(()) => {
                self.update(buffer.as_slice());
                Ok(())
            }
            _ => { Err(core::fmt::Error) }
        }
    }
}

#[derive(Clone, Copy)]
pub struct SHA256(cx_sha256_s);

impl Hasher<32> for SHA256 {
    fn new() -> Self {
        let mut rv = cx_sha256_s::default();
        unsafe { cx_sha256_init_no_throw(&mut rv) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_sha256_init_no_throw(&mut self.0) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_sha256_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<32>> {
        let mut rv = Zeroizing::new(Hash([0; 32]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_sha256_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}

#[derive(Clone, Copy)]
pub struct SHA512(cx_sha512_s);

impl Hasher<64> for SHA512 {
    fn new() -> SHA512 {
        let mut rv = cx_sha512_s::default();
        unsafe { cx_sha512_init_no_throw(&mut rv) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_sha512_init_no_throw(&mut self.0) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_sha512_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<64>> {
        let mut rv = Zeroizing::new(Hash([0; 64]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_sha512_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}

#[derive(Clone, Copy)]
pub struct Blake2b(cx_blake2b_s);

impl Hasher<32> for Blake2b {
    fn new() -> Self {
        let mut rv = cx_blake2b_s::default();
        unsafe { cx_blake2b_init_no_throw(&mut rv, 256) };
        Self(rv)
    }

    fn clear(&mut self) {
        unsafe { cx_blake2b_init_no_throw(&mut self.0, 256) };
    }

    fn update(&mut self, bytes: &[u8]) {
        unsafe {
            cx_hash_update(
                &mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
        }
    }

    fn finalize(&mut self) -> Zeroizing<Hash<32>> {
        let mut rv = Zeroizing::new(Hash([0; 32]));
        unsafe {
            cx_hash_final(
                &mut self.0 as *mut cx_blake2b_s as *mut cx_hash_t,
                rv.0.as_mut_ptr(),
            )
        };
        rv
    }
}
