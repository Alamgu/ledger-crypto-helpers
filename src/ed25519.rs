use arrayvec::ArrayVec;
use core::default::Default;
use ledger_log::*;
use nanos_sdk::bindings::*;
use nanos_sdk::ecc::SeedDerive;
use nanos_sdk::io::SyscallError;
use zeroize::Zeroizing;

use crate::common::*;
use crate::eddsa::{
    ed25519_public_key_bytes, with_public_keys, Ed25519PublicKey, Ed25519RawPubKeyAddress,
};
use crate::hasher::*;

struct BnLock;

impl BnLock {
    fn lock() -> Result<Self, CryptographyError> {
        call_c_api_function!(cx_bn_lock(32, 0))?;
        trace!("Locking BN");
        Ok(BnLock)
    }
}

impl Drop for BnLock {
    fn drop(&mut self) {
        trace!("Unlocking BN");
        call_c_api_function!(cx_bn_unlock()).unwrap();
    }
}

#[derive(Clone, Copy)]
struct Ed25519Hash([u8; 64]);
impl Hash<64> for Ed25519Hash {
    fn new(v: [u8; 64]) -> Self {
        Ed25519Hash(v)
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}
impl Default for Ed25519Hash {
    fn default() -> Self {
        Ed25519Hash([0; 64])
    }
}
impl zeroize::DefaultIsZeroes for Ed25519Hash {}

#[derive(Clone)]
pub struct Ed25519 {
    hash: SHA512,
    path: ArrayVec<u32, 10>,
    r_pre: Zeroizing<Ed25519Hash>,
    r: [u8; 32],
}
impl Default for Ed25519 {
    fn default() -> Ed25519 {
        Ed25519 {
            hash: SHA512::new(),
            path: ArrayVec::default(),
            r_pre: Zeroizing::new(Ed25519Hash([0; 64])),
            r: [0; 32],
        }
    }
}

pub fn with_private_key<A>(
    path: &[u32],
    f: impl FnOnce(&mut nanos_sdk::ecc::ECPrivateKey<32, 'E'>) -> Result<A, CryptographyError>,
) -> Result<A, CryptographyError> {
    f(&mut nanos_sdk::ecc::Ed25519::derive_from_path(path))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519 {
    #[inline(never)]
    pub fn new(path: ArrayVec<u32, 10>) -> Result<Ed25519, CryptographyError> {
        let mut rv = Self::default();
        rv.init(path)?;
        Ok(rv)
    }
    #[inline(never)]
    pub fn init(&mut self, path: ArrayVec<u32, 10>) -> Result<(), CryptographyError> {
        self.hash.clear();

        with_private_key(&path, |key| {
            self.hash.update(&key.key[0..(key.keylength as usize)]);
            let temp: Zeroizing<Ed25519Hash> = self.hash.finalize();
            self.hash.clear();
            self.hash.update(&temp.0[32..64]);
            Ok(())
        })?;

        self.path = path;

        self.r_pre = Zeroizing::new(Ed25519Hash([0; 64]));
        self.r = [0; 32];
        Ok(())
    }

    #[inline(never)]
    pub fn update(&mut self, bytes: &[u8]) {
        self.hash.update(bytes);
    }

    #[inline(never)]
    pub fn done_with_r(&mut self) -> Result<(), CryptographyError> {
        let mut sign = 0;
        {
            let _lock = BnLock::lock();
            trace!("done_with_r lock");
            let mut r = CX_BN_FLAG_UNSET;
            // call_c_api_function!( cx_bn_lock(32,0) )?;
            trace!("ping");
            self.r_pre = self.hash.finalize();
            self.r_pre.0.reverse();

            // Make r_pre into a BN
            call_c_api_function!(cx_bn_alloc_init(
                &mut r as *mut cx_bn_t,
                64,
                self.r_pre.0.as_ptr(),
                self.r_pre.0.len() as u32
            ))?;
            trace!("ping");

            let mut ed_p = cx_ecpoint_t::default();
            // Get the generator for Ed25519's curve
            call_c_api_function!(cx_ecpoint_alloc(
                &mut ed_p as *mut cx_ecpoint_t,
                CX_CURVE_Ed25519
            ))?;
            trace!("ping");
            call_c_api_function!(cx_ecdomain_generator_bn(CX_CURVE_Ed25519, &mut ed_p))?;
            trace!("ping");

            // Multiply r by generator, store in ed_p
            call_c_api_function!(cx_ecpoint_scalarmul_bn(&mut ed_p, r))?;
            trace!("ping");

            // and copy/compress it to self.r
            call_c_api_function!(cx_ecpoint_compress(
                &ed_p,
                self.r.as_mut_ptr(),
                self.r.len() as u32,
                &mut sign
            ))?;
            trace!("ping");
        }

        trace!("ping");
        // and do the mandated byte order and bit twiddling.
        self.r.reverse();
        self.r[31] |= if sign != 0 { 0x80 } else { 0x00 };
        trace!("ping");

        // self.r matches the reference algorithm at this point.

        // Start calculating s.

        self.hash.clear();
        trace!("ping");
        self.hash.update(&self.r);
        trace!("ping");

        let path_tmp = self.path.clone();
        trace!("ping");
        with_public_keys::<_, CryptographyError, _, _>(
            &path_tmp,
            |key: &Ed25519PublicKey, _: &Ed25519RawPubKeyAddress| {
                // Note: public key has a byte in front of it in W, from how the ledger's system call
                // works; it's not for ed25519.
                trace!("ping");
                self.hash.update(ed25519_public_key_bytes(key));
                Ok(())
            },
        )?;
        Ok(())
    }

    // After done_with_r, we stream the message in again with "update".

    #[inline(never)]
    pub fn finalize(&mut self) -> Result<Ed25519Signature, CryptographyError> {
        // Need to make a variable for this.hash so that the closure doesn't capture all of self,
        // including self.path
        let hash_ref = &mut self.hash;
        let (h_a, _lock, ed25519_order) = with_private_key(&self.path, |key| {
            let _lock = BnLock::lock();
            trace!("finalize lock");

            let mut h_scalar: Zeroizing<Ed25519Hash> = hash_ref.finalize();

            h_scalar.0.reverse();

            // Make k into a BN
            let mut h_scalar_bn = CX_BN_FLAG_UNSET;
            call_c_api_function!(cx_bn_alloc_init(
                &mut h_scalar_bn as *mut cx_bn_t,
                64,
                h_scalar.0.as_ptr(),
                h_scalar.0.len() as u32
            ))?;

            // Get the group order
            let mut ed25519_order = CX_BN_FLAG_UNSET;
            call_c_api_function!(cx_bn_alloc(&mut ed25519_order, 64))?;
            call_c_api_function!(cx_ecdomain_parameter_bn(
                CX_CURVE_Ed25519,
                CX_CURVE_PARAM_Order,
                ed25519_order
            ))?;

            // Generate the hashed private key
            let mut rv = CX_BN_FLAG_UNSET;
            hash_ref.clear();
            hash_ref.update(&key.key[0..(key.keylength as usize)]);
            let mut temp: Zeroizing<Ed25519Hash> = hash_ref.finalize();

            // Bit twiddling for ed25519
            temp.0[0] &= 248;
            temp.0[31] &= 63;
            temp.0[31] |= 64;

            let key_slice = &mut temp.0[0..32];

            key_slice.reverse();
            let mut key_bn = CX_BN_FLAG_UNSET;

            // Load key into bn
            call_c_api_function!(cx_bn_alloc_init(
                &mut key_bn as *mut cx_bn_t,
                64,
                key_slice.as_ptr(),
                key_slice.len() as u32
            ))?;
            hash_ref.clear();

            call_c_api_function!(cx_bn_alloc(&mut rv, 64))?;

            // multiply h_scalar_bn by key_bn
            call_c_api_function!(cx_bn_mod_mul(rv, key_bn, h_scalar_bn, ed25519_order))?;

            // Destroy the private key, so it doesn't leak from with_private_key even in the bn
            // area. temp will zeroize on drop already.
            call_c_api_function!(cx_bn_destroy(&mut key_bn))?;
            Ok((rv, _lock, ed25519_order))
        })?;

        // Reload the r value into the bn area
        let mut r = CX_BN_FLAG_UNSET;
        call_c_api_function!(cx_bn_alloc_init(
            &mut r as *mut cx_bn_t,
            64,
            self.r_pre.0.as_ptr(),
            self.r_pre.0.len() as u32
        ))?;

        // finally, compute s:
        let mut s = CX_BN_FLAG_UNSET;
        call_c_api_function!(cx_bn_alloc(&mut s, 64))?;
        call_c_api_function!(cx_bn_mod_add(s, h_a, r, ed25519_order))?;

        // and copy s back to normal memory to return.
        let mut s_bytes = [0; 32];
        call_c_api_function!(cx_bn_export(s, s_bytes.as_mut_ptr(), s_bytes.len() as u32))?;

        s_bytes.reverse();

        // And copy the signature into the output.
        let mut buf = [0; 64];

        buf[..32].copy_from_slice(&self.r);

        buf[32..].copy_from_slice(&s_bytes);

        Ok(Ed25519Signature(buf))
    }
}
