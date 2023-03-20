use arrayvec::ArrayVec;
use core::default::Default;
use ledger_log::*;
use nanos_sdk::bindings::*;
use nanos_sdk::io::SyscallError;
use zeroize::Zeroizing;

use crate::common::*;
use crate::eddsa::{
    ed25519_public_key_bytes, with_private_key, with_public_keys, Ed25519PublicKey,
    Ed25519RawPubKeyAddress,
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
    slip10: bool,
}
impl Default for Ed25519 {
    fn default() -> Ed25519 {
        Ed25519 {
            hash: SHA512::new(),
            path: ArrayVec::default(),
            r_pre: Zeroizing::new(Ed25519Hash([0; 64])),
            r: [0; 32],
            slip10: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519 {
    #[inline(never)]
    pub fn new(path: ArrayVec<u32, 10>, slip10: bool) -> Result<Ed25519, CryptographyError> {
        let mut rv = Self::default();
        rv.slip10 = slip10;
        rv.init(path)?;
        Ok(rv)
    }
    #[inline(never)]
    pub fn init(&mut self, path: ArrayVec<u32, 10>) -> Result<(), CryptographyError> {
        self.hash.clear();

        with_private_key(&path, self.slip10, |key| {
            self.hash.update(&key.key[0..(key.keylength as usize)]);
            let temp: Zeroizing<Ed25519Hash> = self.hash.finalize();
            self.hash.clear();
            self.hash.update(&temp.0[32..64]);
            Ok::<(), CryptographyError>(())
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
            self.slip10,
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
        let (h_a, _lock, ed25519_order) = with_private_key(&self.path, self.slip10, |key| {
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
            Ok::<_, CryptographyError>((rv, _lock, ed25519_order))
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

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use nanos_sdk::assert_eq_err as assert_eq;
    use nanos_sdk::testing::TestType;
    use testmacro::test_item as test;

    // Taken from https://github.com/novifinancial/ed25519-speccheck/blob/main/cases.txt

    struct TestCase {
        msg: &'static [u8],
        pbk: [u8; 32],
        sig: [u8; 64],
    }

    const TEST_CASES: &'static [TestCase] = &[
        TestCase {
            msg: &hex!("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6"),
            pbk: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
            sig: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"),
        },
        TestCase {
            msg: &hex!("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            pbk: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
            sig: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
        },
        TestCase {
            msg: &hex!("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"),
        },
        TestCase {
            msg: &hex!("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: hex!("9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"),
        },
        TestCase {
            msg: &hex!("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: hex!("160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"),
        },
        TestCase {
            msg: &hex!("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: hex!("21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"),
        },
        TestCase {
            msg: &hex!("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            pbk: hex!("442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623"),
            sig: hex!("e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"),
        },
        TestCase {
            msg: &hex!("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            pbk: hex!("442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623"),
            sig: hex!("8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"),
        },
        TestCase {
            msg: &hex!("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"),
        },
        TestCase {
            msg: &hex!("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"),
        },
        TestCase {
            msg: &hex!("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b"),
            pbk: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            sig: hex!("a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
        },
        TestCase {
            msg: &hex!("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f"),
            pbk: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            sig: hex!("a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
        },
    ];
    #[test]
    fn eddsa() {}
}
