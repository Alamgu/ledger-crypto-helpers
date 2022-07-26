use arrayvec::{CapacityError};
use core::default::Default;
use core::ops::{Deref,DerefMut};
use ledger_log::*;
use nanos_sdk::bindings::*;
use nanos_sdk::io::SyscallError;
use zeroize::{DefaultIsZeroes, Zeroizing};

/// Helper function that derives the seed over Ed25519
pub fn bip32_derive_eddsa(path: &[u32]) -> Result<[u8; 64], SyscallError> {
    // Note: os_perso_derive_node_bip32 appears to write 64 bytes for CX_CURVE_Ed25519, despite the
    // private key for ed25519 being only 32 bytes. We still need to give it the space to write to,
    // of course.
    let mut raw_key = [0u8; 64];
    trace!("Calling os_perso_derive_node_bip32 with path {:?}", path);
    unsafe {
        os_perso_derive_node_bip32(
            CX_CURVE_Ed25519,
            path.as_ptr(),
            path.len() as u32,
            raw_key.as_mut_ptr(),
            core::ptr::null_mut()
        )
    };
    trace!("Success");
    Ok(raw_key)
}

macro_rules! call_c_api_function {
    ($($call:tt)*) => {
        {
            let err = unsafe {
                $($call)*
            };
            if err != 0 {
 //               error!("Syscall errored: {:?}", SyscallError::from(err));
                Err(SyscallError::from(err))
            } else {
                Ok(())
            }
        }
    }
}

#[inline(always)]
pub fn get_pubkey_from_privkey(ec_k: &mut nanos_sdk::bindings::cx_ecfp_private_key_t, pubkey: &mut nanos_sdk::bindings::cx_ecfp_public_key_t) -> Result<(), SyscallError> {
    info!("Calling generate_pair_no_throw");
    call_c_api_function!(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, pubkey, ec_k, true))?;
    info!("Calling compress_point_no_throw");
    call_c_api_function!(cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, pubkey.W.as_mut_ptr(), pubkey.W_len))?;
    pubkey.W_len = 33;
    Ok(())
}

#[derive(Default,Copy,Clone)]
// Would like to use ZeroizeOnDrop here, but the zeroize_derive crate doesn't build. We also would
// need Zeroize on cx_ecfp_private_key_t instead of using DefaultIsZeroes; we can't implement both
// Drop and Copy.
struct PrivateKey(nanos_sdk::bindings::cx_ecfp_private_key_t);
impl DefaultIsZeroes for PrivateKey {}
impl Deref for PrivateKey {
  type Target = nanos_sdk::bindings::cx_ecfp_private_key_t;
  fn deref(&self) -> &Self::Target {
      &self.0
  }
}
impl DerefMut for PrivateKey {
  fn deref_mut(&mut self) -> &mut Self::Target {
      &mut self.0
  }
}

#[derive(Debug)]
pub enum CryptographyError {
  NoneError,
  SyscallError(SyscallError),
  CapacityError(CapacityError)
}

impl From<SyscallError> for CryptographyError {
    fn from(e: SyscallError) -> Self {
        CryptographyError::SyscallError(e)
    }
}
impl From<CapacityError> for CryptographyError {
    fn from(e: CapacityError) -> Self {
        CryptographyError::CapacityError(e)
    }
}

// #[inline(always)]
pub fn with_private_key<A>(
    path: &[u32],
    f: impl FnOnce(&mut nanos_sdk::bindings::cx_ecfp_private_key_t) -> Result<A, CryptographyError>
) -> Result<A, CryptographyError> {
    info!("Deriving path");
    let raw_key = bip32_derive_eddsa(path)?;
    let mut ec_k : Zeroizing<PrivateKey> = Default::default();
    info!("Generating key");
    call_c_api_function!(cx_ecfp_init_private_key_no_throw(
            CX_CURVE_Ed25519,
            raw_key.as_ptr(),
            32, // raw_key is 64 bytes because of system call weirdness, but we only want 32.
            (&mut ec_k).deref_mut().deref_mut() as *mut nanos_sdk::bindings::cx_ecfp_private_key_t
        ))?;
    info!("Key generated");
    f(ec_k.deref_mut().deref_mut())
}
