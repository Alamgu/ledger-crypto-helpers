use core::default::Default;
use core::fmt;
use ledger_log::*;
use nanos_sdk::bindings::*;
use nanos_sdk::io::SyscallError;

use crate::internal::*;

pub fn with_public_keys<V, A:Address<A>>(
  path: &[u32],
  f: impl FnOnce(&nanos_sdk::bindings::cx_ecfp_public_key_t, &A) -> Result<V, CryptographyError>
) -> Result<V, CryptographyError> {
    let mut pubkey = Default::default();
    with_private_key(path, |ec_k| {
        info!("Getting private key");
        get_pubkey_from_privkey(ec_k, &mut pubkey)?;
        Ok(())
    })?;
    let pkh = <A as Address<A>>::get_address(&pubkey)?;
    f(&pubkey, &pkh)
}

pub fn public_key_bytes(key: &nanos_sdk::bindings::cx_ecfp_public_key_t) -> &[u8] {
    &key.W[1..33]
}

// Target chain's notion of an address and how to format one.

pub trait Address<A>: fmt::Display {
    fn get_address(key: &nanos_sdk::bindings::cx_ecfp_public_key_t) -> Result<A, SyscallError>;
}

pub struct PKH(pub [u8; 20]);

impl Address<PKH> for PKH {
    fn get_address(key: &nanos_sdk::bindings::cx_ecfp_public_key_t) -> Result<Self, SyscallError> {
        let mut public_key_hash = [0; 32];
        let key_bytes = public_key_bytes(key);
        unsafe {
            let _len: size_t = cx_hash_sha256(
                key_bytes.as_ptr(),
                key_bytes.len() as u32,
                public_key_hash.as_mut_ptr(),
                public_key_hash.len() as u32,
            );
        }
        let mut rv=PKH([0; 20]);
        rv.0.clone_from_slice(&public_key_hash[0..20]);
        Ok(rv)
    }
}

impl fmt::Display for PKH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")?;
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub struct PubKey(cx_ecfp_public_key_t);

impl Address<PubKey> for PubKey {
    fn get_address(key: &nanos_sdk::bindings::cx_ecfp_public_key_t) -> Result<Self, SyscallError> {
        Ok(PubKey(*key))
    }
}
impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HexSlice(&self.0.W[1..self.0.W_len as usize]))
    }
}

struct HexSlice<'a>(&'a [u8]);

// You can choose to implement multiple traits, like Lower and UpperHex
impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want to pad the value or have spaces inbetween, etc.
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

extern "C" {
  pub fn cx_ecfp_decode_sig_der(input: *const u8, input_len: size_t,
      max_size: size_t,
      r: *mut *const u8, r_len: *mut size_t,
      s: *mut *const u8, s_len: *mut size_t,
      ) -> u32;
}
