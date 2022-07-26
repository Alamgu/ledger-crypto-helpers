use arrayvec::{ArrayVec};
use nanos_sdk::bindings::*;
use nanos_sdk::io::SyscallError;

use crate::internal::*;

#[derive(Clone,Debug,PartialEq)]
pub struct EdDSASignature(pub [u8; 64]);

pub fn eddsa_sign(
    path : &ArrayVec<u32, 10>,
    m: &[u8],
) -> Result<EdDSASignature, CryptographyError> {
    let mut sig:[u8;64]=[0; 64];
    with_private_key(path, |key| {
        call_c_api_function!(
            cx_eddsa_sign_no_throw(
                key,
                CX_SHA512,
                m.as_ptr(),
                m.len() as u32,
                sig.as_mut_ptr(),
                sig.len() as u32)
        )?;
        Ok(())
    })?;
    Ok(EdDSASignature(sig))
}
