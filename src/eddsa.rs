use arrayvec::ArrayVec;
use nanos_sdk::bindings::*;
use nanos_sdk::ecc::*;
use nanos_sdk::io::SyscallError;

use crate::common::*;

#[derive(Clone, Debug, PartialEq)]
pub struct EdDSASignature(pub [u8; 64]);

pub type Ed25519PublicKey = ECPublicKey<65, 'E'>;

pub fn eddsa_sign(
    path: &ArrayVec<u32, 10>,
    slip10: bool,
    m: &[u8],
) -> Result<EdDSASignature, CryptographyError> {
    with_private_key(path, slip10, |k| eddsa_sign_int(k, m))
}

pub fn eddsa_sign_int(
    privkey: &ECPrivateKey<32, 'E'>,
    m: &[u8],
) -> Result<EdDSASignature, CryptographyError> {
    let sig = privkey.sign(m)?;
    Ok(EdDSASignature(sig.0))
}

pub fn with_private_key<A, E>(
    path: &[u32],
    slip10: bool,
    f: impl FnOnce(&mut nanos_sdk::ecc::ECPrivateKey<32, 'E'>) -> Result<A, E>,
) -> Result<A, E> {
    if slip10 {
        f(&mut ed25519_derive_from_path_slip10(path))
    } else {
        f(&mut nanos_sdk::ecc::Ed25519::derive_from_path(path))
    }
}

pub fn with_public_keys<V, E, A: Address<A, Ed25519PublicKey>, F>(
    path: &[u32],
    slip10: bool,
    f: F,
) -> Result<V, E>
where
    E: From<CryptographyError>,
    F: FnOnce(&nanos_sdk::ecc::ECPublicKey<65, 'E'>, &A) -> Result<V, E>,
{
    with_private_key(path, slip10, |k| with_public_keys_int(k, f))
}

pub fn with_public_keys_int<V, E, A: Address<A, Ed25519PublicKey>, F>(
    privkey: &ECPrivateKey<32, 'E'>,
    f: F,
) -> Result<V, E>
where
    E: From<CryptographyError>,
    F: FnOnce(&nanos_sdk::ecc::ECPublicKey<65, 'E'>, &A) -> Result<V, E>,
{
    let mut pubkey = privkey
        .public_key()
        .map_err(Into::<CryptographyError>::into)?;
    call_c_api_function!(cx_edwards_compress_point_no_throw(
        CX_CURVE_Ed25519,
        pubkey.pubkey.as_mut_ptr(),
        pubkey.keylength as u32
    ))
    .map_err(Into::<CryptographyError>::into)?;
    pubkey.keylength = 33;
    let pkh = <A as Address<A, Ed25519PublicKey>>::get_address(&pubkey)
        .map_err(Into::<CryptographyError>::into)?;
    f(&pubkey, &pkh)
}

pub struct Ed25519RawPubKeyAddress(nanos_sdk::ecc::ECPublicKey<65, 'E'>);

impl Address<Ed25519RawPubKeyAddress, nanos_sdk::ecc::ECPublicKey<65, 'E'>>
    for Ed25519RawPubKeyAddress
{
    fn get_address(key: &nanos_sdk::ecc::ECPublicKey<65, 'E'>) -> Result<Self, SyscallError> {
        Ok(Ed25519RawPubKeyAddress(key.clone()))
    }
    fn get_binary_address(&self) -> &[u8] {
        ed25519_public_key_bytes(&self.0)
    }
}
impl core::fmt::Display for Ed25519RawPubKeyAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", HexSlice(&self.0.pubkey[1..self.0.keylength]))
    }
}

pub fn ed25519_public_key_bytes(key: &Ed25519PublicKey) -> &[u8] {
    &key.pubkey[1..33]
}

fn ed25519_derive_from_path_slip10(path: &[u32]) -> ECPrivateKey<32, 'E'> {
    let mut tmp = [0; 96];
    let seed_key: &mut [u8; 12] = &mut [0; 12];
    seed_key.copy_from_slice(b"ed25519 seed");
    unsafe {
        os_perso_derive_node_with_seed_key(
            HDW_ED25519_SLIP10,
            CurvesId::Ed25519 as u8,
            path.as_ptr(),
            path.len() as u32,
            tmp.as_mut_ptr(),
            core::ptr::null_mut(),
            seed_key.as_mut_ptr(),
            12,
        );
    }
    let mut sk = ECPrivateKey::new(CurvesId::Ed25519);
    let keylen = sk.key.len();
    sk.key.copy_from_slice(&tmp[..keylen]);
    tmp.copy_from_slice(&[0; 96]);
    sk
}
