use arrayvec::ArrayVec;
use core::default::Default;
use ledger_device_sdk::ecc::{ECPrivateKey, Ed25519Stream, SeedDerive};

use crate::common::*;

#[derive(Default)]
pub struct Ed25519 {
    sk: ECPrivateKey<32, 'E'>,
    ctx: Ed25519Stream,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519 {
    #[inline(never)]
    pub fn new(path: ArrayVec<u32, 10>, slip10: bool) -> Result<Ed25519, CryptographyError> {
        let mut rv = Self::default();
        rv.init(path, slip10)?;
        Ok(rv)
    }
    #[inline(never)]
    pub fn init(&mut self, path: ArrayVec<u32, 10>, slip10: bool) -> Result<(), CryptographyError> {
        self.sk = if slip10 {
            ledger_device_sdk::ecc::Ed25519::derive_from_path_slip10(&path)
        } else {
            ledger_device_sdk::ecc::Ed25519::derive_from_path(&path)
        };
        ledger_device_sdk::ecc::Ed25519::derive_from_path(&path);
        self.ctx.init(&self.sk)?;
        Ok(())
    }

    #[inline(never)]
    pub fn update(&mut self, bytes: &[u8]) {
        self.ctx.sign_update(bytes).unwrap();
    }

    #[inline(never)]
    pub fn done_with_r(&mut self) -> Result<(), CryptographyError> {
        Ok(self.ctx.sign_finalize(&self.sk)?)
    }

    // After done_with_r, we stream the message in again with "update".

    #[inline(never)]
    pub fn finalize(&mut self) -> Result<Ed25519Signature, CryptographyError> {
        self.ctx.sign_finalize(&self.sk)?;

        // And copy the signature into the output.
        let mut buf = [0; 64];

        buf.copy_from_slice(&self.ctx.signature);

        Ok(Ed25519Signature(buf))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use ledger_device_sdk::assert_eq_err as assert_eq;
    use ledger_device_sdk::testing::TestType;
    use testmacro::test_item as test;

    // Taken from https://github.com/novifinancial/ed25519-speccheck/blob/main/cases.txt

    struct TestCase {
        msg: &'static [u8],
        pbk: [u8; 32],
        sig: Ed25519Signature,
    }

    const TEST_CASES: &'static [TestCase] = &[
        TestCase {
            msg: &hex!("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6"),
            pbk: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
            sig: Ed25519Signature(hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000")),
        },
        TestCase {
            msg: &hex!("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            pbk: hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
            sig: Ed25519Signature(hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04")),
        },
        TestCase {
            msg: &hex!("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: Ed25519Signature(hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e")),
        },
        TestCase {
            msg: &hex!("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: Ed25519Signature(hex!("9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009")),
        },
        TestCase {
            msg: &hex!("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: Ed25519Signature(hex!("160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09")),
        },
        TestCase {
            msg: &hex!("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            pbk: hex!("cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"),
            sig: Ed25519Signature(hex!("21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405")),
        },
        TestCase {
            msg: &hex!("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            pbk: hex!("442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623"),
            sig: Ed25519Signature(hex!("e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514")),
        },
        TestCase {
            msg: &hex!("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            pbk: hex!("442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623"),
            sig: Ed25519Signature(hex!("8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22")),
        },
        TestCase {
            msg: &hex!("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: Ed25519Signature(hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f")),
        },
        TestCase {
            msg: &hex!("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            pbk: hex!("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"),
            sig: Ed25519Signature(hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908")),
        },
        TestCase {
            msg: &hex!("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b"),
            pbk: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            sig: Ed25519Signature(hex!("a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04")),
        },
        TestCase {
            msg: &hex!("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f"),
            pbk: hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            sig: Ed25519Signature(hex!("a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04")),
        },
    ];
    #[test]
    fn eddsa() {
        pub const PATH: [u32; 2] = ledger_device_sdk::ecc::make_bip32_path(b"m/3'/4'");
        let mut path = ArrayVec::new();
        path.try_extend_from_slice(&PATH);

        let runTest = |slip10| {
            for TestCase {
                msg,
                pbk: _,
                sig: _,
            } in TEST_CASES
            {
                let sig0 = {
                    let mut e = Ed25519::new(path.clone(), slip10).unwrap();
                    e.update(msg);
                    e.done_with_r();
                    e.update(msg);
                    e.finalize().unwrap()
                };
                let sig1 = { crate::eddsa::eddsa_sign(&path, slip10, &msg).unwrap() };

                assert_eq!(sig0.0, sig1.0);
            }
            Ok(())
        };
        runTest(false);
        runTest(true);
    }
}
