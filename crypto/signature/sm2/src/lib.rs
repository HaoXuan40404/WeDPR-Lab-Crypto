// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM2 signature functions.
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

use wedpr_l_utils::error::WedprError;
use wedpr_l_utils::wedpr_trait::Signature;

use wedpr_l_libsm::sm2::signature::SigCtx;
use wedpr_l_libsm::sm2::signature::Signature as sm2Signature;

lazy_static! {
    /// Shared sm2 instance initialized for all functions.
    pub static ref SM2_CTX: SigCtx = SigCtx::new();
}

#[derive(Default, Debug, Clone)]
pub struct WeDPRSm2p256v1 {}

/// Implements FISCO-BCOS-compatible sm2 as a Signature instance.
/// The signature data contains two parts:
/// sig\[0..64\): signature for the message hash.
impl Signature for WeDPRSm2p256v1 {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let new_sk = match SM2_CTX.load_seckey(&private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            }
        };
        let pk = SM2_CTX.pk_from_sk(&new_sk);
        let signature: sm2Signature = SM2_CTX.sign(&msg.as_ref(), &new_sk, &pk);
        Ok(signature.bytes_encode().to_vec())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(&self, public_key: &T, msg: &T, signature: &T) -> bool {
        let pub_key = match SM2_CTX.load_pubkey(&public_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return false;
            }
        };

        let parsed_sig = match sm2Signature::bytes_decode(signature.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return false;
            }
        };
        SM2_CTX.verify(&msg.as_ref(), &pub_key, &parsed_sig)
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = SM2_CTX.new_keypair();
        let pk_raw = SM2_CTX.serialize_pubkey(&pk, false);
        let sk_raw = SM2_CTX.serialize_seckey(&sk);
        (pk_raw, sk_raw)
    }
}

impl WeDPRSm2p256v1 {
    fn sign_with_pub(
        &self,
        private_key: &[u8],
        public_key: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, WedprError> {
        let new_sk = match SM2_CTX.load_seckey(&private_key) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            }
        };
        let pk = match SM2_CTX.load_pubkey(&public_key) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            }
        };
        let signature: sm2Signature = SM2_CTX.sign(&msg, &new_sk, &pk);
        Ok(signature.bytes_encode().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2() {
        let sm2_sign = WeDPRSm2p256v1::default();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg_hash: [u8; 32] = [
            229, 45, 56, 86, 254, 135, 4, 37, 134, 235, 19, 64, 70, 172, 15, 111, 111, 120, 31, 63,
            247, 6, 86, 133, 87, 2, 175, 0, 144, 114, 119, 212,
        ];

        let (pk, sk) = sm2_sign.generate_keypair();

        let signature = sm2_sign.sign(&sk, &msg_hash.to_vec()).unwrap();

        let signature_pub = sm2_sign
            .sign_with_pub(&sk, &pk, &msg_hash.to_vec())
            .unwrap();

        assert_eq!(true, sm2_sign.verify(&pk, &msg_hash.to_vec(), &signature));
        assert_eq!(
            true,
            sm2_sign.verify(&pk, &msg_hash.to_vec(), &signature_pub)
        );
    }
}
