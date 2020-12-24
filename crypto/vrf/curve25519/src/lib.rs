// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Curve25519 vrf functions.

extern crate curve25519_dalek;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use wedpr_l_utils::wedpr_trait::{Hash, Vrf};

#[macro_use]
extern crate wedpr_l_macros;

use rand::thread_rng;
use sha3::Sha3_512;
use std::convert::TryFrom;
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, point_to_bytes, scalar_to_bytes, BASEPOINT_G1,
};
use wedpr_l_utils::error::WedprError;

extern crate rand;

// curve25519 vrf's order is 8
const ORDER: u8 = 8u8;

#[derive(PartialEq, Debug, Clone, Default)]
pub struct WedprCurve25519Vrf {
    pub gamma_param: [u8; 32],
    pub c_param: [u8; 32],
    pub s_param: [u8; 32],
}

impl Vrf for WedprCurve25519Vrf {
    fn encode(&self) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.append(&mut self.gamma_param.to_vec());
        proof.append(&mut self.c_param.to_vec());
        proof.append(&mut self.s_param.to_vec());
        proof
    }

    fn decode<T: ?Sized + AsRef<[u8]>>(proof: &T) -> Result<Self, WedprError> {
        if proof.as_ref().len() != 96 {
            return Err(WedprError::FormatError);
        }
        let mut gamma = [0u8; 32];
        gamma.copy_from_slice(&proof.as_ref()[0..32]);

        let mut c = [0u8; 32];
        c.copy_from_slice(&proof.as_ref()[32..64]);

        let mut s = [0u8; 32];
        s.copy_from_slice(&proof.as_ref()[64..96]);
        Ok(WedprCurve25519Vrf { gamma_param, c_param: c, s_param: s })
    }

    fn prove<T: ?Sized + AsRef<[u8]>>(vrf_x: &T, vrf_alpha: &str) -> Result<Self, WedprError> {
        let vrf_y = Self::derive_public_key(vrf_x);
        // let y_point = bytes_to_point(&vrf_y.as_ref())?;
        let x_scalar = Scalar::hash_from_bytes::<Sha3_512>(vrf_x.as_ref());
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut vrf_y.clone());
        hash_vec.append(&mut vrf_alpha.as_bytes().to_vec());
        let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash_vec);
        let gamma = h_point * x_scalar;
        let blinding_k = Scalar::random(&mut thread_rng());
        let base_k = *BASEPOINT_G1 * blinding_k;
        let point_k = h_point * blinding_k;
        let mut c_vec = Vec::new();
        c_vec.append(&mut hash_vec.clone());
        c_vec.append(&mut vrf_y.clone());
        c_vec.append(&mut point_to_bytes(&gamma));
        c_vec.append(&mut point_to_bytes(&base_k));
        c_vec.append(&mut point_to_bytes(&point_k));
        let c_scalar = Scalar::hash_from_bytes::<Sha3_512>(&c_vec);
        let s = blinding_k - (c_scalar * x_scalar);
        let proof = WedprCurve25519Vrf {
            gamma_param: <[u8; 32]>::try_from(point_to_bytes(&gamma)).unwrap(),
            c_param: <[u8; 32]>::try_from(scalar_to_bytes(&c_scalar)).unwrap(),
            s_param: <[u8; 32]>::try_from(scalar_to_bytes(&s)).unwrap(),
        };
        Ok(proof)
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(&self, vrf_y: &T, vrf_alpha: &str) -> bool {
        let gamma_point = bytes_to_point!(self.gamma_param.as_ref());
        let y_point = bytes_to_point!(vrf_y.as_ref());
        let c_scalar = bytes_to_scalar!(&self.c_param);
        let s_scalar = bytes_to_scalar!(&self.s_param);
        let u = (y_point * c_scalar) + (*BASEPOINT_G1 * s_scalar);
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut vrf_y.as_ref().to_vec());
        hash_vec.append(&mut vrf_alpha.as_bytes().to_vec());
        let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash_vec);
        let v = (gamma_point * c_scalar) + (h_point * s_scalar);

        let mut c_vec = Vec::new();
        c_vec.append(&mut hash_vec.clone());
        c_vec.append(&mut vrf_y.as_ref().to_vec());
        c_vec.append(&mut self.gamma_param.clone().to_vec());
        c_vec.append(&mut point_to_bytes(&u));
        c_vec.append(&mut point_to_bytes(&v));
        let expect_c_scalar = Scalar::hash_from_bytes::<Sha3_512>(&c_vec);

        if c_scalar != expect_c_scalar {
            return false;
        }
        true
    }

    fn derive_public_key<T: ?Sized + AsRef<[u8]>>(private_message: &T) -> Vec<u8> {
        let private_scalar = Scalar::hash_from_bytes::<Sha3_512>(private_message.as_ref());
        let pubkey = *BASEPOINT_G1 * private_scalar;
        point_to_bytes(&pubkey)
    }

    fn proof_to_hash(&self) -> Result<Vec<u8>, WedprError> {
        let gamma = bytes_to_point(&self.gamma_param)?;
        let base = gamma * Scalar::from(ORDER);
        let hash = WedprKeccak256::default();
        Ok(hash.hash(&point_to_bytes(&base)))
    }

    fn is_valid_public_key<T: ?Sized + AsRef<[u8]>>(public_key: &T) -> bool {
        return match bytes_to_point(&public_key.as_ref()) {
            Ok(_) => true,
            Err(_) => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vrf() {
        //        let x_scalar = Scalar::random(&mut thread_rng());
        let x = "random message".as_bytes().to_vec();
        let y = WedprCurve25519Vrf::derive_public_key(&x);
        let alpha = "test msg";
        assert_eq!(WedprCurve25519Vrf::is_valid_public_key(&y), true);
        assert_eq!(WedprCurve25519Vrf::is_valid_public_key(&x), false);

        let proof = WedprCurve25519Vrf::prove(&x, &alpha).unwrap();
        let hash_proof = proof.proof_to_hash().unwrap();
        let result = proof.verify(&y, &alpha);
        println!("hash_proof = {:?}", hash_proof);
        println!("result = {}", result);

        assert_eq!(result, true);
        let proof_err = WedprCurve25519Vrf::prove(&"error x".as_bytes().to_vec(), &alpha).unwrap();
        let result_err = proof_err.verify(&y, &alpha);
        assert_eq!(result_err, false);

        let encode = proof.encode();
        println!("encode = {:?}", encode);
        let decode = WedprCurve25519Vrf::decode(&encode).unwrap();
        let result = decode.verify(&y, &alpha);
        println!("result = {}", result);
    }
}
