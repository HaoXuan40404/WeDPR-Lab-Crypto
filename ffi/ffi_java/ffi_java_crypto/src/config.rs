// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use wedpr_l_crypto_ecies_secp256k1::WedprSecp256k1Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
lazy_static! {
    pub static ref ECIES: WedprSecp256k1Ecies = WedprSecp256k1Ecies::default();
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
lazy_static! {
    pub static ref SIGNATURE: WedprSecp256k1Recover = WedprSecp256k1Recover::default();
}

#[cfg(feature = "wedpr_f_hash_keccak256")]
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;

#[cfg(feature = "wedpr_f_hash_keccak256")]
lazy_static! {
    pub static ref HASH: WedprKeccak256 = WedprKeccak256::default();
}

#[cfg(feature = "wedpr_f_signature_sm2")]
use wedpr_l_crypto_signature_sm2::WeDPRSm2p256v1;

#[cfg(feature = "wedpr_f_signature_sm2")]
lazy_static! {
    pub static ref SIGNATURE_SM2: WeDPRSm2p256v1 = WeDPRSm2p256v1::default();
}

#[cfg(feature = "wedpr_f_hash_sm3")]
use wedpr_l_crypto_hash_sm3::WedprSm3;

#[cfg(feature = "wedpr_f_hash_sm3")]
lazy_static! {
    pub static ref HASH_SM3: WedprSm3 = WedprSm3::default();
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
use wedpr_l_crypto_vrf_curve25519::WedprCurve25519Vrf;

#[cfg(feature = "wedpr_f_vrf_curve25519")]
lazy_static! {
    pub static ref VRF: WedprCurve25519Vrf = WedprCurve25519Vrf::default();
}
