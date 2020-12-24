// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(feature = "wedpr_f_vrf_curve25519")]

use libc::c_char;
use std::{ffi::CString, panic, ptr};
use wedpr_l_protos::generated::common;

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_vrf_curve25519")]
use wedpr_l_crypto_vrf_curve25519::WedprCurve25519Vrf;
use wedpr_l_utils::wedpr_trait::Vrf;

#[no_mangle]
pub extern "C" fn wedpr_curve25519_vrf_derive_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let encrypt_data = WedprCurve25519Vrf::derive_public_key(&private_key);
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[no_mangle]
pub extern "C" fn wedpr_curve25519_vrf_prove(
    encoded_private_key: *const c_char,
    encoded_input_string: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let input_string = c_safe_c_char_pointer_to_string!(encoded_input_string);
        let proof = match WedprCurve25519Vrf::prove(&private_key, &input_string) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        c_safe_bytes_to_c_char_pointer!(&proof.encode())
    });
    c_safe_return!(result)
}

#[no_mangle]
pub extern "C" fn wedpr_curve25519_vrf_verify(
    encoded_public_key: *const c_char,
    encoded_input_string: *const c_char,
    encoded_proof: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key =
            c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_public_key, FAILURE);
        let input_string =
            c_safe_c_char_pointer_to_string_with_error_value!(encoded_input_string, FAILURE);
        let proof_bytes = c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_proof, FAILURE);

        let proof = match WedprCurve25519Vrf::decode(&proof_bytes) {
            Ok(v) => v,
            Err(_) => {
                return FAILURE;
            }
        };
        match proof.verify(&public_key, &input_string) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

#[no_mangle]
pub extern "C" fn wedpr_curve25519_vrf_proof_to_hash(encoded_proof: *const c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let proof_bytes = c_safe_c_char_pointer_to_bytes!(encoded_proof);
        let proof = match WedprCurve25519Vrf::decode(&proof_bytes) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        let hash_bytes = match proof.proof_to_hash() {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        c_safe_bytes_to_c_char_pointer!(&hash_bytes)
    });
    c_safe_return!(result)
}

#[no_mangle]
pub extern "C" fn wedpr_curve25519_vrf_is_valid_public_key(
    encoded_public_key: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key =
            c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_public_key, FAILURE);
        match WedprCurve25519Vrf::is_valid_public_key(&public_key) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}
