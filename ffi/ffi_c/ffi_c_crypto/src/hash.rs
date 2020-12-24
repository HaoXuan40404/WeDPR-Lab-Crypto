// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::wedpr_trait::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

use libc::c_char;
use std::{ffi::CString, panic, ptr};
use wedpr_l_protos::generated::common;

use protobuf::{self, Message};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash'.
// TODO: Add wedpr_keccak256_hash_utf8 to allow non-encoded UTF8 input.
pub extern "C" fn wedpr_keccak256_hash(encoded_message: *mut c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);

        let msg_hash = bytes_to_string(&HASH.hash(&message));
        c_safe_string_to_c_char_pointer!(msg_hash)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash'.
pub extern "C" fn wedpr_sm3_hash(encoded_message: *mut c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);

        let msg_hash = bytes_to_string(&HASH_SM3.hash(&message));
        c_safe_string_to_c_char_pointer!(msg_hash)
    });
    c_safe_return!(result)
}
