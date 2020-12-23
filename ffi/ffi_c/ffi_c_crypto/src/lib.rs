// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of crypto, targeting C/C++
//! compatible architectures (including iOS).

#[cfg(all(feature = "wedpr_f_base64", feature = "wedpr_f_hex"))]
compile_error!("Feature wedpr_base64 and wedpr_hex can not be enable at same time!");

#[cfg(all(not(feature = "wedpr_f_base64"), not(feature = "wedpr_f_hex")))]
compile_error!("Must use feature wedpr_base64 or wedpr_hex!");

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[macro_use]
extern crate wedpr_l_macros;

#[macro_use]
extern crate lazy_static;

mod config;

use protobuf::{self, Message};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS,
};

use wedpr_l_utils::wedpr_trait::{Ecies, Hash, Signature};

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use config::ECIES;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use config::SIGNATURE;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use config::HASH;

use libc::c_char;
use std::{ffi::CString, panic, ptr};
use wedpr_l_protos::generated::common;

// C/C++ FFI: C-style interfaces will be generated.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_encrypt'.
// TODO: Add wedpr_secp256k1_ecies_encrypt_utf8 to allow non-encoded UTF8 input.
pub extern "C" fn wedpr_secp256k1_ecies_encrypt(
    encoded_public_key: *mut c_char,
    encoded_plaintext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes!(encoded_public_key);
        let encoded_message = c_safe_c_char_pointer_to_bytes!(encoded_plaintext);

        let encrypt_data = match ECIES.encrypt(&public_key, &encoded_message) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "ECIES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&encoded_message),
                    bytes_to_string(&public_key)
                );
                return ptr::null_mut();
            }
        };
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_decrypt'.
pub extern "C" fn wedpr_secp256k1_ecies_decrypt(
    encoded_private_key: *mut c_char,
    encoded_ciphertext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let ciphertext = c_safe_c_char_pointer_to_bytes!(encoded_ciphertext);

        let decrypted_data = match ECIES.decrypt(&private_key, &ciphertext) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "ECIES decrypt failed, ciphertext={}",
                    bytes_to_string(&ciphertext)
                );
                return ptr::null_mut();
            }
        };
        c_safe_bytes_to_c_char_pointer!(&decrypted_data)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_key_pair'.
pub extern "C" fn wedpr_secp256k1_gen_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (pk, sk) = SIGNATURE.generate_keypair();
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign'.
pub extern "C" fn wedpr_secp256k1_sign(
    encoded_private_key: *mut c_char,
    encoded_message_hash: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let message_hash = c_safe_c_char_pointer_to_bytes!(encoded_message_hash);

        let signature = match SIGNATURE.sign(&private_key, &message_hash) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        c_safe_bytes_to_c_char_pointer!(&signature)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify'.
pub extern "C" fn wedpr_secp256k1_verify(
    encoded_public_key: *mut c_char,
    encoded_message_hash: *mut c_char,
    encoded_signature: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key =
            c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_public_key, FAILURE);
        let message_hash =
            c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_message_hash, FAILURE);
        let signature =
            c_safe_c_char_pointer_to_bytes_with_error_value!(encoded_signature, FAILURE);

        match SIGNATURE.verify(&public_key, &message_hash, &signature) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

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
