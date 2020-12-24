// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(feature = "wedpr_f_vrf_curve25519")]

#[cfg(feature = "wedpr_f_vrf_curve25519")]
use config::VRF;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject, string_to_bytes,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject, string_to_bytes,
};