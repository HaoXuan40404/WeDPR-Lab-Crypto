use jni::{
    objects::{JClass, JObject, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

use jni::sys::jbyteArray;
use wedpr_ffi_common::utils::{
    java_bytes_to_jbyte_array, java_jbytes_to_bytes,
    java_set_error_field_and_extract_jobject,
};

use wedpr_l_crypto_zkp_range_proof::{
    prove_value_range_with_blinding, verify_value_range,
};
use wedpr_l_crypto_zkp_utils::{bytes_to_point, bytes_to_scalar};

use super::get_result_jobject;

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->proveRangeProof'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_proveRangeProof(
    env: JNIEnv,
    _class: JClass,
    value: jint,
    blinding: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte array to Rust byte vector
    let blinding_bytes = match java_jbytes_to_bytes(&env, blinding) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding conversion failed",
            );
        },
    };

    // Convert bytes to scalar
    let blinding_scalar = match bytes_to_scalar(&blinding_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding scalar conversion failed",
            );
        },
    };

    // Generate the range proof
    let (proof, _) =
        prove_value_range_with_blinding(value as u64, &blinding_scalar);

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(&env, result_jobject, &proof, "proof");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->verifyRangeProof'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_verifyRangeProof(
    env: JNIEnv,
    _class: JClass,
    commitment: jbyteArray,
    proof: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte array to Rust byte vector
    let commitment_bytes = match java_jbytes_to_bytes(&env, commitment) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment conversion failed",
            );
        },
    };

    let proof_bytes = match java_jbytes_to_bytes(&env, proof) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof conversion failed",
            );
        },
    };

    // Deserialize the commitment and proof
    let commitment = match bytes_to_point(&commitment_bytes) {
        Ok(point) => point,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment deserialization failed",
            );
        },
    };

    // Verify the proof
    let result = verify_value_range(&commitment, &proof_bytes);

    java_safe_set_boolean_field!(&env, result_jobject, result, "result");
    result_jobject.into_inner()
}
