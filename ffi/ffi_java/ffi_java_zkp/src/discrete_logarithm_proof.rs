use curve25519_dalek::Scalar;
use jni::{
    objects::{JClass, JObject, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

use jni::sys::jbyteArray;
use wedpr_ffi_common::utils::{
    self, java_bytes_to_jbyte_array, java_jbytes_to_bytes,
    java_set_error_field_and_extract_jobject,
};

use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    coordinator_prove_multi_sum_relationship_final,
    coordinator_prove_multi_sum_relationship_setup, prove_knowledge_proof,
    prove_multi_sum_relationship, prove_value_equality_relationship_proof,
    receiver_prove_multi_sum_relationship_final,
    receiver_prove_multi_sum_relationship_setup,
    sender_prove_multi_sum_relationship_final,
    sender_prove_multi_sum_relationship_setup, verify_knowledge_proof,
    verify_multi_sum_relationship, verify_value_equality_relationship_proof,
};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, scalar_to_bytes, Deserialize,
    KnowledgeProof, Serialize, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;

use super::get_result_jobject;

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->proveKnowledgeProof'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_proveKnowledgeProof(
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

    // Generate the knowledge proof
    let proof = prove_knowledge_proof(
        value as u64,
        &blinding_scalar,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    // Serialize the proof to bytes
    let proof_bytes = proof.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &proof_bytes,
        "proof"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->verifyKnowledgeProof'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_verifyKnowledgeProof(
    env: JNIEnv,
    _class: JClass,
    commitment_jbytes: jbyteArray,
    proof_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte array to Rust byte vector
    let commitment_bytes = match java_jbytes_to_bytes(&env, commitment_jbytes) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment conversion failed",
            );
        },
    };

    let commitment = match bytes_to_point(&commitment_bytes) {
        Ok(point) => point,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment conversion failed",
            );
        },
    };

    let proof_bytes = match java_jbytes_to_bytes(&env, proof_jbytes) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof conversion failed",
            );
        },
    };

    // Deserialize the proof
    let proof = match wedpr_l_crypto_zkp_utils::KnowledgeProof::deserialize(
        &proof_bytes,
    ) {
        Ok(proof) => proof,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof deserialization failed",
            );
        },
    };

    // Verify the proof
    let result = match verify_knowledge_proof(
        &commitment,
        &proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    ) {
        Ok(result) => result,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof verification failed",
            );
        },
    };

    java_safe_set_boolean_field!(&env, result_jobject, result, "result");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->proveValueEqualityRelationshipProof'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_proveValueEqualityRelationshipProof(
    env: JNIEnv,
    _class: JClass,
    value1: jint,
    blinding1: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let blinding1_bytes = match java_jbytes_to_bytes(&env, blinding1) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding1 conversion failed",
            );
        },
    };

    // Convert bytes to scalars
    let blinding1_scalar = match bytes_to_scalar(&blinding1_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding1 scalar conversion failed",
            );
        },
    };

    // Generate the value equality relationship proof
    let proof = prove_value_equality_relationship_proof(
        value1 as u64,
        &blinding1_scalar,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    // Serialize the proof to bytes
    let proof_bytes = proof.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &proof_bytes,
        "proof"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->verifyValueEqualityRelationshipProof'
/// .
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_verifyValueEqualityRelationshipProof(
    env: JNIEnv,
    _class: JClass,
    value1: jint,
    commitment1_jbytes: jbyteArray,
    proof_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let commitment1_bytes = match java_jbytes_to_bytes(&env, commitment1_jbytes)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment1 conversion failed",
            );
        },
    };

    let proof_bytes = match java_jbytes_to_bytes(&env, proof_jbytes) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof conversion failed",
            );
        },
    };

    // Deserialize the commitments and proof
    let commitment1 = match bytes_to_point(&commitment1_bytes) {
        Ok(point) => point,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Commitment1 deserialization failed",
            );
        },
    };

    let proof = match wedpr_l_crypto_zkp_utils::ValueEqualityProof::deserialize(
        &proof_bytes,
    ) {
        Ok(proof) => proof,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof deserialization failed",
            );
        },
    };

    // Verify the proof
    let result = match verify_value_equality_relationship_proof(
        value1 as u64,
        &commitment1,
        &proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    ) {
        Ok(result) => result,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof verification failed",
            );
        },
    };

    java_safe_set_boolean_field!(&env, result_jobject, result, "result");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->senderProveMultiSumRelationshipSetup'
/// .
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_senderProveMultiSumRelationshipSetup(
    env: JNIEnv,
    _class: JClass,
    values: jint,
    blindings: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let blindings_bytes = match java_jbytes_to_bytes(&env, blindings) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blindings conversion failed",
            );
        },
    };

    // Convert bytes to scalars
    let blinding_scalar = match bytes_to_scalar(&blindings_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding scalar conversion failed",
            );
        },
    };

    // Generate the setup proof
    let (private, public) = sender_prove_multi_sum_relationship_setup(
        values as u64,
        &blinding_scalar,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    // Serialize the proof to bytes
    let private_bytes = private.serialize();
    let public_bytes = public.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &private_bytes,
        "privatePart"
    );
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &public_bytes,
        "publicPart"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->senderProveMultiSumRelationshipFinal'
/// .
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_senderProveMultiSumRelationshipFinal(
    env: JNIEnv,
    _class: JClass,
    values: jint,
    blindings: jbyteArray,
    proof_secret: jbyteArray,
    check: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let blindings_bytes = match java_jbytes_to_bytes(&env, blindings) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blindings conversion failed",
            );
        },
    };

    let proof_secret_bytes = match java_jbytes_to_bytes(&env, proof_secret) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof secret conversion failed",
            );
        },
    };

    let check_bytes = match java_jbytes_to_bytes(&env, check) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check conversion failed",
            );
        },
    };

    // Convert bytes to scalars
    let blinding_scalar = match bytes_to_scalar(&blindings_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding scalar conversion failed",
            );
        },
    };

    let proof_secret_scalar = match wedpr_l_crypto_zkp_utils::SenderRelationshipProofSetupPrivate::deserialize(&proof_secret_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof secret scalar conversion failed",
            );
        }
    };

    let check_scalar = match bytes_to_scalar(&check_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check scalar conversion failed",
            );
        },
    };

    // Generate the final proof
    let public = sender_prove_multi_sum_relationship_final(
        values as u64,
        &blinding_scalar,
        &proof_secret_scalar,
        &check_scalar,
    );

    // Serialize the proof to bytes
    let public_bytes = public.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &public_bytes,
        "publicPart"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.
/// NativeInterface->receiverProveMultiSumRelationshipSetup'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_receiverProveMultiSumRelationshipSetup(
    env: JNIEnv,
    _class: JClass,
    values: jint,
    blindings: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let blindings_bytes = match java_jbytes_to_bytes(&env, blindings) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blindings conversion failed",
            );
        },
    };

    // Convert bytes to scalars
    let blinding_scalar = match bytes_to_scalar(&blindings_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding scalar conversion failed",
            );
        },
    };

    // Generate the setup proof
    let (private, public) = receiver_prove_multi_sum_relationship_setup(
        values as u64,
        &blinding_scalar,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    // Serialize the proof to bytes
    let private_bytes = private.serialize();
    let public_bytes = public.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &private_bytes,
        "privatePart"
    );
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &public_bytes,
        "publicPart"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.
/// NativeInterface->receiverProveMultiSumRelationshipFinal'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_receiverProveMultiSumRelationshipFinal(
    env: JNIEnv,
    _class: JClass,
    blindings: jbyteArray,
    proof_secret: jbyteArray,
    check: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let blindings_bytes = match java_jbytes_to_bytes(&env, blindings) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blindings conversion failed",
            );
        },
    };

    let proof_secret_bytes = match java_jbytes_to_bytes(&env, proof_secret) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof secret conversion failed",
            );
        },
    };

    let check_bytes = match java_jbytes_to_bytes(&env, check) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check conversion failed",
            );
        },
    };

    // Convert bytes to scalars
    let blinding_scalar = match bytes_to_scalar(&blindings_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Blinding scalar conversion failed",
            );
        },
    };

    let proof_secret_scalar = match wedpr_l_crypto_zkp_utils::ReceiverRelationshipProofSetupPrivate::deserialize(&proof_secret_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof secret scalar conversion failed",
            );
        }
    };

    let check_scalar = match bytes_to_scalar(&check_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check scalar conversion failed",
            );
        },
    };

    // Generate the final proof
    let public = receiver_prove_multi_sum_relationship_final(
        &blinding_scalar,
        &proof_secret_scalar,
        &check_scalar,
    );

    // Serialize the proof to bytes
    let public_bytes = public.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &public_bytes,
        "publicPart"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.
/// NativeInterface->coordinatorProveMultiSumRelationshipSetup'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_coordinatorProveMultiSumRelationshipSetup(
    env: JNIEnv,
    _class: JClass,
    sender_setup_lists: jbyteArray,
    receiver_setup_lists: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let sender_setup_bytes =
        match java_jbytes_to_bytes(&env, sender_setup_lists) {
            Ok(bytes) => bytes,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Sender setup lists conversion failed",
                );
            },
        };

    let receiver_setup_bytes =
        match java_jbytes_to_bytes(&env, receiver_setup_lists) {
            Ok(bytes) => bytes,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Receiver setup lists conversion failed",
                );
            },
        };

    // Deserialize setup lists
    let sender_setup = match wedpr_l_crypto_zkp_utils::SenderRelationshipProofSetupPublicList::deserialize(&sender_setup_bytes) {
        Ok(setup) => setup,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Sender setup lists deserialization failed",
            );
        }
    };

    let receiver_setup = match wedpr_l_crypto_zkp_utils::ReceiverRelationshipProofSetupPublicList::deserialize(&receiver_setup_bytes) {
        Ok(setup) => setup,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Receiver setup lists deserialization failed",
            );
        }
    };

    // Generate the setup proof
    let check = coordinator_prove_multi_sum_relationship_setup(
        &sender_setup.sender_setup_list,
        &receiver_setup.receiver_setup_list,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    // Serialize the proof to bytes
    let check_bytes = scalar_to_bytes(&check);

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &check_bytes,
        "check"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.
/// NativeInterface->coordinatorProveMultiSumRelationshipFinal'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_coordinatorProveMultiSumRelationshipFinal(
    env: JNIEnv,
    _class: JClass,
    check: jbyteArray,
    sender_proofs: jbyteArray,
    receiver_proofs: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let check_bytes = match java_jbytes_to_bytes(&env, check) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check conversion failed",
            );
        },
    };

    let sender_proofs_bytes = match java_jbytes_to_bytes(&env, sender_proofs) {
        Ok(bytes) => bytes,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Sender proofs conversion failed",
            );
        },
    };

    let receiver_proofs_bytes =
        match java_jbytes_to_bytes(&env, receiver_proofs) {
            Ok(bytes) => bytes,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Receiver proofs conversion failed",
                );
            },
        };

    // Deserialize proofs
    let check_scalar = match bytes_to_scalar(&check_bytes) {
        Ok(scalar) => scalar,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Check scalar conversion failed",
            );
        },
    };

    let sender_proofs = match wedpr_l_crypto_zkp_utils::SenderRelationshipProofFinalPublicList::deserialize(&sender_proofs_bytes) {
        Ok(proofs) => proofs,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Sender proofs deserialization failed",
            );
        }
    };

    let receiver_proofs = match wedpr_l_crypto_zkp_utils::ReceiverRelationshipProofFinalPublicList::deserialize(&receiver_proofs_bytes) {
        Ok(proofs) => proofs,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Receiver proofs deserialization failed",
            );
        }
    };

    // Generate the final proof
    let proof = coordinator_prove_multi_sum_relationship_final(
        &check_scalar,
        &sender_proofs.sender_final_list,
        &receiver_proofs.receiver_final_list,
    );

    // Serialize the proof to bytes
    let proof_bytes = proof.serialize();

    // Convert Rust byte vector to Java byte array
    java_safe_set_byte_array_field!(
        &env,
        result_jobject,
        &proof_bytes,
        "proof"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->verifyMultiSumRelationship'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_verifyMultiSumRelationship(
    env: JNIEnv,
    _class: JClass,
    input_commitments: jbyteArray,
    output_commitments: jbyteArray,
    proof: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&env);

    // Convert Java byte arrays to Rust byte vectors
    let input_commitments_bytes =
        match java_jbytes_to_bytes(&env, input_commitments) {
            Ok(bytes) => bytes,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Input commitments conversion failed",
                );
            },
        };

    let output_commitments_bytes =
        match java_jbytes_to_bytes(&env, output_commitments) {
            Ok(bytes) => bytes,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Output commitments conversion failed",
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

    // Deserialize commitments and proof
    let input_commitments =
        match wedpr_l_crypto_zkp_utils::Commitments::deserialize(
            &input_commitments_bytes,
        ) {
            Ok(commitments) => commitments,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Input commitments deserialization failed",
                );
            },
        };

    let output_commitments =
        match wedpr_l_crypto_zkp_utils::Commitments::deserialize(
            &output_commitments_bytes,
        ) {
            Ok(commitments) => commitments,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &env,
                    &result_jobject,
                    "Output commitments deserialization failed",
                );
            },
        };

    let proof = match wedpr_l_crypto_zkp_utils::RelationshipProof::deserialize(
        &proof_bytes,
    ) {
        Ok(proof) => proof,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof deserialization failed",
            );
        },
    };

    // Verify the proof
    let result = match verify_multi_sum_relationship(
        &input_commitments.commitments,
        &output_commitments.commitments,
        &proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    ) {
        Ok(result) => result,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &env,
                &result_jobject,
                "Proof verification failed",
            );
        },
    };

    java_safe_set_boolean_field!(&env, result_jobject, result, "result");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->computeCommitment'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_computeCommitment(
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

    // Compute the commitment
    let commitment = Scalar::from(value as u64) * *BASEPOINT_G1 + blinding_scalar * *BASEPOINT_G2;

    // Convert Rust byte vector to Java byte array
    let commitment_bytes = wedpr_l_crypto_zkp_utils::point_to_bytes(&commitment);
    java_safe_set_byte_array_field!(&env, result_jobject, &commitment_bytes, "commitment");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.zkp.NativeInterface->computeViewkey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_zkp_NativeInterface_computeViewkey(
    env: JNIEnv,
    _class: JClass,
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

    // Compute the commitment
    let viewkey = blinding_scalar * *BASEPOINT_G1;

    // Convert Rust byte vector to Java byte array
    let viewkey_bytes = wedpr_l_crypto_zkp_utils::point_to_bytes(&viewkey);
    java_safe_set_byte_array_field!(&env, result_jobject, &viewkey_bytes, "viewkey");
    result_jobject.into_inner()
}