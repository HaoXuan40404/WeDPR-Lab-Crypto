use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_ffi_common::utils::{
    c_read_raw_data_pointer, c_read_raw_pointer, c_write_data_to_pointer,
    CInputBuffer, COutputBuffer,
};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, ArithmeticProof, BalanceProof,
    Deserialize, EqualityProof, FormatProof, KnowledgeProof, RelationshipProof,
    Serialize, ValueEqualityProof,
};
use wedpr_l_utils::error::WedprError;

// From Rust to C/C++.
use libc::c_char;

pub unsafe fn c_input_buffer_to_vec(
    input_data: &CInputBuffer,
) -> Result<Vec<u8>, WedprError> {
    let rust_bytes_input = c_read_raw_pointer(&input_data);
    // avoid the input c buffer been released
    let result = rust_bytes_input.clone();
    std::mem::forget(rust_bytes_input);
    Ok(result)
}

pub unsafe fn c_input_buffer_to_point(
    input_data: &CInputBuffer,
) -> Result<RistrettoPoint, WedprError> {
    let rust_bytes_input = c_read_raw_pointer(&input_data);
    let result = bytes_to_point(&rust_bytes_input.as_slice());
    // avoid the input c buffer been released
    std::mem::forget(rust_bytes_input);
    result
}

pub unsafe fn c_input_buffer_to_scalar(
    input_data: &CInputBuffer,
) -> Result<Scalar, WedprError> {
    let rust_bytes_input = c_read_raw_pointer(&input_data);
    let result = bytes_to_scalar(&rust_bytes_input.as_slice());
    // avoid the input c buffer been released
    std::mem::forget(rust_bytes_input);
    result
}

pub unsafe fn c_bytes_to_point(
    c_bytes: *const c_char,
    len: usize,
) -> Result<RistrettoPoint, WedprError> {
    let rust_bytes_input = c_read_raw_data_pointer(c_bytes, len);
    let result = bytes_to_point(&rust_bytes_input.as_slice());
    // avoid the input c buffer been released
    std::mem::forget(rust_bytes_input);
    return result;
}

pub unsafe fn c_bytes_to_scalar(
    c_bytes: *const c_char,
    len: usize,
) -> Result<Scalar, WedprError> {
    let rust_bytes_input = c_read_raw_data_pointer(c_bytes, len);
    let result = bytes_to_scalar(&rust_bytes_input.as_slice());
    // avoid the input c buffer been released
    std::mem::forget(rust_bytes_input);
    return result;
}

pub unsafe fn write_balance_proof(
    balance_proof: &BalanceProof,
    c_balance_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &balance_proof.serialize(),
        c_balance_proof.data,
        c_balance_proof.len,
    );
}

pub unsafe fn read_c_balance_proof(
    c_balance_proof: &CInputBuffer,
) -> Result<BalanceProof, WedprError> {
    let proof =
        c_read_raw_data_pointer(c_balance_proof.data, c_balance_proof.len);
    let balance_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    balance_proof
}

pub unsafe fn write_knowledger_proof(
    knowledge_proof: &KnowledgeProof,
    c_knowledge_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &knowledge_proof.serialize(),
        c_knowledge_proof.data,
        c_knowledge_proof.len,
    );
}

pub unsafe fn read_c_knowledge_proof(
    c_knowledge_proof: &CInputBuffer,
) -> Result<KnowledgeProof, WedprError> {
    let proof =
        c_read_raw_data_pointer(c_knowledge_proof.data, c_knowledge_proof.len);
    let knowledge_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    knowledge_proof
}

pub unsafe fn write_format_proof(
    format_proof: &FormatProof,
    c_format_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &format_proof.serialize(),
        c_format_proof.data,
        c_format_proof.len,
    );
}

pub unsafe fn read_c_format_proof(
    c_format_proof: &CInputBuffer,
) -> Result<FormatProof, WedprError> {
    let proof =
        c_read_raw_data_pointer(c_format_proof.data, c_format_proof.len);
    let format_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    format_proof
}

pub unsafe fn write_arithmetic_proof(
    arithmetic_proof: &ArithmeticProof,
    c_arithmetic_proof_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &arithmetic_proof.serialize(),
        c_arithmetic_proof_proof.data,
        c_arithmetic_proof_proof.len,
    );
}

pub unsafe fn write_commitments(commitments: &Vec<RistrettoPoint>, c_commitments: &mut COutputBuffer) {
    let mut result = Vec::new();
    for commitment in commitments {
        result.extend_from_slice(&commitment.compress().to_bytes());
    }
    c_write_data_to_pointer(&result, c_commitments.data, c_commitments.len);
}

pub unsafe fn read_c_commitments(
    c_commitments: &CInputBuffer,
) -> Result<Vec<RistrettoPoint>, WedprError> {
    let commitments = c_read_raw_pointer(c_commitments);
    let mut result = Vec::new();
    let mut index = 0;
    while index < commitments.len() {
        let point = bytes_to_point(&commitments[index..index + 32])?;
        result.push(point);
        index += 32;
    }
    // avoid the input c buffer been released
    std::mem::forget(commitments);
    Ok(result)
}

pub unsafe fn read_c_relationship_proof(
    c_relationship_proof: &CInputBuffer,
) -> Result<RelationshipProof, WedprError> {
    let proof = c_read_raw_data_pointer(
        c_relationship_proof.data,
        c_relationship_proof.len,
    );
    let relationship_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    relationship_proof
}

pub unsafe fn read_c_arithmetic_proof(
    c_arithmetic_proof: &CInputBuffer,
) -> Result<ArithmeticProof, WedprError> {
    let proof = c_read_raw_data_pointer(
        c_arithmetic_proof.data,
        c_arithmetic_proof.len,
    );
    let arithmetic_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    arithmetic_proof
}

pub unsafe fn write_equality_proof(
    equality_proof: &EqualityProof,
    c_equality_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &equality_proof.serialize(),
        c_equality_proof.data,
        c_equality_proof.len,
    );
}

pub unsafe fn read_c_equality_proof(
    c_equality_proof: &CInputBuffer,
) -> Result<EqualityProof, WedprError> {
    let proof =
        c_read_raw_data_pointer(c_equality_proof.data, c_equality_proof.len);
    let equality_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    equality_proof
}

pub unsafe fn write_value_equality_proof(
    value_equality_proof: &ValueEqualityProof,
    c_value_equality_proof: &mut COutputBuffer,
) {
    c_write_data_to_pointer(
        &value_equality_proof.serialize(),
        c_value_equality_proof.data,
        c_value_equality_proof.len,
    );
}

pub unsafe fn read_c_value_equality_proof(
    c_value_equality_proof: &CInputBuffer,
) -> Result<ValueEqualityProof, WedprError> {
    let proof = c_read_raw_data_pointer(
        c_value_equality_proof.data,
        c_value_equality_proof.len,
    );
    let value_equality_proof = Deserialize::deserialize(&proof);
    // avoid the input c buffer been released
    std::mem::forget(proof);
    value_equality_proof
}
