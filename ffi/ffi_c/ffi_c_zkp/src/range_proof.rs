use crate::utils::{
    c_input_buffer_to_point, c_input_buffer_to_scalar,
    c_input_buffer_to_vec
};
use wedpr_ffi_common::utils::{CInputBuffer, COutputBuffer, FAILURE, SUCCESS};

use wedpr_ffi_common::utils::c_write_data_to_pointer;

#[cfg(feature = "wedpr_f_zkp_proof")]
use wedpr_l_crypto_zkp_range_proof::{
    prove_value_range_with_blinding_and_blinding_basepoint, verify_value_range_with_blinding_basepoint
};
use wedpr_l_crypto_zkp_utils::BASEPOINT_G2;

#[no_mangle]
/// C interface for 'wedpr_generate_range_proof'.
pub unsafe extern "C" fn wedpr_generate_range_proof(
    c_value: u64,
    c_blinding: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
    c_range_proof: &mut COutputBuffer,
) -> i8 {
    // c_blinding
    let c_blinding_result: Result<curve25519_dalek::Scalar, wedpr_l_utils::error::WedprError> = c_input_buffer_to_scalar(&c_blinding);
    let c_blinding_value = match c_blinding_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let (range_proof, _) = prove_value_range_with_blinding_and_blinding_basepoint(
        c_value,
        &c_blinding_value,
        &blinding_basepoint,
    );
    // write balance proof back to c_balance_proof
    c_write_data_to_pointer(
        &range_proof,
        c_range_proof.data,
        c_range_proof.len,
    );
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_verify_range_proof'.
pub unsafe extern "C" fn wedpr_verify_range_proof(
    commitment_point_data: &CInputBuffer,
    proof: &CInputBuffer,
    blinding_basepoint_data: &CInputBuffer,
) -> i8 {
    // c_point
    let c_point_result = c_input_buffer_to_point(commitment_point_data);
    let c_point = match c_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // range_proof
    let range_proof_result = c_input_buffer_to_vec(proof);
    let range_proof = match range_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // blinding_basepoint
    let blinding_basepoint_result =
        c_input_buffer_to_point(blinding_basepoint_data);
    let blinding_basepoint = match blinding_basepoint_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    let result = verify_value_range_with_blinding_basepoint(
        &c_point,
        &range_proof,
        &blinding_basepoint,
    );
    if result {
        return SUCCESS;
    }
    FAILURE
}


#[no_mangle]
/// C interface for 'wedpr_verify_range_proof_without_basepoint'.
pub unsafe extern "C" fn wedpr_verify_range_proof_without_basepoint(
    commitment_point_data: &CInputBuffer,
    proof: &CInputBuffer,
) -> i8 {
    // c_point
    let c_point_result = c_input_buffer_to_point(commitment_point_data);
    let c_point = match c_point_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // range_proof
    let range_proof_result = c_input_buffer_to_vec(proof);
    let range_proof = match range_proof_result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };

    let result = verify_value_range_with_blinding_basepoint(
        &c_point,
        &range_proof,
        &BASEPOINT_G2,
    );
    if result {
        return SUCCESS;
    }
    FAILURE
}
