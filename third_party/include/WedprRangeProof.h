#ifndef _WEDPR_RANGE_PROOF_H_
#define _WEDPR_RANGE_PROOF_H_
#include "WedprUtilities.h"
extern "C" {
/**
 * C interface for 'wedpr_generate_range_proof'.
 */
int8_t wedpr_generate_range_proof(uint64_t c_value,
                                  const CInputBuffer *c_blinding,
                                  const CInputBuffer *blinding_basepoint_data,
                                  COutputBuffer *c_range_proof);

/**
 * C interface for 'wedpr_verify_range_proof'.
 */
int8_t wedpr_verify_range_proof(const CInputBuffer *commitment_point_data,
                                const CInputBuffer *proof,
                                const CInputBuffer *blinding_basepoint_data);
/**
 * C interface for 'wedpr_verify_range_proof_without_basepoint'.
 */
int8_t wedpr_verify_range_proof_without_basepoint(
    const CInputBuffer *commitment_point_data, const CInputBuffer *proof);
}
#endif