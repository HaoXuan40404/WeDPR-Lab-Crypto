// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;
use criterion::Criterion;

use curve25519_dalek::Scalar;
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    prove_knowledge_proof, prove_sum_relationship,
    prove_value_equality_relationship_proof, verify_knowledge_proof,
    verify_sum_relationship, verify_value_equality_relationship_proof,
};
use wedpr_l_crypto_zkp_range_proof::{
    prove_value_range_with_blinding,
    prove_value_range_with_blinding_and_blinding_basepoint,
    verify_value_range_with_blinding_basepoint,
};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, Serialize, BASEPOINT_G1, BASEPOINT_G2,
};

fn create_mint_helper(c: &mut Criterion) {
    let label = format!("create_mint_helper");
    let value = 1;
    let c_scalar = Scalar::from(value);
    let c_blinding = get_random_scalar();
    let c_commitment = c_scalar * *BASEPOINT_G1 + c_blinding * *BASEPOINT_G2;
    let value_proof: wedpr_l_crypto_zkp_utils::ValueQualityProof =
        prove_value_equality_relationship_proof(
            value,
            &c_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(
                true,
                verify_value_equality_relationship_proof(
                    value,
                    &c_commitment,
                    &value_proof,
                    &BASEPOINT_G1,
                    &BASEPOINT_G2
                )
                .unwrap()
            );
        })
    });
}

fn create_transfer_helper(c: &mut Criterion) {
    let label = format!("create_transfer_helper");
    // 1 mint
    let value = 1;
    let c_scalar = Scalar::from(value);
    let c_blinding = get_random_scalar();
    let c_commitment = c_scalar * *BASEPOINT_G1 + c_blinding * *BASEPOINT_G2;
    let value_proof: wedpr_l_crypto_zkp_utils::ValueQualityProof =
        prove_value_equality_relationship_proof(
            value,
            &c_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );
    assert_eq!(
        true,
        verify_value_equality_relationship_proof(
            value,
            &c_commitment,
            &value_proof,
            &BASEPOINT_G1,
            &BASEPOINT_G2
        )
        .unwrap()
    );

    let c2_value = 1u64;
    let c2_scalar = Scalar::from(c2_value);
    let c2_blinding = get_random_scalar();
    let c2_commitment = c2_scalar * *BASEPOINT_G1 + c2_blinding * *BASEPOINT_G2;

    let c3_value = value - c2_value;
    let c3_scalar = Scalar::from(c3_value);
    let c3_blinding = get_random_scalar();
    let c3_commitment = c3_scalar * *BASEPOINT_G1 + c3_blinding * *BASEPOINT_G2;

    let knowledge_proof =
        prove_knowledge_proof(value, &c_blinding, &BASEPOINT_G1, &BASEPOINT_G2);

    let balance_proof = prove_sum_relationship(
        c2_value,
        c3_value,
        &c2_blinding,
        &c3_blinding,
        &c_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    let (rangeproof_c2, expected_commitment2) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            c2_value,
            &c2_blinding,
            &BASEPOINT_G2,
        );
    let (rangeproof_c3, expected_commitment3) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            c3_value,
            &c3_blinding,
            &BASEPOINT_G2,
        );

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(
                true,
                verify_knowledge_proof(
                    &c_commitment,
                    &knowledge_proof,
                    &BASEPOINT_G1,
                    &BASEPOINT_G2
                )
                .unwrap()
            );

            assert_eq!(
                true,
                verify_value_equality_relationship_proof(
                    value,
                    &c_commitment,
                    &value_proof,
                    &BASEPOINT_G1,
                    &BASEPOINT_G2
                )
                .unwrap()
            );
            assert_eq!(
                true,
                verify_value_range_with_blinding_basepoint(
                    &c2_commitment,
                    &rangeproof_c2,
                    &BASEPOINT_G2
                )
            );
            assert_eq!(
                true,
                verify_value_range_with_blinding_basepoint(
                    &c3_commitment,
                    &rangeproof_c3,
                    &BASEPOINT_G2
                )
            );
        })
    });
}

fn create_withdraw_helper(c: &mut Criterion) {
    let label: String = format!("create_withdraw_helper");
    let value = 1;
    let c_scalar = Scalar::from(value);
    let c_blinding = get_random_scalar();
    let c_commitment = c_scalar * *BASEPOINT_G1 + c_blinding * *BASEPOINT_G2;
    let value_proof: wedpr_l_crypto_zkp_utils::ValueQualityProof =
        prove_value_equality_relationship_proof(
            value,
            &c_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );
    assert_eq!(
        true,
        verify_value_equality_relationship_proof(
            value,
            &c_commitment,
            &value_proof,
            &BASEPOINT_G1,
            &BASEPOINT_G2
        )
        .unwrap()
    );

    let c2_value = 1u64;
    let c2_scalar = Scalar::from(c2_value);
    let c2_blinding = get_random_scalar();
    let c2_commitment = c2_scalar * *BASEPOINT_G1 + c2_blinding * *BASEPOINT_G2;

    let c3_value = value - c2_value;
    let c3_scalar = Scalar::from(c3_value);
    let c3_blinding = get_random_scalar();
    let c3_commitment = c3_scalar * *BASEPOINT_G1 + c3_blinding * *BASEPOINT_G2;

    let knowledge_proof =
        prove_knowledge_proof(value, &c_blinding, &BASEPOINT_G1, &BASEPOINT_G2);

    let balance_proof = prove_sum_relationship(
        c2_value,
        c3_value,
        &c2_blinding,
        &c3_blinding,
        &c_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    let (rangeproof_c2, expected_commitment2) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            c2_value,
            &c2_blinding,
            &BASEPOINT_G2,
        );
    let (rangeproof_c3, expected_commitment3) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            c3_value,
            &c3_blinding,
            &BASEPOINT_G2,
        );

    let knowledge_proof = prove_knowledge_proof(
        c3_value,
        &c3_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );
    let value_proof = prove_value_equality_relationship_proof(
        c3_value,
        &c3_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(
                true,
                verify_knowledge_proof(
                    &c3_commitment,
                    &knowledge_proof,
                    &BASEPOINT_G1,
                    &BASEPOINT_G2
                )
                .unwrap()
            );
            assert_eq!(
                true,
                verify_value_equality_relationship_proof(
                    c3_value,
                    &c3_commitment,
                    &value_proof,
                    &BASEPOINT_G1,
                    &BASEPOINT_G2
                )
                .unwrap()
            );
        })
    });
}

criterion_group! {
    name = init_proof_test;
    config = Criterion::default().sample_size(10);
targets =
create_mint_helper,
create_transfer_helper,
create_withdraw_helper
}

criterion_main!(init_proof_test);
