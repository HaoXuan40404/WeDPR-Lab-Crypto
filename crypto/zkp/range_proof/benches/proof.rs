// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;
use criterion::Criterion;

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_range_proof::{
    self, prove_value_range, verify_value_range,
};

fn create_verify_range_proof_helper(c: &mut Criterion) {
    let label = format!("create_verify_range_proof_helper");
    let (proof_c1, c1_point, _) = prove_value_range(32u64);
    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(true, verify_value_range(&c1_point, &proof_c1));
        })
    });
}

criterion_group! {
    name = init_proof_test;
    config = Criterion::default().sample_size(10);
targets =
create_verify_range_proof_helper,

}

criterion_main!(init_proof_test);
