// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions based on DLP construction.
extern crate hex;

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use rand::Rng;
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, ArithmeticProof, BalanceProof, EqualityProof, FormatProof, KnowledgeProof, ReceiverRelationshipProofFinalPublic, ReceiverRelationshipProofSetupPrivate, ReceiverRelationshipProofSetupPublic, RelationshipProof, SenderRelationshipProofFinalPublic, SenderRelationshipProofSetupPrivate, SenderRelationshipProofSetupPublic, ValueEqualityProof
};

use wedpr_l_utils::error::WedprError;

pub fn aggregate_ristretto_point(
    point_sum: &RistrettoPoint,
    point_share: &RistrettoPoint,
) -> Result<RistrettoPoint, WedprError> {
    Ok(point_sum + point_share)
}

/// Proves a value with a commitments satisfying an equality relationship, i.e.
/// the value embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint. It returns a proof for the above equality relationship.
pub fn prove_value_equality_relationship_proof(
    c_value: u64,
    c_blinding: &Scalar,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> ValueEqualityProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t1 = blinding_a * c_basepoint;
    let t2 = blinding_a * c_basepoint + blinding_b * blinding_basepoint;
    let c_value_scalar = Scalar::from(c_value);
    let c_point =
        c_value_scalar * c_basepoint + c_blinding * blinding_basepoint;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1));
    hash_vec.append(&mut point_to_bytes(&t2));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut c_value.to_be_bytes().to_vec());
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * c_value_scalar);
    let m2 = blinding_b - (check * c_blinding);
    return ValueEqualityProof { check, m1, m2 };
}

/// Verifies a commitment satisfying an equality relationship, i.e.
/// the value embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint.
/// It returns a proof for the above equality relationship.
pub fn verify_value_equality_relationship_proof(
    c_value: u64,
    c_point: &RistrettoPoint,
    proof: &ValueEqualityProof,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let c_value_scalar = Scalar::from(c_value);

    let t1 =
        c_value_scalar * proof.check * c_basepoint + proof.m1 * c_basepoint;
    let t2 = proof.check * c_point
        + proof.m1 * c_basepoint
        + proof.m2 * blinding_basepoint;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1));
    hash_vec.append(&mut point_to_bytes(&t2));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut c_value.to_be_bytes().to_vec());
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);

    if check == proof.check {
        return Ok(true);
    }
    Ok(false)
}

/// Proves three commitments satisfying either or equality relationships, i.e.
/// the values embedded in c1_point = c1_value * c_basepoint + c1_blinding *
/// blinding_basepoint c2_point = c2_value * c_basepoint + c2_blinding *
/// blinding_basepoint c3_point = c3_blinding * blinding_basepoint
/// where c1_value = c2_value or 0,
/// It returns a proof for the above equality relationship.
pub fn prove_either_equality_relationship_proof(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let blinding_f = get_random_scalar();
    let blinding_w = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*c_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*c_basepoint, *blinding_basepoint],
    );
    let c3_point = c3_blinding * blinding_basepoint;

    let (check1, check2, m1, m2, m3, m4, m5, m6) = if c1_value == c2_value {
        let t1_p =
            RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t2_p =
            RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_c], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t3_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_d, blinding_e],
            &[c3_point, *c_basepoint, *blinding_basepoint],
        );
        let t4_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_d, blinding_f],
            &[c1_point, *c_basepoint, *blinding_basepoint],
        );

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&t4_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));

        let check = hash_to_scalar(&hash_vec) - blinding_w;
        (
            check,
            blinding_w,
            blinding_a - (check * Scalar::from(c2_value)),
            blinding_b - (check * c2_blinding),
            blinding_c - (check * c1_blinding),
            blinding_d,
            blinding_e,
            blinding_f,
        )
    } else if c1_value == 0 {
        let t1_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_a, blinding_b],
            &[c2_point, *c_basepoint, *blinding_basepoint],
        );
        let t2_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_a, blinding_c],
            &[c1_point, *c_basepoint, *blinding_basepoint],
        );
        let t3_p =
            RistrettoPoint::multiscalar_mul(&[blinding_d, blinding_e], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t4_p =
            RistrettoPoint::multiscalar_mul(&[blinding_d, blinding_f], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&t4_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));

        let check = hash_to_scalar(&hash_vec) - blinding_w;
        (
            blinding_w,
            check,
            blinding_a,
            blinding_b,
            blinding_c,
            blinding_d,
            blinding_e - (check * c3_blinding),
            blinding_f - (check * c1_blinding),
        )
    } else {
        return BalanceProof::default();
    };
    return BalanceProof {
        check1: check1,
        check2: check2,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
        m6: m6,
    };
}

/// Verifies owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_either_equality_relationship_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let t1_v = RistrettoPoint::multiscalar_mul(
        &[proof.check1, proof.m1, proof.m2],
        &[*c2_point, *c_basepoint, *blinding_basepoint],
    );
    let t2_v = RistrettoPoint::multiscalar_mul(
        &[proof.check1, proof.m1, proof.m3],
        &[*c1_point, *c_basepoint, *blinding_basepoint],
    );
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[proof.check2, proof.m4, proof.m5],
        &[*c3_point, *c_basepoint, *blinding_basepoint],
    );
    let t4_v = RistrettoPoint::multiscalar_mul(
        &[proof.check2, proof.m4, proof.m6],
        &[*c1_point, *c_basepoint, *blinding_basepoint],
    );

    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_v));
    hash_vec.append(&mut point_to_bytes(&t2_v));
    hash_vec.append(&mut point_to_bytes(&t3_v));
    hash_vec.append(&mut point_to_bytes(&t4_v));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);

    if check == (proof.check1 + proof.check2) {
        return Ok(true);
    }
    Ok(false)
}

/// Proves owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint It returns a proof for the above balance relationship.
pub fn prove_knowledge_proof(
    c_value: u64,
    c_blinding: &Scalar,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> KnowledgeProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *c_basepoint,
        *blinding_basepoint,
    ]);
    let c_scalar_value = Scalar::from(c_value);
    let c_point =
        RistrettoPoint::multiscalar_mul(&[c_scalar_value, *c_blinding], &[
            *c_basepoint,
            *blinding_basepoint,
        ]);
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * c_scalar_value);
    let m2 = blinding_b - (check * c_blinding);
    return KnowledgeProof {
        t1: t1_p,
        m1: m1,
        m2: m2,
    };
}

/// Verifies owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_knowledge_proof(
    c_point: &RistrettoPoint,
    proof: &KnowledgeProof,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);
    let t1_v =
        RistrettoPoint::multiscalar_mul(&[check, proof.m1, proof.m2], &[
            *c_point,
            *c_basepoint,
            *blinding_basepoint,
        ]);

    if t1_v == proof.t1 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying knowledge relationships,
/// where each commitment pair contains one commitment points,
/// c_point = c_point_list[i],
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_knowledge_proof_in_batch(
    c_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<KnowledgeProof>,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c_point_list.len() != proof_list.len() {
        return Err(WedprError::FormatError);
    }
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::from(0u8);
    let mut m2_expected: Scalar = Scalar::from(0u8);

    for i in 0..c_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c_point = c_point_list[i];

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&c_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));
        let check = hash_to_scalar(&hash_vec);

        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        c1_c_expected += c_factor * c_point;
    }
    let t1_compute_sum_final = m1_expected * c_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;

    if t1_compute_sum_final == t1_sum_expected {
        return Ok(true);
    }
    Ok(false)
}

/// Proves two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_blinding =
/// c2_blinding, where c1_point = c1_value * c1_basepoint + c1_blinding *
/// blinding_basepoint, c2_point = c2_blinding * c2_basepoint. It returns a
/// proof for the above equality relationship.
pub fn prove_format_proof(
    c1_value: u64,
    c_blinding: &Scalar,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> FormatProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *c1_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = c2_basepoint * blinding_b;
    let c1_scalar_value = Scalar::from(c1_value);
    let c1_point =
        RistrettoPoint::multiscalar_mul(&[c1_scalar_value, *c_blinding], &[
            *c1_basepoint,
            *blinding_basepoint,
        ]);
    let c2_point = c_blinding * c2_basepoint;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(c1_basepoint));
    hash_vec.append(&mut point_to_bytes(c2_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * c1_scalar_value);
    let m2 = blinding_b - (check * c_blinding);
    return FormatProof {
        t1: t1_p,
        t2: t2_p,
        m1: m1,
        m2: m2,
    };
}

/// Verifies two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_blinding =
/// c2_blinding, where c1_point = c1_value * c1_basepoint + c1_blinding *
/// blinding_basepoint, c2_point = c2_blinding * c2_basepoint.
pub fn verify_format_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    proof: &FormatProof,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(c1_basepoint));
    hash_vec.append(&mut point_to_bytes(c2_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);
    let t1_v =
        RistrettoPoint::multiscalar_mul(&[check, proof.m1, proof.m2], &[
            *c1_point,
            *c1_basepoint,
            *blinding_basepoint,
        ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[check, proof.m2], &[
        *c2_point,
        *c2_basepoint,
    ]);

    if t1_v == proof.t1 && t2_v == proof.t2 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying equality relationships,
/// where each commitment pair contains two commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i],
/// and the values embedded in c1_point, c2_point satisfying
/// c1_blinding = c2_blinding.
pub fn verify_format_proof_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<FormatProof>,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c1_point_list.len()
        || c1_point_list.len() != proof_list.len()
    {
        return Err(WedprError::FormatError);
    }
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::from(0u8);
    let mut m2_expected: Scalar = Scalar::from(0u8);

    for i in 0..c1_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(c1_basepoint));
        hash_vec.append(&mut point_to_bytes(c2_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));
        let check = hash_to_scalar(&hash_vec);

        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
    }
    let t1_compute_sum_final = m1_expected * c1_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m2_expected * c2_basepoint + c2_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
}

pub fn sender_prove_multi_sum_relationship_setup(
    input_value: u64,
    input_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> (
    SenderRelationshipProofSetupPrivate,
    SenderRelationshipProofSetupPublic,
) {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t_commit =
        blinding_a * value_basepoint + blinding_b * blinding_basepoint;
    let a_commit = blinding_a * value_basepoint;
    let commit = Scalar::from(input_value) * value_basepoint
        + input_blinding * blinding_basepoint;
    return (
        SenderRelationshipProofSetupPrivate {
            blinding_a: blinding_a,
            blinding_b: blinding_b,
        },
        SenderRelationshipProofSetupPublic {
            t_commit: t_commit,
            a_commit: a_commit,
            commitment: commit,
        },
    );
}

pub fn sender_prove_multi_sum_relationship_final(input_value: u64, input_blinding: &Scalar, proof_secret: &SenderRelationshipProofSetupPrivate, check: &Scalar) -> SenderRelationshipProofFinalPublic {
    let m = proof_secret.blinding_a - check * Scalar::from(input_value);
    let n = proof_secret.blinding_b - check * input_blinding;
    return SenderRelationshipProofFinalPublic {
        m: m,
        n: n,
    };
}

pub fn receiver_prove_multi_sum_relationship_setup(
    output_value: u64,
    output_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> (
    ReceiverRelationshipProofSetupPrivate,
    ReceiverRelationshipProofSetupPublic,
) {
    let blinding_f = get_random_scalar();
    let f_commit = blinding_f * blinding_basepoint;
    let commit = Scalar::from(output_value) * value_basepoint
        + output_blinding * blinding_basepoint;
    return (
        ReceiverRelationshipProofSetupPrivate {
            f_blinding: blinding_f,
        },
        ReceiverRelationshipProofSetupPublic {
            f_commit: f_commit,
            commitment: commit,
        },
    );
}

pub fn receiver_prove_multi_sum_relationship_final(output_blinding: &Scalar, proof_secret: &ReceiverRelationshipProofSetupPrivate, check: &Scalar) -> ReceiverRelationshipProofFinalPublic {
    let t_commit_share = proof_secret.f_blinding - check * output_blinding;
    return ReceiverRelationshipProofFinalPublic {
        t_commit_share: t_commit_share,
    };
}

pub fn coordinator_prove_multi_sum_relationship_setup(
    sender_setup_lists: &[SenderRelationshipProofSetupPublic],
    receiver_setup_lists: &[ReceiverRelationshipProofSetupPublic],
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Scalar {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let mut a_sum_commit = RistrettoPoint::default();
    let mut f_sum_commit = RistrettoPoint::default();
    for sender_setup in sender_setup_lists.iter() {
        a_sum_commit += sender_setup.a_commit;
        hash_vec.append(&mut point_to_bytes(&sender_setup.commitment));
    }
    for receiver_setup in receiver_setup_lists.iter() {
        f_sum_commit += receiver_setup.f_commit;
        hash_vec.append(&mut point_to_bytes(&receiver_setup.commitment));
    }
    for sender_setup in sender_setup_lists.iter() {
        hash_vec.append(&mut point_to_bytes(&sender_setup.t_commit));
    }
    let t_commit = a_sum_commit + f_sum_commit;
    hash_vec.append(&mut point_to_bytes(&t_commit));
    return hash_to_scalar(&hash_vec);
}

pub fn coordinator_prove_multi_sum_relationship_final(check: &Scalar, sender_proofs: &[SenderRelationshipProofFinalPublic], receiver_proofs: &[ReceiverRelationshipProofFinalPublic]) -> RelationshipProof {
    let mut left_commit = Scalar::from(0u64);
    let mut m_list = Vec::new();
    let mut n_list = Vec::new();
    for i in 0..receiver_proofs.len() 
    {
        left_commit += receiver_proofs[i].t_commit_share;
    }

    for i in 0..sender_proofs.len()
    {
        m_list.push(sender_proofs[i].m);
        n_list.push(sender_proofs[i].n);
    }

    return RelationshipProof {
        check: *check,
        m_list: m_list,
        n_list: n_list,
        left_commit: left_commit,
    };
}

pub fn prove_multi_sum_relationship(
    input_value_list: &[u64],
    input_blinding_list: &[Scalar],
    output_value_list: &[u64],
    output_blinding_list: &[Scalar],
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> RelationshipProof {
    if input_value_list.len() != input_blinding_list.len()
        || output_value_list.len() != output_blinding_list.len()
    {
        return RelationshipProof::default();
    }
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    let mut m_list = Vec::new();
    let mut n_list = Vec::new();

    let mut blinding_a_list = Vec::new();
    let mut blinding_b_list = Vec::new();
    let blinding_f = get_random_scalar();

    let mut input_t_point_list = Vec::new();
    let mut blinding_a_sum = Scalar::from(0u64);

    // TODO: add commitment for hasher
    for i in 0..input_value_list.len() {
        let blinding_a_i = get_random_scalar();
        let blinding_b_i = get_random_scalar();
        blinding_a_list.push(blinding_a_i);
        blinding_b_list.push(blinding_b_i);

        let point_t_i =
            blinding_a_i * value_basepoint + blinding_b_i * blinding_basepoint;
        input_t_point_list.push(point_t_i);
        blinding_a_sum += blinding_a_i;
        let input_commitment_i = Scalar::from(input_value_list[i])
            * value_basepoint
            + input_blinding_list[i] * blinding_basepoint;
        hash_vec.append(&mut point_to_bytes(&input_commitment_i));
    }

    for i in 0..output_value_list.len() {
        let output_commitment_i = Scalar::from(output_value_list[i])
            * value_basepoint
            + output_blinding_list[i] * blinding_basepoint;
        hash_vec.append(&mut point_to_bytes(&output_commitment_i));
    }

    let t_sum_commit =
        blinding_a_sum * value_basepoint + blinding_f * blinding_basepoint;

    for point in input_t_point_list.iter() {
        hash_vec.append(&mut point_to_bytes(point));
    }
    hash_vec.append(&mut point_to_bytes(&t_sum_commit));

    let check = hash_to_scalar(&hash_vec);
    let mut left_blinding_sum = Scalar::from(0u64);

    for i in 0..input_value_list.len() {
        let mi = blinding_a_list[i] - check * Scalar::from(input_value_list[i]);
        let ni = blinding_b_list[i] - check * input_blinding_list[i];
        m_list.push(mi);
        n_list.push(ni);
    }
    for i in 0..output_blinding_list.len() {
        left_blinding_sum += output_blinding_list[i];
    }
    let left_commit = blinding_f - check * left_blinding_sum;

    return RelationshipProof {
        check: check,
        m_list: m_list,
        n_list: n_list,
        left_commit: left_commit,
    };
}

pub fn verify_multi_sum_relationship(
    input_commitments: &[RistrettoPoint],
    output_commitments: &[RistrettoPoint],
    proof: &RelationshipProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if proof.m_list.len() != input_commitments.len()
        || proof.n_list.len() != input_commitments.len()
    {
        return Ok(false);
    }

    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    for point in input_commitments.iter() {
        hash_vec.append(&mut point_to_bytes(point));
    }
    for point in output_commitments.iter() {
        hash_vec.append(&mut point_to_bytes(point));
    }

    let mut m_sum = Scalar::from(0u64);
    for i in 0..input_commitments.len() {
        m_sum += proof.m_list[i];
        let point_t_i = proof.m_list[i] * value_basepoint
            + proof.n_list[i] * blinding_basepoint
            + proof.check * input_commitments[i];
        hash_vec.append(&mut point_to_bytes(&point_t_i));
    }
    let mut output_sum_commitment = RistrettoPoint::default();
    for point in output_commitments.iter() {
        output_sum_commitment += point;
    }
    let t_sum_commit = m_sum * value_basepoint
        + proof.left_commit * blinding_basepoint
        + proof.check * output_sum_commitment;
    hash_vec.append(&mut point_to_bytes(&t_sum_commit));
    let check = hash_to_scalar(&hash_vec);
    return Ok(check == proof.check);
}
/// Proves three commitments satisfying a sum relationship, i.e.
/// the values embedded in them satisfying c1_value + c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value + c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above sum relationship.
pub fn prove_sum_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> ArithmeticProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) + Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[(blinding_a + blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * (Scalar::from(c1_value)));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (Scalar::from(c2_value)));
    let m4 = blinding_d - (check * (c2_blinding));
    let m5 = blinding_e - (check * (c3_blinding));
    return ArithmeticProof {
        t1: t1_p,
        t2: t2_p,
        t3: t3_p,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
    };
}

/// Verifies three commitments satisfying a sum relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &ArithmeticProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&proof.t3));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

    let t1_v =
        RistrettoPoint::multiscalar_mul(&[proof.m1, proof.m2, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c1_point,
        ]);
    let t2_v =
        RistrettoPoint::multiscalar_mul(&[proof.m3, proof.m4, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c2_point,
        ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[proof.m1 + (proof.m3), proof.m5, check],
        &[*value_basepoint, *blinding_basepoint, *c3_point],
    );
    if t1_v == proof.t1 && t2_v == proof.t2 && t3_v == proof.t3 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment tuples satisfying sum relationships,
/// where each commitment tuple contains three commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i], c3_point =
/// c3_point_list[i], and the values embedded in c1_point, c2_point, c3_point
/// satisfying c1_value + c2_value = c3_value.
pub fn verify_sum_relationship_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    c3_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<ArithmeticProof>,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != c3_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut t3_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut c3_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::from(0u8);
    let mut m2_expected: Scalar = Scalar::from(0u8);
    let mut m3_expected: Scalar = Scalar::from(0u8);
    let mut m4_expected: Scalar = Scalar::from(0u8);
    let mut m5_expected: Scalar = Scalar::from(0u8);
    for i in 0..c1_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t3));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        m3_expected += blinding_factor * proof_list[i].m3;
        m4_expected += blinding_factor * proof_list[i].m4;
        m5_expected += blinding_factor * proof_list[i].m5;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        t3_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t3);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
    }

    let t1_compute_sum_final = m1_expected * value_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m3_expected * value_basepoint
        + m4_expected * blinding_basepoint
        + c2_c_expected;
    let t3_compute_sum_final = (m1_expected + m3_expected) * value_basepoint
        + m5_expected * blinding_basepoint
        + c3_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
        && t3_compute_sum_final == t3_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
}

/// Proves three commitments satisfying a product relationship, i.e.
/// the values embedded in them satisfying c1_value * c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value * c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above product relationship.
pub fn prove_product_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> ArithmeticProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) * Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );

    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[blinding_a * (blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let value1 = Scalar::from(c1_value);
    let value2 = Scalar::from(c2_value);
    let m1 = blinding_a - (check * (value1));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (value2));
    let m4 = blinding_d - (check * c2_blinding);
    let c_index2 = check * check;
    let m5 = blinding_e
        + c_index2
            * ((value1 * c2_blinding) - c3_blinding + (value2 * c1_blinding))
        - check * ((blinding_a * c2_blinding) + (blinding_c * c1_blinding));

    return ArithmeticProof {
        t1: t1_p,
        t2: t2_p,
        t3: t3_p,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
    };
}

/// Verifies three commitments satisfying a product relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &ArithmeticProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&proof.t3));
    hash_vec.append(&mut point_to_bytes(c1_point));
    hash_vec.append(&mut point_to_bytes(c2_point));
    hash_vec.append(&mut point_to_bytes(c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

    let t1_v =
        RistrettoPoint::multiscalar_mul(&[proof.m1, proof.m2, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c1_point,
        ]);
    let t2_v =
        RistrettoPoint::multiscalar_mul(&[proof.m3, proof.m4, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c2_point,
        ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[
            proof.m1 * proof.m3,
            proof.m5,
            check * check,
            check * proof.m3,
            check * proof.m1,
        ],
        &[
            *value_basepoint,
            *blinding_basepoint,
            *c3_point,
            *c1_point,
            *c2_point,
        ],
    );

    if t1_v == proof.t1 && t2_v == proof.t2 && t3_v == proof.t3 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment tuples satisfying product relationships,
/// where each commitment tuple contains three commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i], c3_point =
/// c3_point_list[i], and the values embedded in c1_point, c2_point, c3_point
/// satisfying c1_value * c2_value = c3_value.
pub fn verify_product_relationship_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    c3_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<ArithmeticProof>,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != c3_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut t3_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut c3_c_expected: RistrettoPoint = Default::default();
    let mut t3_c1_c_expected: RistrettoPoint = Default::default();
    let mut t3_c2_c_expected: RistrettoPoint = Default::default();
    let mut t3_c3_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::from(0u8);
    let mut m1_m3_expected: Scalar = Scalar::from(0u8);
    let mut m2_expected: Scalar = Scalar::from(0u8);
    let mut m3_expected: Scalar = Scalar::from(0u8);
    let mut m4_expected: Scalar = Scalar::from(0u8);
    let mut m5_expected: Scalar = Scalar::from(0u8);
    for i in 0..c1_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t3));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        m1_expected += blinding_factor * proof_list[i].m1;
        let c_factor = blinding_factor * check;
        m1_m3_expected += blinding_factor * proof_list[i].m1 * proof_list[i].m3;
        m2_expected += blinding_factor * proof_list[i].m2;
        m3_expected += blinding_factor * proof_list[i].m3;
        m4_expected += blinding_factor * proof_list[i].m4;
        m5_expected += blinding_factor * proof_list[i].m5;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        t3_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t3);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
        t3_c1_c_expected +=
            blinding_factor * check * proof_list[i].m3 * c1_point;
        t3_c2_c_expected +=
            blinding_factor * check * proof_list[i].m1 * c2_point;
        t3_c3_c_expected += blinding_factor * check * check * c3_point;
    }

    let t1_compute_sum_final = m1_expected * value_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m3_expected * value_basepoint
        + m4_expected * blinding_basepoint
        + c2_c_expected;
    let t3_compute_sum_final = m1_m3_expected * value_basepoint
        + m5_expected * blinding_basepoint
        + t3_c3_c_expected
        + t3_c1_c_expected
        + t3_c2_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
        && t3_compute_sum_final == t3_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
}

/// Proves two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_value = c2_value,
/// where c1_point = c1_value * basepoint1, c2_point = c2_value * basepoint2.
/// It returns a proof for the above equality relationship.
pub fn prove_equality_relationship_proof(
    c1_value: &Scalar,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> EqualityProof {
    let blinding_a = get_random_scalar();
    let c1_point =
        RistrettoPoint::multiscalar_mul(&[*c1_value], &[*basepoint1]);
    let c2_point =
        RistrettoPoint::multiscalar_mul(&[*c1_value], &[*basepoint2]);

    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a], &[*basepoint1]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_a], &[*basepoint2]);
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(basepoint1));
    hash_vec.append(&mut point_to_bytes(basepoint2));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * (c1_value));

    return EqualityProof {
        m1: m1,
        t1: t1_p,
        t2: t2_p,
    };
}

/// Verifies two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point, c2_point satisfying
/// c1_value = c2_value,
/// where c1_point = c1_value * basepoint1, c2_point = c2_value * basepoint2.
pub fn verify_equality_relationship_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    proof: &EqualityProof,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(basepoint1));
    hash_vec.append(&mut point_to_bytes(basepoint2));

    let check = hash_to_scalar(&hash_vec);
    let t1_v = RistrettoPoint::multiscalar_mul(&[proof.m1, check], &[
        *basepoint1,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[proof.m1, check], &[
        *basepoint2,
        *c2_point,
    ]);
    if t1_v == proof.t1 && t2_v == proof.t2 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying equality relationships,
/// where each commitment pair contains two commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i],
/// and the values embedded in c1_point, c2_point satisfying
/// c1_value = c2_value.
pub fn verify_equality_relationship_proof_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<EqualityProof>,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::from(0u8);
    for i in 0..c1_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(basepoint1));
        hash_vec.append(&mut point_to_bytes(basepoint2));
        let check = hash_to_scalar(&hash_vec);
        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
    }
    let t1_compute_sum_final = m1_expected * basepoint1 + c1_c_expected;
    let t2_compute_sum_final = m1_expected * basepoint2 + c2_c_expected;
    if t1_sum_expected == t1_compute_sum_final
        && t2_sum_expected == t2_compute_sum_final
    {
        return Ok(true);
    }
    Ok(false)
}

fn small_scalar_point_mul(scalar: u8, point: RistrettoPoint) -> RistrettoPoint {
    let mut rbyte = scalar;
    let mut base_point = point;
    let mut result_point = RistrettoPoint::default();

    while rbyte != 0 {
        if rbyte & 1u8 == 1 {
            result_point = result_point + base_point;
        }
        base_point += base_point;
        rbyte >>= 1;
    }
    result_point
}

pub fn get_random_u8() -> u8 {
    let mut rng = rand::thread_rng();
    let blinding: u8 = rng.gen();
    blinding
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_crypto_zkp_utils::{
        get_random_u32, Serialize, BASEPOINT_G1, BASEPOINT_G2,
    };
    use wedpr_l_macros::wedpr_println;

    const BATCH_SIZE: usize = 10;

    #[test]
    fn test_either_equality() {
        let c1_value = 100u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let c2_value = c1_value;
        let c_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[c_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[c_basepoint, blinding_basepoint],
        );
        let c3_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(0u8), c3_blinding],
            &[c_basepoint, blinding_basepoint],
        );

        let proof = prove_either_equality_relationship_proof(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &c_basepoint,
            &blinding_basepoint,
        );
        assert_eq!(
            true,
            verify_either_equality_relationship_proof(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &c_basepoint,
                &blinding_basepoint,
            )
            .unwrap()
        );
        wedpr_println!("#### verify_either_equality_relationship_proof:");
        wedpr_println!(
            "#c1_point: {:?}",
            hex::encode(point_to_bytes(&c1_point))
        );
        wedpr_println!(
            "#c2_point: {:?}",
            hex::encode(point_to_bytes(&c2_point))
        );
        wedpr_println!(
            "#c3_point: {:?}",
            hex::encode(point_to_bytes(&c3_point))
        );

        wedpr_println!(
            "#basepoint: {:?}",
            hex::encode(point_to_bytes(&c_basepoint))
        );
        wedpr_println!(
            "#blinding_basepoint: {:?}",
            hex::encode(point_to_bytes(&blinding_basepoint))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
        wedpr_println!(
            "#### verify_either_equality_relationship_proof print finish"
        );
        let zero_c1_point = c1_blinding * blinding_basepoint;
        let proof_zero = prove_either_equality_relationship_proof(
            0,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &c_basepoint,
            &blinding_basepoint,
        );
        wedpr_println!(
            "#### verify_either_equality_relationship_proof: case proof zero"
        );
        wedpr_println!(
            "#c1_point: {:?}",
            hex::encode(point_to_bytes(&zero_c1_point))
        );
        wedpr_println!(
            "#c2_point: {:?}",
            hex::encode(point_to_bytes(&c2_point))
        );
        wedpr_println!(
            "#c3_point: {:?}",
            hex::encode(point_to_bytes(&c3_point))
        );

        wedpr_println!(
            "#basepoint: {:?}",
            hex::encode(point_to_bytes(&c_basepoint))
        );
        wedpr_println!(
            "#blinding_basepoint: {:?}",
            hex::encode(point_to_bytes(&blinding_basepoint))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof_zero.serialize()));
        wedpr_println!(
            "#### verify_either_equality_relationship_proof: case proof zero \
             print finish"
        );
        assert_eq!(
            true,
            verify_either_equality_relationship_proof(
                &zero_c1_point,
                &c2_point,
                &c3_point,
                &proof_zero,
                &c_basepoint,
                &blinding_basepoint,
            )
            .unwrap()
        );

        let invalid_c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(101u64), c1_blinding],
            &[c_basepoint, blinding_basepoint],
        );

        assert_eq!(
            false,
            verify_either_equality_relationship_proof(
                &invalid_c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &c_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_knowledge_proof_in_batch() {
        let mut proofs: Vec<KnowledgeProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let c1_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2 * get_random_scalar();
        for _ in 0..BATCH_SIZE {
            let c1_value = get_random_u32() as u64;
            let c1_blinding = get_random_scalar();

            let proof = prove_knowledge_proof(
                c1_value,
                &c1_blinding,
                &c1_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[c1_basepoint, blinding_basepoint],
            );

            wedpr_println!("#### verify_knowledge_proof: print begin");
            wedpr_println!(
                "#c1_point: {:?}",
                hex::encode(&point_to_bytes(&c1_point))
            );
            wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
            wedpr_println!(
                "#c1_basepoint: {:?}",
                hex::encode(&point_to_bytes(&c1_basepoint))
            );
            wedpr_println!(
                "#blinding_basepoint: {:?}",
                hex::encode(&point_to_bytes(&blinding_basepoint))
            );
            wedpr_println!("#### verify_knowledge_proof: print end");
            assert_eq!(
                true,
                verify_knowledge_proof(
                    &c1_point,
                    &proof,
                    &c1_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
        }
        assert_eq!(
            true,
            verify_knowledge_proof_in_batch(
                &c1_points,
                &proofs,
                &c1_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c1_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_knowledge_proof_in_batch(
                &c1_points,
                &proofs,
                &c1_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_format_proof_in_batch() {
        let mut proofs: Vec<FormatProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let c1_basepoint = *BASEPOINT_G1;
        let c2_basepoint = *BASEPOINT_G2;
        let blinding_basepoint = *BASEPOINT_G2 * get_random_scalar();
        for _ in 0..BATCH_SIZE {
            let c1_value = get_random_u32() as u64;
            let c1_blinding = get_random_scalar();

            let proof = prove_format_proof(
                c1_value,
                &c1_blinding,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[c1_basepoint, blinding_basepoint],
            );
            let c2_point = c1_blinding * c2_basepoint;
            wedpr_println!("#### verify_format_proof: print begin");
            wedpr_println!(
                "#c1_point: {:?}",
                hex::encode(&point_to_bytes(&c1_point))
            );
            wedpr_println!(
                "#c2_point: {:?}",
                hex::encode(&point_to_bytes(&c2_point))
            );
            wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
            wedpr_println!(
                "#c1_basepoint: {:?}",
                hex::encode(&point_to_bytes(&c1_basepoint))
            );
            wedpr_println!(
                "#c2_basepoint: {:?}",
                hex::encode(&point_to_bytes(&c2_basepoint))
            );
            wedpr_println!(
                "#blinding_basepoint: {:?}",
                hex::encode(&point_to_bytes(&blinding_basepoint))
            );
            wedpr_println!("#### verify_format_proof: print end");
            assert_eq!(
                true,
                verify_format_proof(
                    &c1_point,
                    &c2_point,
                    &proof,
                    &c1_basepoint,
                    &c2_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
        }
        assert_eq!(
            true,
            verify_format_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_format_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_sum_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_sum_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        // c3 = c1 + c2
        let c3_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value + c2_value), c3_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        assert_eq!(
            true,
            verify_sum_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        wedpr_println!("#### verify_sum_relationship: print begin");
        wedpr_println!(
            "#c1_point: {:?}",
            hex::encode(&point_to_bytes(&c1_point))
        );
        wedpr_println!(
            "#c2_point: {:?}",
            hex::encode(&point_to_bytes(&c2_point))
        );
        wedpr_println!(
            "#c3_point: {:?}",
            hex::encode(&point_to_bytes(&c3_point))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
        wedpr_println!(
            "#value_basepoint: {:?}",
            hex::encode(&point_to_bytes(&value_basepoint))
        );
        wedpr_println!(
            "#blinding_basepoint: {:?}",
            hex::encode(&point_to_bytes(&blinding_basepoint))
        );
        wedpr_println!("#### verify_sum_relationship: print end");
    }

    #[test]
    fn test_sum_relationship_proof_in_batch() {
        let mut proofs: Vec<ArithmeticProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let mut c3_points: Vec<RistrettoPoint> = vec![];
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
            let c1_value = 30u64;
            let c2_value = 10u64;
            let c1_blinding = get_random_scalar();
            let c2_blinding = get_random_scalar();
            let c3_blinding = get_random_scalar();
            let value_basepoint = *BASEPOINT_G1;
            let blinding_basepoint = *BASEPOINT_G2;

            let proof = prove_sum_relationship(
                c1_value,
                c2_value,
                &c1_blinding,
                &c2_blinding,
                &c3_blinding,
                &value_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            let c2_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c2_value), c2_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            // c3 = c1 + c2
            let c3_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value + c2_value), c3_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            assert_eq!(
                true,
                verify_sum_relationship(
                    &c1_point,
                    &c2_point,
                    &c3_point,
                    &proof,
                    &value_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
            c3_points.push(c3_point);
        }
        assert_eq!(
            true,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_product_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_product_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        // c3 = c1 * c2
        let c3_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value * c2_value), c3_blinding],
            &[value_basepoint, blinding_basepoint],
        );

        wedpr_println!("#### verify_product_relationship: print begin");
        wedpr_println!(
            "#c1_point: {:?}",
            hex::encode(&point_to_bytes(&c1_point))
        );
        wedpr_println!(
            "#c2_point: {:?}",
            hex::encode(&point_to_bytes(&c2_point))
        );
        wedpr_println!(
            "#c3_point: {:?}",
            hex::encode(&point_to_bytes(&c3_point))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
        wedpr_println!(
            "#value_basepoint: {:?}",
            hex::encode(&point_to_bytes(&value_basepoint))
        );
        wedpr_println!(
            "#blinding_basepoint: {:?}",
            hex::encode(&point_to_bytes(&blinding_basepoint))
        );
        wedpr_println!("#### verify_product_relationship: print end");
        assert_eq!(
            true,
            verify_product_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_product_relationship_proof_in_batch() {
        let mut proofs: Vec<ArithmeticProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let mut c3_points: Vec<RistrettoPoint> = vec![];
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
            let c1_value = 30u64;
            let c2_value = 10u64;
            let c1_blinding = get_random_scalar();
            let c2_blinding = get_random_scalar();
            let c3_blinding = get_random_scalar();
            let value_basepoint = *BASEPOINT_G1;
            let blinding_basepoint = *BASEPOINT_G2;

            let proof = prove_product_relationship(
                c1_value,
                c2_value,
                &c1_blinding,
                &c2_blinding,
                &c3_blinding,
                &value_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            let c2_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c2_value), c2_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            // c3 = c1 * c2
            let c3_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value * c2_value), c3_blinding],
                &[value_basepoint, blinding_basepoint],
            );
            assert_eq!(
                true,
                verify_product_relationship(
                    &c1_point,
                    &c2_point,
                    &c3_point,
                    &proof,
                    &value_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
            c3_points.push(c3_point);
        }
        assert_eq!(
            true,
            verify_product_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_equality_relationship_proof() {
        let c_value = get_random_scalar();
        let c_wrong_value = get_random_scalar();
        let basepoint1 = *BASEPOINT_G1;
        let basepoint2 = *BASEPOINT_G2;
        let c1_point = basepoint1 * &c_value;
        let c2_point = basepoint2 * &c_value;
        let proof = prove_equality_relationship_proof(
            &c_value,
            &basepoint1,
            &basepoint2,
        );
        wedpr_println!("#### verify_equality_relationship_proof: print begin");
        wedpr_println!(
            "#c1_point: {:?}",
            hex::encode(&point_to_bytes(&c1_point))
        );
        wedpr_println!(
            "#c2_point: {:?}",
            hex::encode(&point_to_bytes(&c2_point))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
        wedpr_println!(
            "#basepoint1: {:?}",
            hex::encode(&point_to_bytes(&basepoint1))
        );
        wedpr_println!(
            "#basepoint2: {:?}",
            hex::encode(&point_to_bytes(&basepoint2))
        );
        wedpr_println!("#### verify_equality_relationship_proof: print end");
        assert_eq!(
            true,
            verify_equality_relationship_proof(
                &c1_point,
                &c2_point,
                &proof,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
        let c2_wrong_point = basepoint2 * &c_wrong_value;
        assert_eq!(
            false,
            verify_equality_relationship_proof(
                &c1_point,
                &c2_wrong_point,
                &proof,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
    }

    #[test]
    fn test_equality_relationship_proof_in_batch() {
        let mut proofs: Vec<EqualityProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let basepoint1 = *BASEPOINT_G1;
        let basepoint2 = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
            let c_value = get_random_scalar();
            let c1_point = basepoint1 * &c_value;
            let c2_point = basepoint2 * &c_value;
            let proof = prove_equality_relationship_proof(
                &c_value,
                &basepoint1,
                &basepoint2,
            );
            assert_eq!(
                true,
                verify_equality_relationship_proof(
                    &c1_point,
                    &c2_point,
                    &proof,
                    &basepoint1,
                    &basepoint2
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
        }
        assert_eq!(
            true,
            verify_equality_relationship_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_equality_relationship_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
    }

    #[test]
    fn test_fast_small_scalar_point() {
        for i in 0..255u8 {
            let scalar = i;
            let point = *BASEPOINT_G1;
            let point_get = small_scalar_point_mul(scalar, point);
            let expect_point = Scalar::from(scalar) * point;
            assert_eq!(
                point_to_bytes(&point_get),
                point_to_bytes(&expect_point)
            );
        }
    }

    #[test]
    fn test_value_equality_proof() {
        let c1_value = 100u64;
        let c1_scalar = Scalar::from(c1_value);
        let c1_blinding = get_random_scalar();
        let commitment =
            c1_scalar * *BASEPOINT_G1 + c1_blinding * *BASEPOINT_G2;

        let proof = prove_value_equality_relationship_proof(
            c1_value,
            &c1_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );
        assert_eq!(
            true,
            verify_value_equality_relationship_proof(
                c1_value,
                &commitment,
                &proof,
                &BASEPOINT_G1,
                &BASEPOINT_G2
            )
            .unwrap()
        );

        let c2_value = 101u64;
        let c2_scalar = Scalar::from(c2_value);
        let c2_blinding = get_random_scalar();

        assert_eq!(
            false,
            verify_value_equality_relationship_proof(
                c2_value,
                &commitment,
                &proof,
                &BASEPOINT_G1,
                &BASEPOINT_G2
            )
            .unwrap()
        );

        let commitment2 =
            c2_scalar * *BASEPOINT_G1 + c2_blinding * *BASEPOINT_G2;
        let proof2 = prove_value_equality_relationship_proof(
            c2_value,
            &c2_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );
        assert_eq!(
            true,
            verify_value_equality_relationship_proof(
                c2_value,
                &commitment2,
                &proof2,
                &BASEPOINT_G1,
                &BASEPOINT_G2
            )
            .unwrap()
        );

        let result = verify_value_equality_relationship_proof(
            c2_value,
            &commitment,
            &proof,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        )
        .unwrap();
        assert_eq!(false, result);

        wedpr_println!(
            "#### verify_value_equality_relationship_proof: print begin"
        );
        wedpr_println!(
            "#commitment: {:?}",
            hex::encode(&point_to_bytes(&commitment))
        );
        wedpr_println!("#proof: {:?}", hex::encode(proof.serialize()));
    }

    #[test]
    fn test_multi_sum_relationship() {
        let input_length = 10;
        let output_length = 4;
        let mut input_values: Vec<u64> = vec![];
        let mut input_blindings: Vec<Scalar> = vec![];
        let mut input_commitments: Vec<RistrettoPoint> = vec![];
        let mut output_blindings: Vec<Scalar> = vec![];
        let mut output_values: Vec<u64> = vec![];
        let mut output_commitments: Vec<RistrettoPoint> = vec![];
        let mut output_commitments_error: Vec<RistrettoPoint> = vec![];
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let mut spend_sum = 0;
        for i in 0..input_length {
            let value = i as u64;
            let blinding = get_random_scalar();
            input_values.push(value);
            input_blindings.push(blinding);
            spend_sum += value;
            let scalar_value = Scalar::from(value);
            input_commitments.push(
                scalar_value * value_basepoint + blinding * blinding_basepoint,
            );
        }
        for i in 0..output_length - 1 {
            let value = i as u64;
            let blinding = get_random_scalar();
            output_values.push(value);
            output_blindings.push(blinding);
            output_commitments.push(
                value_basepoint * Scalar::from(value)
                    + blinding * blinding_basepoint,
            );
            output_commitments_error.push(
                value_basepoint * Scalar::from(value + 1)
                    + blinding * blinding_basepoint,
            );
        }
        let final_unspent = spend_sum - output_values.iter().sum::<u64>();
        output_values.push(final_unspent);
        output_blindings.push(get_random_scalar());
        output_commitments.push(
            value_basepoint * Scalar::from(final_unspent)
                + output_blindings[output_length - 1] * blinding_basepoint,
        );

        let proof = prove_multi_sum_relationship(
            &input_values,
            &input_blindings,
            &output_values,
            &output_blindings,
            &value_basepoint,
            &blinding_basepoint,
        );
        assert_eq!(
            true,
            verify_multi_sum_relationship(
                &input_commitments,
                &output_commitments,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );

        // error case
        // 1. error input commitment
        let mut error_input_commitments = input_commitments.clone();
        error_input_commitments[0] =
            error_input_commitments[0] + value_basepoint;
        assert_eq!(
            false,
            verify_multi_sum_relationship(
                &error_input_commitments,
                &output_commitments,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );

        // 2. error output commitment
        let mut error_output_commitments = output_commitments.clone();
        error_output_commitments[0] =
            error_output_commitments[0] + value_basepoint;
        assert_eq!(
            false,
            verify_multi_sum_relationship(
                &input_commitments,
                &error_output_commitments,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );

        // 3. error proof
        let mut error_proof = proof.clone();
        error_proof.check = error_proof.check + Scalar::from(1u8);
        assert_eq!(
            false,
            verify_multi_sum_relationship(
                &input_commitments,
                &output_commitments,
                &error_proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );

        // fake error input commitment
        error_proof.check = error_proof.check + Scalar::from(1u8);
        assert_eq!(
            false,
            verify_multi_sum_relationship(
                &input_commitments,
                &output_commitments_error,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_sum_relation_ship_with_round()
    {
        let input_count = 10;
        let output_count = 5;
        let mut input_blindings = Vec::new();
        let mut input_private_part = Vec::new();
        let mut input_public_part = Vec::new();
        let mut input_commitments = Vec::new();

        let mut output_private_part = Vec::new();
        let mut output_public_part = Vec::new();
        let mut output_commitments = Vec::new();
        let mut output_blidings = Vec::new();

        // 45
        let mut input_value_sum = 0;
        for i in 0..input_count 
        {
            let value = i as u64;
            input_value_sum += value;
            let blinding = get_random_scalar();
            let scalar_value = Scalar::from(value);
            input_blindings.push(blinding);
            input_commitments.push(
                scalar_value * *BASEPOINT_G1 + blinding * *BASEPOINT_G2,
            );
            let (private_part, public_part ) = sender_prove_multi_sum_relationship_setup(value, &blinding, &BASEPOINT_G1, &BASEPOINT_G2);
            input_private_part.push(private_part);
            input_public_part.push(public_part);
        }
        wedpr_println!("input_value_sum: {:?}", input_value_sum);
        // 15
        let mut output_value_sum = 0;
        for i in 0..output_count
        {
            let value = i as u64 + 7;
            output_value_sum += value;
            let blinding = get_random_scalar();
            output_blidings.push(blinding);
            output_commitments.push(
                *BASEPOINT_G1 * Scalar::from(value)
                    + blinding * *BASEPOINT_G2,
            );
            let (private_part, public_part ) = receiver_prove_multi_sum_relationship_setup(value, &blinding, &BASEPOINT_G1, &BASEPOINT_G2);
            output_private_part.push(private_part);
            output_public_part.push(public_part);
        }
        wedpr_println!("output_value_sum: {:?}", output_value_sum);
        assert_eq!(input_value_sum, output_value_sum);

        let check = coordinator_prove_multi_sum_relationship_setup(&input_public_part, &output_public_part, &BASEPOINT_G1, &BASEPOINT_G2);

        let mut sender_public_parts = Vec::new();
        let mut receiver_public_parts = Vec::new();
        for i in 0..input_count 
        {
            let sender_public_part = sender_prove_multi_sum_relationship_final(i as u64, &input_blindings[i], &input_private_part[i], &check);
            sender_public_parts.push(sender_public_part);
        }

        for i in 0..output_count
        {
            let receiver_public_part = receiver_prove_multi_sum_relationship_final(&output_blidings[i], &output_private_part[i], &check);
            receiver_public_parts.push(receiver_public_part);
        }

        let result_proof = coordinator_prove_multi_sum_relationship_final(&check, &sender_public_parts, &receiver_public_parts);

        assert_eq!(
            true,
            verify_multi_sum_relationship(&input_commitments, &output_commitments, &result_proof, &BASEPOINT_G1, &BASEPOINT_G2)
            .unwrap()
        );


    }
}
