use std::fs::File;
use std::io::Write;

use curve25519_dalek::Scalar;
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{prove_knowledge_proof, prove_multi_sum_relationship, prove_sum_relationship, prove_value_equality_relationship_proof, verify_knowledge_proof, verify_multi_sum_relationship, verify_sum_relationship, verify_value_equality_relationship_proof};
use wedpr_l_crypto_zkp_range_proof::{prove_value_range_with_blinding, prove_value_range_with_blinding_and_blinding_basepoint, verify_value_range_with_blinding_basepoint};
use wedpr_l_crypto_zkp_utils::{get_random_scalar, point_to_bytes, Serialize, BASEPOINT_G1, BASEPOINT_G2};
#[macro_use]
extern crate wedpr_l_macros;

fn main() {
    // generate_mint_file(100);
    demo();
}

fn generate_mint_file(count: u64) {
    let mut file_proof = File::create("mint_proof.txt").unwrap();
    let mut file_commitment = File::create("mint_commitment.txt").unwrap();
    let mut file_commitment2 = File::create("transfer_commitment2.txt").unwrap();
    let mut file_commitment3 = File::create("transfer_commitment3.txt").unwrap();
    let mut file_proof_range1 = File::create("transfer_range_proof1.txt").unwrap();
    let mut file_proof_range2 = File::create("transfer_range_proof2.txt").unwrap();
    let mut file_proof_balance = File::create("transfer_balance_proof.txt").unwrap();
    let mut file_proof_knowledge = File::create("transfer_knowledge_proof.txt").unwrap();
    let mut file_commitment_withdraw = File::create("withdraw_commitment.txt").unwrap();
    let mut file_proof_withdraw_knowledge = File::create("withdraw_knowledge_proof.txt").unwrap();
    let mut file_proof_withdraw_value = File::create("withdraw_value_proof.txt").unwrap();

    for _ in 0..count
    {   
        // 1 mint
        let value = 1;
        let c_scalar = Scalar::from(value);
        let c_blinding = get_random_scalar();
        let c_commitment = c_scalar * *BASEPOINT_G1 + c_blinding * *BASEPOINT_G2;
        let value_proof: wedpr_l_crypto_zkp_utils::ValueQualityProof = prove_value_equality_relationship_proof(value, &c_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
        assert_eq!(true, verify_value_equality_relationship_proof(value, &c_commitment, &value_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
        writeln!(file_commitment, "{}", hex::encode(&point_to_bytes(&c_commitment)));
        writeln!(file_proof, "{}", hex::encode(&value_proof.serialize()));

        // 2 transfer

        let c2_value = 1u64;
        let c2_scalar = Scalar::from(c2_value);
        let c2_blinding = get_random_scalar();
        let c2_commitment = c2_scalar * *BASEPOINT_G1 + c2_blinding * *BASEPOINT_G2;

        let c3_value = value - c2_value;
        let c3_scalar = Scalar::from(c3_value);
        let c3_blinding = get_random_scalar();
        let c3_commitment = c3_scalar * *BASEPOINT_G1 + c3_blinding * *BASEPOINT_G2;

        let knowledge_proof = prove_knowledge_proof(value, &c_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
        assert_eq!(true, verify_knowledge_proof(&c_commitment, &knowledge_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());

        let balance_proof = prove_sum_relationship(
            c2_value,
            c3_value,
            &c2_blinding,
            &c3_blinding,
            &c_blinding,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
        );

        assert_eq!(
            true,
            verify_sum_relationship(
                &c2_commitment,
                &c3_commitment,
                &c_commitment,
                &balance_proof,
                &BASEPOINT_G1,
                &BASEPOINT_G2
            )
            .unwrap()
        );
    
        let (rangeproof_c2, expected_commitment2) = prove_value_range_with_blinding_and_blinding_basepoint(c2_value, &c2_blinding, &BASEPOINT_G2);
        let (rangeproof_c3, expected_commitment3) = prove_value_range_with_blinding_and_blinding_basepoint(c3_value, &c3_blinding, &BASEPOINT_G2);
        
        assert_eq!(true, verify_value_range_with_blinding_basepoint(&c2_commitment, &rangeproof_c2, &BASEPOINT_G2));
        assert_eq!(true, verify_value_range_with_blinding_basepoint(&c3_commitment, &rangeproof_c3, &BASEPOINT_G2));
        assert_eq!(true, c2_commitment == expected_commitment2);
        assert_eq!(true, c3_commitment == expected_commitment3);

        writeln!(file_commitment2, "{}", hex::encode(&point_to_bytes(&c2_commitment)));
        writeln!(file_commitment3, "{}", hex::encode(&point_to_bytes(&c3_commitment)));
        writeln!(file_proof_range1, "{}", hex::encode(rangeproof_c2.clone()));
        writeln!(file_proof_range2, "{}", hex::encode(rangeproof_c3.clone()));
        writeln!(file_proof_balance, "{}", hex::encode(balance_proof.serialize()));
        writeln!(file_proof_knowledge, "{}", hex::encode(knowledge_proof.serialize()));

        // 3 withdraw
        let knowledge_proof = prove_knowledge_proof(c3_value, &c3_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
        assert_eq!(true, verify_knowledge_proof(&c3_commitment, &knowledge_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
        let value_proof = prove_value_equality_relationship_proof(c3_value, &c3_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
        assert_eq!(true, verify_value_equality_relationship_proof(c3_value, &c3_commitment, &value_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
        writeln!(file_commitment_withdraw, "{}", hex::encode(&point_to_bytes(&c3_commitment)));
        writeln!(file_proof_withdraw_knowledge, "{}", hex::encode(knowledge_proof.serialize()));
        writeln!(file_proof_withdraw_value, "{}", hex::encode(value_proof.serialize()));
    }
}

fn demo()
{
    // 1. 生成commitment 生成value证明，链上入金
    // value_proof证明commitment钱和value相等
    let c1_value = 100u64;
    let c1_scalar = Scalar::from(c1_value);
    let c1_blinding = get_random_scalar();
    let c1_commitment = c1_scalar * *BASEPOINT_G1 + c1_blinding * *BASEPOINT_G2;

    let value_proof = prove_value_equality_relationship_proof(c1_value, &c1_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
    assert_eq!(true, verify_value_equality_relationship_proof(c1_value, &c1_commitment, &value_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());

    wedpr_println!(
        "#c1_value: {:?}",
        c1_value
    );
    wedpr_println!(
        "#c1_commitment: {:?}",
        hex::encode(&point_to_bytes(&c1_commitment))
    );
    wedpr_println!(
        "#value_proof: {:?}",
        hex::encode(value_proof.serialize())
    );
    
    // 2. 生成transfer_proof，链上转账 
    // knowledge proof证明拥有所有权
    // balance proof 会计平衡
    // range proof防止作恶
    let knowledge_proof = prove_knowledge_proof(c1_value, &c1_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
    assert_eq!(true, verify_knowledge_proof(&c1_commitment, &knowledge_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
    wedpr_println!(
        "#c1 knowledge_proof: {:?}",
        hex::encode(knowledge_proof.serialize())
    );

    let mut input_value_list = Vec::new();
    let mut input_bliding_list = Vec::new();
    input_value_list.push(c1_value);
    input_bliding_list.push(c1_blinding);

    let mut output_value_list = Vec::new();
    let mut output_blinding_list = Vec::new();
    let c2_value = 51u64;
    let c2_scalar = Scalar::from(c2_value);
    let c2_blinding = get_random_scalar();
    let c2_commitment = c2_scalar * *BASEPOINT_G1 + c2_blinding * *BASEPOINT_G2;

    let c3_value = c1_value - c2_value;
    let c3_scalar = Scalar::from(c3_value);
    let c3_blinding = get_random_scalar();
    let c3_commitment = c3_scalar * *BASEPOINT_G1 + c3_blinding * *BASEPOINT_G2;
    output_value_list.push(c2_value);
    output_value_list.push(c3_value);
    output_blinding_list.push(c2_blinding);
    output_blinding_list.push(c3_blinding);

    
    let balance_proof = prove_multi_sum_relationship(
        &input_value_list,
        &input_bliding_list,
        &output_value_list,
        &output_blinding_list,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

    let input_commitments = vec![c1_commitment];
    let output_commitments = vec![c2_commitment, c3_commitment];

    wedpr_println!(
        "#c2_value: {:?}",
        c2_value
    );
    wedpr_println!(
        "#c2_commitment: {:?}",
        hex::encode(&point_to_bytes(&c2_commitment))
    );
    wedpr_println!(
        "#c3_value: {:?}",
        c3_value
    );
    wedpr_println!(
        "#c3_commitment: {:?}",
        hex::encode(&point_to_bytes(&c3_commitment))
    );
    wedpr_println!(
        "#balance_proof: {:?}",
        hex::encode(balance_proof.serialize())
    );

    assert_eq!(
        true,
        verify_multi_sum_relationship(
            &input_commitments,
            &output_commitments,
            &balance_proof,
            &BASEPOINT_G1,
            &BASEPOINT_G2
        )
        .unwrap()
    );

    let (rangeproof_c2, expected_commitment2) = prove_value_range_with_blinding_and_blinding_basepoint(c2_value, &c2_blinding, &BASEPOINT_G2);
    let (rangeproof_c3, expected_commitment3) = prove_value_range_with_blinding_and_blinding_basepoint(c3_value, &c3_blinding, &BASEPOINT_G2);

    assert_eq!(true, c2_commitment == expected_commitment2);
    assert_eq!(true, c3_commitment == expected_commitment3);

    wedpr_println!(
        "#rangeproof_c2: {:?}",
        hex::encode(rangeproof_c2.clone())
    );
    wedpr_println!(
        "#rangeproof_c3: {:?}",
        hex::encode(rangeproof_c3.clone())
    );

    assert_eq!(true, verify_value_range_with_blinding_basepoint(&c2_commitment, &rangeproof_c2, &BASEPOINT_G2));
    assert_eq!(true, verify_value_range_with_blinding_basepoint(&c3_commitment, &rangeproof_c3, &BASEPOINT_G2));

    // 3. 生成 出金证明 将c3转出
    // knowledge proof证明拥有所有权 
    // value_proof证明commitment钱和value相等

    let knowledge_proof = prove_knowledge_proof(c3_value, &c3_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
    assert_eq!(true, verify_knowledge_proof(&c3_commitment, &knowledge_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
    wedpr_println!(
        "c3 #knowledge_proof: {:?}",
        hex::encode(knowledge_proof.serialize())
    );

    let value_proof = prove_value_equality_relationship_proof(c3_value, &c3_blinding, &BASEPOINT_G1, &BASEPOINT_G2);
    assert_eq!(true, verify_value_equality_relationship_proof(c3_value, &c3_commitment, &value_proof, &BASEPOINT_G1, &BASEPOINT_G2).unwrap());
    wedpr_println!(
        "c3 #value_proof: {:?}",
        hex::encode(value_proof.serialize())
    );
    wedpr_println!(
        "#c3_commitment: {:?}",
        hex::encode(&point_to_bytes(&c3_commitment))
    );
}
