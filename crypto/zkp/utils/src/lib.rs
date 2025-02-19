// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions for ZKP.
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

mod config;
use config::HASH;
use rand::Rng;
use sha3::Sha3_512;
use std::convert::TryInto;
use wedpr_l_utils::{error::WedprError, traits::Hash};

lazy_static! {
    /// A base point used by various crypto algorithms.
    pub static ref BASEPOINT_G1: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    /// Another base point used by various crypto algorithms.
    pub static ref BASEPOINT_G2: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(
            RISTRETTO_BASEPOINT_COMPRESSED.as_bytes()
        );
}

/// Serialized data size of a point.
const RISTRETTO_POINT_SIZE_IN_BYTES: usize = 32;
const SCALAR_SIZE_IN_BYTE: usize = 32;

/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError>;
}

#[derive(Default, Debug, Clone)]
pub struct Commitments {
    pub commitments: Vec<RistrettoPoint>,
}

impl Serialize for Commitments {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for commitment in &self.commitments {
            buf.extend(&(point_to_bytes(commitment)));
        }
        buf
    }
}

impl Deserialize for Commitments {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        let mut offset = 0;
        let mut commitments = Vec::new();
        while offset < bytes.len() {
            let commitment = bytes_to_point(&bytes[offset..])?;
            commitments.push(commitment);
            offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        }
        Ok(Commitments {
            commitments: commitments,
        })
    }
}

// ZKP data to verify the balance relationship among value commitments.
// For example, given C(x), C(y), C(z), this proof data can be used to
// verify whether x * y =? z.
#[derive(Default, Debug, Clone)]
pub struct ValueEqualityProof {
    pub check: Scalar,
    pub m1: Scalar,
    pub m2: Scalar,
}

impl Serialize for ValueEqualityProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 * SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.check)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf
    }
}

impl Deserialize for ValueEqualityProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 3 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        // decode check
        let mut offset = 0;
        let check =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m1
        offset += SCALAR_SIZE_IN_BYTE;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(ValueEqualityProof {
            check: check,
            m1: m1,
            m2: m2,
        })
    }
}

// ZKP data to verify the balance relationship among value commitments.
// For example, given C(x), C(y), C(z), this proof data can be used to
// verify whether x * y =? z.
#[derive(Default, Debug, Clone)]
pub struct BalanceProof {
    pub check1: Scalar,
    pub check2: Scalar,
    pub m1: Scalar,
    pub m2: Scalar,
    pub m3: Scalar,
    pub m4: Scalar,
    pub m5: Scalar,
    pub m6: Scalar,
}

impl Serialize for BalanceProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 * SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.check1)));
        buf.extend(&(scalar_to_bytes(&self.check2)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf.extend(&(scalar_to_bytes(&self.m3)));
        buf.extend(&(scalar_to_bytes(&self.m4)));
        buf.extend(&(scalar_to_bytes(&self.m5)));
        buf.extend(&(scalar_to_bytes(&self.m6)));
        buf
    }
}

impl Deserialize for BalanceProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 8 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        // decode check1
        let mut offset = 0;
        let check1 =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode check2
        offset += SCALAR_SIZE_IN_BYTE;
        let check2 =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m1
        offset += SCALAR_SIZE_IN_BYTE;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m3
        offset += SCALAR_SIZE_IN_BYTE;
        let m3 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m4
        offset += SCALAR_SIZE_IN_BYTE;
        let m4 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m5
        offset += SCALAR_SIZE_IN_BYTE;
        let m5 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m6
        offset += SCALAR_SIZE_IN_BYTE;
        let m6 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(BalanceProof {
            check1: check1,
            check2: check2,
            m1: m1,
            m2: m2,
            m3: m3,
            m4: m4,
            m5: m5,
            m6: m6,
        })
    }
}
#[derive(Default, Debug, Clone)]
pub struct KnowledgeProof {
    pub t1: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
}

impl Serialize for KnowledgeProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 * SCALAR_SIZE_IN_BYTE + RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf
    }
}

impl Deserialize for KnowledgeProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 2 * SCALAR_SIZE_IN_BYTE + RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(KnowledgeProof {
            t1: t1,
            m1: m1,
            m2: m2,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct FormatProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
}

impl Serialize for FormatProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 * SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf
    }
}

impl Deserialize for FormatProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len()
            < 2 * SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(FormatProof {
            t1: t1,
            t2: t2,
            m1: m1,
            m2: m2,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ReceiverRelationshipProofSetupPrivate {
    pub f_blinding: Scalar,
}

impl Serialize for ReceiverRelationshipProofSetupPrivate {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.f_blinding)));
        buf
    }
}

impl Deserialize for ReceiverRelationshipProofSetupPrivate {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        let f_blinding = bytes_to_scalar(&bytes[0..SCALAR_SIZE_IN_BYTE])?;
        Ok(ReceiverRelationshipProofSetupPrivate {
            f_blinding: f_blinding,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ReceiverRelationshipProofSetupPublicList {
    pub receiver_setup_list: Vec<ReceiverRelationshipProofSetupPublic>
}

impl Serialize for ReceiverRelationshipProofSetupPublicList {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for setup in &self.receiver_setup_list {
            buf.extend(&(setup.serialize()));
        }
        buf
    }
}

impl Deserialize for ReceiverRelationshipProofSetupPublicList {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        let mut offset = 0;
        let mut receiver_setup_list = Vec::new();
        while offset < bytes.len() {
            let setup = ReceiverRelationshipProofSetupPublic::deserialize(
                &bytes[offset..],
            )?;
            receiver_setup_list.push(setup);
            offset += 2 * RISTRETTO_POINT_SIZE_IN_BYTES;
        }
        Ok(ReceiverRelationshipProofSetupPublicList {
            receiver_setup_list: receiver_setup_list,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ReceiverRelationshipProofSetupPublic {
    pub f_commit: RistrettoPoint,
    pub commitment: RistrettoPoint,
}

impl Serialize for ReceiverRelationshipProofSetupPublic {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 * RISTRETTO_POINT_SIZE_IN_BYTES);
        buf.extend(&(point_to_bytes(&self.f_commit)));
        buf.extend(&(point_to_bytes(&self.commitment)));
        buf
    }
}

impl Deserialize for ReceiverRelationshipProofSetupPublic {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 2 * RISTRETTO_POINT_SIZE_IN_BYTES {
            return Err(WedprError::ArgumentError);
        }
        let f_commit =
            bytes_to_point(&bytes[0..RISTRETTO_POINT_SIZE_IN_BYTES])?;
        let commitment = bytes_to_point(
            &bytes[RISTRETTO_POINT_SIZE_IN_BYTES
                ..2 * RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        Ok(ReceiverRelationshipProofSetupPublic {
            f_commit: f_commit,
            commitment: commitment,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct SenderRelationshipProofSetupPrivate {
    pub blinding_a: Scalar,
    pub blinding_b: Scalar,
}

impl Serialize for SenderRelationshipProofSetupPrivate {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 * SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.blinding_a)));
        buf.extend(&(scalar_to_bytes(&self.blinding_b)));
        buf
    }
}

impl Deserialize for SenderRelationshipProofSetupPrivate {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 2 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        let blinding_a = bytes_to_scalar(&bytes[0..SCALAR_SIZE_IN_BYTE])?;
        let blinding_b = bytes_to_scalar(
            &bytes[SCALAR_SIZE_IN_BYTE..2 * SCALAR_SIZE_IN_BYTE],
        )?;
        Ok(SenderRelationshipProofSetupPrivate {
            blinding_a: blinding_a,
            blinding_b: blinding_b,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct SenderRelationshipProofSetupPublicList {
    pub sender_setup_list: Vec<SenderRelationshipProofSetupPublic>
}

impl Serialize for SenderRelationshipProofSetupPublicList {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for setup in &self.sender_setup_list {
            buf.extend(&(setup.serialize()));
        }
        buf
    }
}

impl Deserialize for SenderRelationshipProofSetupPublicList {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        let mut offset = 0;
        let mut sender_setup_list = Vec::new();
        while offset < bytes.len() {
            let setup = SenderRelationshipProofSetupPublic::deserialize(
                &bytes[offset..],
            )?;
            sender_setup_list.push(setup);
            offset += 3 * RISTRETTO_POINT_SIZE_IN_BYTES;
        }
        Ok(SenderRelationshipProofSetupPublicList {
            sender_setup_list: sender_setup_list,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct SenderRelationshipProofSetupPublic {
    pub t_commit: RistrettoPoint,
    pub a_commit: RistrettoPoint,
    pub commitment: RistrettoPoint,
}

impl Serialize for SenderRelationshipProofSetupPublic {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 * RISTRETTO_POINT_SIZE_IN_BYTES);
        buf.extend(&(point_to_bytes(&self.t_commit)));
        buf.extend(&(point_to_bytes(&self.a_commit)));
        buf.extend(&(point_to_bytes(&self.commitment)));
        buf
    }
}

impl Deserialize for SenderRelationshipProofSetupPublic {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 3 * RISTRETTO_POINT_SIZE_IN_BYTES {
            return Err(WedprError::ArgumentError);
        }
        let t_commit =
            bytes_to_point(&bytes[0..RISTRETTO_POINT_SIZE_IN_BYTES])?;
        let a_commit = bytes_to_point(
            &bytes[RISTRETTO_POINT_SIZE_IN_BYTES
                ..2 * RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        let commitment = bytes_to_point(
            &bytes[2 * RISTRETTO_POINT_SIZE_IN_BYTES
                ..3 * RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        Ok(SenderRelationshipProofSetupPublic {
            t_commit: t_commit,
            a_commit: a_commit,
            commitment: commitment,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct SenderRelationshipProofFinalPublicList {
    pub sender_final_list: Vec<SenderRelationshipProofFinalPublic>
}

impl Serialize for SenderRelationshipProofFinalPublicList {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for final_public in &self.sender_final_list {
            buf.extend(&(final_public.serialize()));
        }
        buf
    }
}

impl Deserialize for SenderRelationshipProofFinalPublicList {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        let mut offset = 0;
        let mut sender_final_list = Vec::new();
        while offset < bytes.len() {
            let final_public =
                SenderRelationshipProofFinalPublic::deserialize(&bytes[offset..])?;
            sender_final_list.push(final_public);
            offset += 2 * SCALAR_SIZE_IN_BYTE;
        }
        Ok(SenderRelationshipProofFinalPublicList {
            sender_final_list: sender_final_list,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct SenderRelationshipProofFinalPublic {
    pub m: Scalar,
    pub n: Scalar,
}

impl Serialize for SenderRelationshipProofFinalPublic {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 * SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.m)));
        buf.extend(&(scalar_to_bytes(&self.n)));
        buf
    }
}

impl Deserialize for SenderRelationshipProofFinalPublic {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 2 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        let m = bytes_to_scalar(&bytes[0..SCALAR_SIZE_IN_BYTE])?;
        let n = bytes_to_scalar(
            &bytes[SCALAR_SIZE_IN_BYTE..2 * SCALAR_SIZE_IN_BYTE],
        )?;
        Ok(SenderRelationshipProofFinalPublic { m: m, n: n })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ReceiverRelationshipProofFinalPublicList {
    pub receiver_final_list: Vec<ReceiverRelationshipProofFinalPublic>
} 

impl Serialize for ReceiverRelationshipProofFinalPublicList {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for final_public in &self.receiver_final_list {
            buf.extend(&(final_public.serialize()));
        }
        buf
    }
}

impl Deserialize for ReceiverRelationshipProofFinalPublicList {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        let mut offset = 0;
        let mut receiver_final_list = Vec::new();
        while offset < bytes.len() {
            let final_public =
                ReceiverRelationshipProofFinalPublic::deserialize(&bytes[offset..])?;
            receiver_final_list.push(final_public);
            offset += SCALAR_SIZE_IN_BYTE;
        }
        Ok(ReceiverRelationshipProofFinalPublicList {
            receiver_final_list: receiver_final_list,
        })
    }
}


#[derive(Default, Debug, Clone)]
pub struct ReceiverRelationshipProofFinalPublic {
    pub t_commit_share: Scalar,
}

impl Serialize for ReceiverRelationshipProofFinalPublic {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.t_commit_share)));
        buf
    }
}

impl Deserialize for ReceiverRelationshipProofFinalPublic {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        let t_commit_share = bytes_to_scalar(&bytes[0..SCALAR_SIZE_IN_BYTE])?;
        Ok(ReceiverRelationshipProofFinalPublic {
            t_commit_share: t_commit_share,
        })
    }
}
#[derive(Default, Debug, Clone)]
pub struct RelationshipProof {
    pub check: Scalar,
    pub left_commit: Scalar,
    pub m_list: Vec<Scalar>,
    pub n_list: Vec<Scalar>,
}

impl Serialize for RelationshipProof {
    fn serialize(&self) -> Vec<u8> {
        if self.m_list.len() != self.n_list.len() {
            return Vec::new();
        }
        let mut buf = Vec::with_capacity(
            SCALAR_SIZE_IN_BYTE
                + SCALAR_SIZE_IN_BYTE * self.m_list.len()
                + SCALAR_SIZE_IN_BYTE * self.n_list.len(),
        );
        buf.push(self.m_list.len() as u8);
        buf.extend(&(scalar_to_bytes(&self.check)));
        buf.extend(&(scalar_to_bytes(&self.left_commit)));
        for m in &self.m_list {
            buf.extend(&(scalar_to_bytes(m)));
        }
        for n in &self.n_list {
            buf.extend(&(scalar_to_bytes(n)));
        }

        buf
    }
}

impl Deserialize for RelationshipProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 3 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        let mut offset = 0;
        let m_list_len = bytes[offset];
        offset += 1;
        // decode check
        let check =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        offset += SCALAR_SIZE_IN_BYTE;
        // decode left_commit
        let left_commit =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        offset += SCALAR_SIZE_IN_BYTE;
        // decode m_list
        let mut m_list = Vec::new();
        for _ in 0..m_list_len {
            let m =
                bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
            m_list.push(m);
            offset += SCALAR_SIZE_IN_BYTE;
        }
        // decode n_list
        let mut n_list = Vec::new();
        for _ in 0..m_list_len {
            let n =
                bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
            n_list.push(n);
            offset += SCALAR_SIZE_IN_BYTE;
        }
        Ok(RelationshipProof {
            check: check,
            left_commit: left_commit,
            m_list: m_list,
            n_list: n_list,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ArithmeticProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub t3: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
    pub m3: Scalar,
    pub m4: Scalar,
    pub m5: Scalar,
}

impl Serialize for ArithmeticProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            5 * SCALAR_SIZE_IN_BYTE + 3 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf.extend(&(point_to_bytes(&self.t3)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf.extend(&(scalar_to_bytes(&self.m3)));
        buf.extend(&(scalar_to_bytes(&self.m4)));
        buf.extend(&(scalar_to_bytes(&self.m5)));
        buf
    }
}

impl Deserialize for ArithmeticProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len()
            < 5 * SCALAR_SIZE_IN_BYTE + 3 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t3
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t3 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m3
        offset += SCALAR_SIZE_IN_BYTE;
        let m3 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m4
        offset += SCALAR_SIZE_IN_BYTE;
        let m4 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m5
        offset += SCALAR_SIZE_IN_BYTE;
        let m5 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(ArithmeticProof {
            t1: t1,
            t2: t2,
            t3: t3,
            m1: m1,
            m2: m2,
            m3: m3,
            m4: m4,
            m5: m5,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct EqualityProof {
    pub m1: Scalar,
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
}

impl Serialize for EqualityProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf
    }
}

impl Deserialize for EqualityProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode m1
        let mut offset = 0;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode t1
        offset += SCALAR_SIZE_IN_BYTE;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        Ok(EqualityProof {
            m1: m1,
            t1: t1,
            t2: t2,
        })
    }
}

/// Gets a random Scalar.
pub fn get_random_scalar() -> Scalar {
    Scalar::random(&mut rand::thread_rng())
}

/// Converts an arbitrary string to Scalar.
/// It will hash it first, and transform the numeric value of hash output to
/// Scalar.
pub fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Scalar {
    let mut array = [0; 32];
    array.clone_from_slice(&HASH.hash(input));
    Scalar::from_bytes_mod_order(array)
}

/// Converts Scalar to a vector.
pub fn scalar_to_bytes(input: &Scalar) -> Vec<u8> {
    input.as_bytes().to_vec()
}

/// Converts Scalar to a slice.
pub fn scalar_to_slice(input: &Scalar) -> [u8; 32] {
    input.as_bytes().clone()
}

/// Extracts a slice of &[u8; 32] from the given slice.
fn to_bytes32_slice(barry: &[u8]) -> Result<&[u8; 32], WedprError> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(pop_u8)
}

// Private utility functions.

/// Converts a vector to Scalar.
pub fn bytes_to_scalar(input: &[u8]) -> Result<Scalar, WedprError> {
    let get_num_u8 = to_bytes32_slice(&input)?;
    let scalar_num = Scalar::from_bytes_mod_order(*get_num_u8);
    Ok(scalar_num)
}

/// Converts RistrettoPoint to a bytes vector.
pub fn point_to_bytes(point: &RistrettoPoint) -> Vec<u8> {
    point.compress().to_bytes().to_vec()
}

/// Converts RistrettoPoint to a bytes slice.
pub fn point_to_slice(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

/// Converts a vector to RistrettoPoint.
pub fn bytes_to_point(point: &[u8]) -> Result<RistrettoPoint, WedprError> {
    if point.len() != RISTRETTO_POINT_SIZE_IN_BYTES {
        wedpr_println!("bytes_to_point decode failed");
        return Err(WedprError::FormatError);
    }
    let point_value_result = match CompressedRistretto::from_slice(&point) {
        Ok(v) => v,
        Err(_e) => {
            wedpr_println!(
                "bytes_to_point decompress CompressedRistretto failed"
            );
            return Err(WedprError::FormatError);
        },
    };
    let point_value = match point_value_result.decompress() {
        Some(v) => v,
        None => {
            wedpr_println!(
                "bytes_to_point decompress CompressedRistretto failed"
            );
            return Err(WedprError::FormatError);
        },
    };
    Ok(point_value)
}

/// Gets a random u32 integer.
pub fn get_random_u32() -> u32 {
    let mut rng = rand::thread_rng();
    let blinding: u32 = rng.gen();
    blinding
}
