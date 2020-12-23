// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use crate::error::WedprError;

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    /// Generates a fixed length hash bytes vector from a bytes array of any
    /// length.
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8>;
}

/// Trait of a replaceable coder algorithm.
pub trait Coder {
    /// Converts bytes to an encoded string.
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String;
    /// Decodes an encoded string to a bytes vector.
    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError>;
}

/// Trait of a replaceable ECIES algorithm.
pub trait Ecies {
    /// Encrypts a message by ECIES with a public key.
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Decrypts a ciphertext by ECIES with a private key.
    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
    ) -> Result<Vec<u8>, WedprError>;
}

/// Trait of a replaceable signature algorithm.
pub trait Signature {
    /// Signs a message hash with the private key.
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Verifies a message hash with the public key.
    fn verify<T: ?Sized + AsRef<[u8]>>(&self, public_key: &T, msg_hash: &T, signature: &T) -> bool;

    /// Generates a new key pair for signature algorithm.
    // TODO: Replace output list with a struct or protobuf.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
}
