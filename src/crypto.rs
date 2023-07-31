use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use ed25519_zebra::{SigningKey as Ed25519PrivateKey, VerificationKey as Ed25519PublicKey};
use ucan::crypto::did::KeyConstructorSlice;
use ucan_key_support::{
    ed25519::{bytes_to_ed25519_key, Ed25519KeyMaterial, ED25519_MAGIC_BYTES},
    rsa::{bytes_to_rsa_key, RSA_MAGIC_BYTES},
};

pub const SUPPORTED_KEYS: &KeyConstructorSlice = &[
    (ED25519_MAGIC_BYTES, bytes_to_ed25519_key),
    (RSA_MAGIC_BYTES, bytes_to_rsa_key),
];

pub fn generate_ed25519_key() -> Ed25519KeyMaterial {
    let private_key = Ed25519PrivateKey::new(rand::thread_rng());
    let public_key = Ed25519PublicKey::from(&private_key);
    Ed25519KeyMaterial(public_key, Some(private_key))
}

pub fn ed25519_key_from_base64(encoded_key: &str) -> Result<Ed25519KeyMaterial> {
    let bytes = general_purpose::STANDARD.decode(encoded_key).unwrap();
    let private_key_bytes: &[u8; 32] = bytes.as_slice()[0..32]
        .try_into()
        .expect("Could not extract private key");
    let private_key = Ed25519PrivateKey::from(private_key_bytes.to_owned());
    let public_key = Ed25519PublicKey::from(&private_key);

    Ok(Ed25519KeyMaterial(public_key, Some(private_key)))
}
