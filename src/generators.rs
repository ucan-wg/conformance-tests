use cid::multihash::Code;
use serde_json::Value;
use std::{collections::BTreeMap, default::Default};
use ucan::{builder::Signable, capability::Capability, Ucan};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

pub mod assertions;
pub mod mutate;
pub mod refute;
pub mod verify;

#[derive(Debug)]
pub struct UcanOptions {
    capabilities: Vec<Capability>,
    expiration: Option<u64>,
    not_before: Option<u64>,
    facts: BTreeMap<String, Value>,
    proofs: Vec<String>,
    add_nonce: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for UcanOptions {
    fn default() -> Self {
        UcanOptions {
            capabilities: vec![],
            expiration: None,
            not_before: None,
            facts: BTreeMap::new(),
            proofs: vec![],
            add_nonce: false,
        }
    }
}

pub async fn make_proof(
    issuer: &Ed25519KeyMaterial,
    audience: String,
    options: UcanOptions,
) -> (String, String) {
    let signable = Signable {
        issuer: &issuer.clone(),
        audience: audience.clone(),
        capabilities: options.capabilities,
        expiration: options.expiration,
        not_before: options.not_before,
        facts: options.facts,
        proofs: options.proofs,
        add_nonce: options.add_nonce,
    };
    let ucan = signable.sign().await.unwrap();

    let cid = ucan.to_cid(Code::Sha2_256).unwrap().to_string();
    let token = Ucan::encode(&ucan).unwrap();

    (cid, token)
}
