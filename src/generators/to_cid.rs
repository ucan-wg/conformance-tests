use super::UcanOptions;
use crate::identities::Identities;
use anyhow::Result;
use cid::multihash::Code;
use serde::{Deserialize, Serialize};
use std::{default::Default, rc::Rc};
use ucan::{builder::Signable, Ucan};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToCIDFixture {
    name: String,
    task: String,
    inputs: Inputs,
    outputs: Outputs,
}

impl ToCIDFixture {
    fn new(name: String, inputs: Inputs, outputs: Outputs) -> Self {
        ToCIDFixture {
            name,
            task: "toCID".to_string(),
            inputs,
            outputs,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Inputs {
    token: String,
    hasher: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Outputs {
    cid: String,
}

// GENERATE

pub async fn generate() -> Result<Vec<ToCIDFixture>> {
    let identities = Rc::new(Identities::new().await);

    let fixtures: Vec<ToCIDFixture> = vec![
        computes_cid_with_sha2_256_hasher(identities.clone()).await,
        computes_cid_with_blake3_256_hasher(identities.clone()).await,
    ];

    Ok(fixtures)
}

async fn make_fixture(
    name: String,
    issuer: &Ed25519KeyMaterial,
    audience: String,
    hasher: String,
    options: UcanOptions,
) -> ToCIDFixture {
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
    let token = Ucan::encode(&ucan).unwrap();

    let inputs = Inputs {
        token,
        hasher: hasher.clone(),
    };

    let hasher_code = match hasher.as_str() {
        "SHA2-256" => Code::Sha2_256,
        "BLAKE3-256" => Code::Blake3_256,
        _ => Code::Sha2_256,
    };
    let cid = ucan.to_cid(hasher_code).unwrap().to_string();
    let outputs = Outputs { cid };

    ToCIDFixture::new(name, inputs, outputs)
}

// TO CID

async fn computes_cid_with_sha2_256_hasher(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> ToCIDFixture {
    make_fixture(
        String::from("Compute CID for token using SHA2-256 hasher"),
        &identities.alice_key,
        identities.bob_did.clone(),
        String::from("SHA2-256"),
        UcanOptions {
            ..Default::default()
        },
    )
    .await
}

async fn computes_cid_with_blake3_256_hasher(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> ToCIDFixture {
    make_fixture(
        String::from("Compute CID for token using BLAKE3-256 hasher"),
        &identities.alice_key,
        identities.bob_did.clone(),
        String::from("BLAKE3-256"),
        UcanOptions {
            ..Default::default()
        },
    )
    .await
}
