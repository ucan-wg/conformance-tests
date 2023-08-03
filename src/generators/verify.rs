use super::{make_proof, ucan_to_assertions, UcanAssertions, UcanOptions};
use crate::identities::Identities;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{base64::Base64, serde_as};
use std::{collections::HashMap, default::Default, rc::Rc};
use ucan::{
    builder::Signable,
    capability::Capability,
    ucan::{UcanHeader, UcanPayload},
    Ucan,
};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyFixture {
    name: String,
    task: String,
    inputs: Inputs,
    assertions: UcanAssertions,
}

impl VerifyFixture {
    fn new(name: String, inputs: Inputs, assertions: UcanAssertions) -> Self {
        VerifyFixture {
            name,
            task: "verify".to_string(),
            inputs,
            assertions,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Inputs {
    token: String,
    proofs: HashMap<String, String>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Assertions {
    header: UcanHeader,
    payload: UcanPayload,
    #[serde_as(as = "Base64")]
    signature: Vec<u8>,
}

pub async fn generate() -> Result<Vec<VerifyFixture>> {
    let identities = Rc::new(Identities::new().await);
    let mut fixtures: Vec<VerifyFixture> = vec![];

    let not_expired_fixture = not_expired(identities.clone()).await;
    let active_fixture = active(identities.clone()).await;
    let has_proof_fixture = has_proof(identities.clone()).await;
    fixtures.push(not_expired_fixture);
    fixtures.push(active_fixture);
    fixtures.push(has_proof_fixture);

    Ok(fixtures)
}

async fn make_fixture(
    name: String,
    issuer: &Ed25519KeyMaterial,
    audience: String,
    options: UcanOptions,
    proofs: HashMap<String, String>,
) -> VerifyFixture {
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

    let inputs = Inputs {
        token: Ucan::encode(&ucan).unwrap(),
        proofs,
    };
    let assertions = ucan_to_assertions(ucan);

    VerifyFixture::new(name, inputs, assertions)
}

async fn not_expired(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    make_fixture(
        String::from("UCAN has not expired"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

async fn active(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    make_fixture(
        "UCAN is ready to be used".to_string(),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            expiration: Some(9246211200),
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

async fn has_proof(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let email_capability: Capability = Capability {
        resource: String::from("mailto:alice@email.com"),
        ability: String::from("email/send"),
        caveat: json!({}),
    };

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![email_capability.clone()],
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN has proof of capability"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![email_capability],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}
