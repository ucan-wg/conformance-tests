use super::{make_proof, UcanOptions};
use crate::{
    capabilities::EmailSemantics,
    generators::assertions::{ucan_to_assertions, UcanAssertions},
    identities::Identities,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{base64::Base64, serde_as};
use std::{collections::HashMap, default::Default, rc::Rc};
use ucan::{
    builder::Signable,
    capability::{Capability, CapabilitySemantics},
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

const EMAIL_SEMANTICS: EmailSemantics = EmailSemantics {};

// GENERATE

pub async fn generate() -> Result<Vec<VerifyFixture>> {
    let identities = Rc::new(Identities::new().await);

    let fixtures: Vec<VerifyFixture> = vec![
        not_expired(identities.clone()).await,
        active(identities.clone()).await,
        has_proof(identities.clone()).await,
        caveats_equal(identities.clone()).await,
    ];

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

// TIME BOUNDS

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

// DELEGATION

async fn has_proof(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice.clone()],
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN has proof of capability"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

// CAVEATS

async fn caveats_equal(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let caveat = json!({"templates": ["newsletter"]});
    let send_newsletter_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_newsletter_as_alice.clone()],
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN capability caveats equal to proof caveats"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_newsletter_as_alice],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}
