use super::UcanOptions;
use crate::{
    capabilities::EmailSemantics,
    identities::{Identities, ALICE_BASE64_KEY},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::{default::Default, rc::Rc};
use ucan::{
    builder::Signable,
    capability::{Capabilities, Capability, CapabilitySemantics},
    ucan::FactsMap,
    Ucan,
};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildFixture {
    name: String,
    task: String,
    inputs: Inputs,
    outputs: Outputs,
}

impl BuildFixture {
    fn new(name: String, inputs: Inputs, outputs: Outputs) -> Self {
        BuildFixture {
            name,
            task: "build".to_string(),
            inputs,
            outputs,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Inputs {
    version: String,
    issuer_base64_key: String,
    signature_scheme: String,
    audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<u64>,
    expiration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts: Option<FactsMap>,
    capabilities: Capabilities,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Outputs {
    token: String,
}

const EMAIL_SEMANTICS: EmailSemantics = EmailSemantics {};

// GENERATE

pub async fn generate() -> Result<Vec<BuildFixture>> {
    let identities = Rc::new(Identities::new().await);

    let fixtures: Vec<BuildFixture> = vec![
        // Time bounds
        has_expiration(identities.clone()).await,
        has_not_before(identities.clone()).await,
        // Capability
        send_email_as_alice(identities.clone()).await,
        send_newsletter_as_alice(identities.clone()).await,
        // Facts
        has_fact(identities.clone()).await,
    ];

    Ok(fixtures)
}

async fn make_fixture(
    name: String,
    issuer: &Ed25519KeyMaterial,
    issuer_base64_key: String,
    signature_scheme: String,
    audience: String,
    options: UcanOptions,
) -> BuildFixture {
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
        version: ucan.version().into(),
        issuer_base64_key,
        signature_scheme,
        audience,
        not_before: *ucan.not_before(),
        expiration: *ucan.expires_at(),
        facts: ucan.facts().clone(),
        capabilities: ucan.capabilities().clone(),
    };

    let token = Ucan::encode(&ucan).unwrap();
    let outputs = Outputs { token };

    BuildFixture::new(name, inputs, outputs)
}

// TIME BOUNDS

async fn has_expiration(identities: Rc<Identities<Ed25519KeyMaterial>>) -> BuildFixture {
    make_fixture(
        String::from("UCAN has an expiration"),
        &identities.alice_key,
        String::from(ALICE_BASE64_KEY),
        String::from("Ed25519"),
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            ..Default::default()
        },
    )
    .await
}

async fn has_not_before(identities: Rc<Identities<Ed25519KeyMaterial>>) -> BuildFixture {
    make_fixture(
        String::from("UCAN has a not before"),
        &identities.alice_key,
        String::from(ALICE_BASE64_KEY),
        String::from("Ed25519"),
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            ..Default::default()
        },
    )
    .await
}

// CAPABILITY

async fn send_email_as_alice(identities: Rc<Identities<Ed25519KeyMaterial>>) -> BuildFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    make_fixture(
        String::from("UCAN delegates send email capability"),
        &identities.alice_key,
        String::from(ALICE_BASE64_KEY),
        String::from("Ed25519"),
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
    )
    .await
}

async fn send_newsletter_as_alice(identities: Rc<Identities<Ed25519KeyMaterial>>) -> BuildFixture {
    let caveat = json!({"templates": ["newsletter"]});
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    make_fixture(
        String::from("UCAN delegates send email capability with newsletter template caveat"),
        &identities.alice_key,
        String::from(ALICE_BASE64_KEY),
        String::from("Ed25519"),
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
    )
    .await
}

// FACTS

async fn has_fact(identities: Rc<Identities<Ed25519KeyMaterial>>) -> BuildFixture {
    make_fixture(
        String::from("UCAN has a fact with a challenge"),
        &identities.alice_key,
        String::from(ALICE_BASE64_KEY),
        String::from("Ed25519"),
        identities.bob_did.clone(),
        UcanOptions {
            facts: BTreeMap::from([(String::from("challenge"), json!("abcdef"))]),
            ..Default::default()
        },
    )
    .await
}
