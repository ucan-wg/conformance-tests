use super::UcanOptions;
use crate::{
    generators::assertions::{ucan_to_assertions, UcanAssertions},
    identities::Identities,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc};
use ucan::{builder::Signable, Ucan};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

#[derive(Debug, Serialize, Deserialize)]
pub struct RefuteFixture {
    name: String,
    task: String,
    inputs: Inputs,
    assertions: UcanAssertions,
    errors: Vec<String>,
}

impl RefuteFixture {
    fn new(name: String, inputs: Inputs, assertions: UcanAssertions, errors: Vec<String>) -> Self {
        RefuteFixture {
            name,
            task: "refute".to_string(),
            inputs,
            assertions,
            errors,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Inputs {
    token: String,
    proofs: HashMap<String, String>,
}

pub async fn generate() -> Result<Vec<RefuteFixture>> {
    let identities = Rc::new(Identities::new().await);
    let mut fixtures: Vec<RefuteFixture> = vec![];

    let expired_fixture = expired(identities.clone()).await;
    let missing_algorithm_fixture = missing_algorithm(identities.clone()).await;
    fixtures.push(expired_fixture);
    fixtures.push(missing_algorithm_fixture);

    Ok(fixtures)
}

async fn make_fixture(
    name: String,
    issuer: &Ed25519KeyMaterial,
    audience: String,
    options: UcanOptions,
    proofs: HashMap<String, String>,
    errors: Vec<String>,
) -> RefuteFixture {
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

    RefuteFixture::new(name, inputs, assertions, errors)
}

async fn expired(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    make_fixture(
        String::from("UCAN has expired"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(1),
            ..Default::default()
        },
        HashMap::new(),
        vec!["expired".into()],
    )
    .await
}

async fn missing_algorithm(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN is missing header algorithm field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.header.alg_mut() = None;

    fixture
}
