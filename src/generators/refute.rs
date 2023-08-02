use super::{ucan_to_assertions, UcanAssertions};
use crate::{capabilities::EmailSemantics, identities::Identities};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc};
use ucan::{builder::UcanBuilder, capability::CapabilitySemantics, Ucan};
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

    let fixture = expired(identities.clone()).await;
    fixtures.push(fixture);

    Ok(fixtures)
}

async fn expired(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let email_semantics = EmailSemantics {};
    let send_email_as_alice = email_semantics
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap();

    let ucan = UcanBuilder::default()
        .issued_by(&identities.alice_key)
        .for_audience(identities.bob_did.as_str())
        .with_expiration(1)
        .claiming_capability(&send_email_as_alice)
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap();

    let inputs = Inputs {
        token: Ucan::encode(&ucan).unwrap(),
        proofs: HashMap::new(),
    };
    let assertions = ucan_to_assertions(ucan);
    let errors = vec!["expired".into()];

    RefuteFixture::new("UCAN has expired".to_string(), inputs, assertions, errors)
}
