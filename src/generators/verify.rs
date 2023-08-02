use super::{ucan_to_assertions, UcanAssertions};
use crate::{capabilities::EmailSemantics, identities::Identities};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::{collections::HashMap, rc::Rc};
use ucan::{
    builder::UcanBuilder,
    capability::CapabilitySemantics,
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
    fixtures.push(not_expired_fixture);

    Ok(fixtures)
}

async fn not_expired(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let email_semantics = EmailSemantics {};
    let send_email_as_alice = email_semantics
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap();

    let ucan = UcanBuilder::default()
        .issued_by(&identities.alice_key)
        .for_audience(identities.bob_did.as_str())
        .with_expiration(9246211200)
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

    VerifyFixture::new("UCAN has not expired".to_string(), inputs, assertions)
}
