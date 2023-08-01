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
    assertions: Assertions,
}

impl VerifyFixture {
    fn new(name: String, inputs: Inputs, assertions: Assertions) -> Self {
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
struct Assertions {
    header: UcanHeader,
    payload: UcanPayload,
    #[serde_as(as = "Base64")]
    signature: Vec<u8>,
}

pub async fn generate() -> Result<Vec<VerifyFixture>> {
    let identities = Rc::new(Identities::new().await);
    let mut fixtures: Vec<VerifyFixture> = vec![];

    let fixture = not_expired(identities.clone()).await;
    fixtures.push(fixture);

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

// Helpers

fn ucan_to_assertions(ucan: Ucan) -> Assertions {
    Assertions {
        header: UcanHeader {
            alg: ucan.algorithm().into(),
            typ: "JWT".into(),
        },
        payload: UcanPayload {
            ucv: ucan.version().into(),
            iss: ucan.issuer().into(),
            aud: ucan.audience().into(),
            exp: *ucan.expires_at(),
            nbf: *ucan.not_before(),
            nnc: ucan.nonce().clone(),
            cap: ucan.capabilities().clone(),
            fct: ucan.facts().clone(),
            prf: ucan.proofs().clone(),
        },
        signature: ucan.signature().into(),
    }
}
