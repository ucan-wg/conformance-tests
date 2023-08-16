use super::{make_proof, UcanOptions};
use crate::{
    capabilities::EmailSemantics,
    generators::assertions::{ucan_to_assertions, UcanAssertions},
    identities::Identities,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::{collections::HashMap, default::Default, rc::Rc};
use ucan::{
    builder::Signable,
    capability::{Capability, CapabilitySemantics},
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

const EMAIL_SEMANTICS: EmailSemantics = EmailSemantics {};

// GENERATE

pub async fn generate() -> Result<Vec<VerifyFixture>> {
    let identities = Rc::new(Identities::new().await);

    let fixtures: Vec<VerifyFixture> = vec![
        // Time bounds
        not_expired(identities.clone()).await,
        active(identities.clone()).await,
        same_time_bounds(identities.clone()).await,
        proof_expires_after(identities.clone()).await,
        proof_active_before(identities.clone()).await,
        // Capability
        well_formed_capability(identities.clone()).await,
        well_formed_capability_with_caveat(identities.clone()).await,
        multiple_well_formed_capabilities(identities.clone()).await,
        // Delegation
        issuer_matches_proof_audience(identities.clone()).await,
        has_delegated_capability(identities.clone()).await,
        merges_delegated_capabilities(identities.clone()).await,
        caveats_equal(identities.clone()).await,
        caveats_attenuate(identities.clone()).await,
        caveats_attenuate_from_no_caveats(identities.clone()).await,
        // Facts
        has_fact(identities.clone()).await,
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
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

async fn same_time_bounds(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            expiration: Some(9246211200),
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        "UCAN has same time bounds as proof".to_string(),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            not_before: Some(1),
            expiration: Some(9246211200),
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

async fn proof_expires_after(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(14069142000),
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        "UCAN expires before proof".to_string(),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

async fn proof_active_before(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        "UCAN active after proof".to_string(),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            not_before: Some(2),
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

// CAPABILITY

async fn well_formed_capability(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    make_fixture(
        "UCAN has a well-formed capability".to_string(),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

async fn well_formed_capability_with_caveat(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> VerifyFixture {
    let caveat = json!({"templates": ["marketing"]});
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    make_fixture(
        "UCAN has a well-formed capability with a caveat".to_string(),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

async fn multiple_well_formed_capabilities(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> VerifyFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let caveat = json!({"templates": ["marketing"]});
    let send_email_as_marketing: Capability = EMAIL_SEMANTICS
        .parse("mailto:marketing@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    make_fixture(
        "UCAN has multiple well-formed capabilities".to_string(),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice, send_email_as_marketing],
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}

// DELEGATION

async fn issuer_matches_proof_audience(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> VerifyFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN issuer matches proof audience"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

async fn has_delegated_capability(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
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
        String::from("UCAN has a delegated capability"),
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

async fn merges_delegated_capabilities(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> VerifyFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let (alice_proof_ucan_cid, alice_proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice.clone()],
            ..Default::default()
        },
    )
    .await;

    let send_email_as_marketing: Capability = EMAIL_SEMANTICS
        .parse("mailto:marketing@email.com", "email/send", None)
        .unwrap()
        .into();

    let (marketing_proof_ucan_cid, marketing_proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_marketing.clone()],
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN merges delegated capabilities"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice, send_email_as_marketing],
            proofs: vec![
                alice_proof_ucan_cid.clone(),
                marketing_proof_ucan_cid.clone(),
            ],
            ..Default::default()
        },
        HashMap::from([
            (alice_proof_ucan_cid, alice_proof_token),
            (marketing_proof_ucan_cid, marketing_proof_token),
        ]),
    )
    .await
}

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

async fn caveats_attenuate(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    let full_caveat = json!({"templates": ["newsletter", "marketing"]});
    let reduced_scope_caveat = json!({"templates": ["newsletter"]});

    let send_email_as_marketing: Capability = EMAIL_SEMANTICS
        .parse(
            "mailto:marketing@email.com",
            "email/send",
            Some(&full_caveat),
        )
        .unwrap()
        .into();
    let send_newsletter: Capability = EMAIL_SEMANTICS
        .parse(
            "mailto:marketing@email.com",
            "email/send",
            Some(&reduced_scope_caveat),
        )
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_marketing],
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN capability attenuates existing caveats"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_newsletter],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

async fn caveats_attenuate_from_no_caveats(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> VerifyFixture {
    let send_email_as_marketing: Capability = EMAIL_SEMANTICS
        .parse("mailto:marketing@email.com", "email/send", None)
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_marketing],
            ..Default::default()
        },
    )
    .await;

    let caveat = json!({"templates": ["newsletter"]});
    let send_newsletter: Capability = EMAIL_SEMANTICS
        .parse("mailto:marketing@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    make_fixture(
        String::from("UCAN capability attenuates from no caveats"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_newsletter],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
    )
    .await
}

// FACTS

async fn has_fact(identities: Rc<Identities<Ed25519KeyMaterial>>) -> VerifyFixture {
    make_fixture(
        String::from("UCAN has a fact"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            facts: BTreeMap::from([(String::from("challenge"), json!("abcdef"))]),
            ..Default::default()
        },
        HashMap::new(),
    )
    .await
}
