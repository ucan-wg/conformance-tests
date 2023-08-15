use super::{
    assertions::{ucan_to_assertions, UcanAssertions},
    make_proof,
    mutate::{mutate_field, remove_field},
    UcanOptions,
};
use crate::{capabilities::EmailSemantics, identities::Identities};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::{collections::HashMap, rc::Rc};
use ucan::{
    builder::Signable,
    capability::{Capability, CapabilitySemantics},
    Ucan,
};
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

impl Inputs {
    fn token_mut(&mut self) -> &mut String {
        &mut self.token
    }
}

const EMAIL_SEMANTICS: EmailSemantics = EmailSemantics {};

// GENERATE

pub async fn generate() -> Result<Vec<RefuteFixture>> {
    let identities = Rc::new(Identities::new().await);

    let fixtures: Vec<RefuteFixture> = vec![
        // Time bounds
        expired(identities.clone()).await,
        not_ready(identities.clone()).await,
        expires_after_proofs(identities.clone()).await,
        ready_before_proofs(identities.clone()).await,
        // Encoding

        // Missing fields
        missing_type(identities.clone()).await,
        missing_algorithm(identities.clone()).await,
        missing_version(identities.clone()).await,
        missing_issuer(identities.clone()).await,
        missing_audience(identities.clone()).await,
        missing_expiration(identities.clone()).await,
        missing_capabilities(identities.clone()).await,
        // Invalid fields
        invalid_algorithm(identities.clone()).await,
        invalid_type(identities.clone()).await,
        invalid_type_not_jwt(identities.clone()).await,
        invalid_version(identities.clone()).await,
        invalid_version_not_semantic(identities.clone()).await,
        invalid_issuer(identities.clone()).await,
        invalid_audience(identities.clone()).await,
        invalid_not_before(identities.clone()).await,
        invalid_expiration(identities.clone()).await,
        invalid_nonce(identities.clone()).await,
        invalid_facts(identities.clone()).await,
        invalid_capabilities(identities.clone()).await,
        invalid_capabilities_ability(identities.clone()).await,
        invalid_capabilities_caveats(identities.clone()).await,
        invalid_capabilities_caveats_empty(identities.clone()).await,
        invalid_proofs(identities.clone()).await,
        invalid_proof_cids(identities.clone()).await,
        // Delegation
        issuer_does_not_match_proof_audience(identities.clone()).await,
        claimed_capability_not_delegated(identities.clone()).await,
        caveats_escalate_with_new_caveat(identities.clone()).await,
        caveats_escalate_to_no_caveats(identities.clone()).await,
        caveats_escalate_with_different_caveat(identities.clone()).await,
    ];

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

// TIME BOUNDS

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

async fn not_ready(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    make_fixture(
        String::from("UCAN is not ready to be used"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(9246211200),
            ..Default::default()
        },
        HashMap::new(),
        vec!["notReady".into()],
    )
    .await
}

async fn expires_after_proofs(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN expires after proofs"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(14069142000),
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["timeBoundsViolation".into()],
    )
    .await
}

async fn ready_before_proofs(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(2),
            ..Default::default()
        },
    )
    .await;

    make_fixture(
        String::from("UCAN ready before proofs"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["timeBoundsViolation".into()],
    )
    .await
}

// ENCODING

// MISSING FIELDS

async fn missing_algorithm(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN header is missing alg field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    // *fixture.assertions.header.alg_mut() = None;
    *fixture.assertions.header.alg_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "header",
        "alg",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_type(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN header is missing typ field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.header.typ_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "header",
        "typ",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_version(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload is missing ucv field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.payload.ucv_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "payload",
        "ucv",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_issuer(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload is missing iss field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.payload.iss_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "payload",
        "iss",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_audience(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload is missing aud field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.payload.aud_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "payload",
        "aud",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_expiration(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload is missing exp field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    // Some(86) is a special marker value to remove exp from the assertions
    *fixture.assertions.payload.exp_mut() = Some(86);
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "payload",
        "exp",
        identities.alice_key.clone(),
    );

    fixture
}

async fn missing_capabilities(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload is missing cap field"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["missingField".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;
    *fixture.inputs.token_mut() = remove_field(
        fixture.inputs.token.as_str(),
        "payload",
        "cap",
        identities.alice_key.clone(),
    );

    fixture
}

// INVALID FIELDS

async fn invalid_algorithm(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN header alg field is not a string"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.header.alg_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "header",
        "alg",
        json!(1),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_type(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN header typ field is not a string"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.header.typ_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "header",
        "typ",
        json!(1),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_type_not_jwt(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN type is not JWT"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.header.typ_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "header",
        "typ",
        json!("NOT_JWT"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_version(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload ucv field is not a string"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.ucv_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "ucv",
        json!(1),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_version_not_semantic(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload ucv field is not semantically versioned"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.ucv_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "ucv",
        json!("0.10"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_issuer(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload iss field is not a DID"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.iss_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "iss",
        json!("z6Mkk89bC3JrVqKie71YEcc5M1SMVxuCgNx6zLZ8SYJsxALi"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_audience(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload aud field is not a DID"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.aud_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "aud",
        json!("z6MkffDZCkCTWreg8868fG1FGFogcJj5X6PY93pPcWDn9bob"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_not_before(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload nbf field is not a number"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            not_before: Some(1),
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.nbf_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "nbf",
        json!("1"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_expiration(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload exp field is not a number"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            expiration: Some(9246211200),
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    // Some(86) is a special marker value to remove exp from the assertions
    *fixture.assertions.payload.exp_mut() = Some(86);
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "exp",
        json!("9246211200"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_nonce(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload nnc field is not a string"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            add_nonce: true,
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.nnc_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "nnc",
        json!(1),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_facts(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload fct field is not a JSON object"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            facts: BTreeMap::from([(String::from("challenge"), json!("abcdef"))]),
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.fct_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "fct",
        json!(null),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_capabilities(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN payload cap field is not a JSON object"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "cap",
        json!(null),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_capabilities_ability(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN payload cap field ability for resource is not a JSON object"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "cap",
        json!({ "mailto:alice@email.com": null }),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_capabilities_caveats(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN payload cap field caveat is not an array"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "cap",
        json!( { "mailto:alice@email.com": { "email/send": null }}),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_capabilities_caveats_empty(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN payload cap field caveat is an empty array"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "cap",
        json!( { "mailto:alice@email.com": { "email/send": []}}),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_proofs(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload prf field is not an array"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            proofs: vec![String::from("placeholder")],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectType".into()],
    )
    .await;

    *fixture.assertions.payload.prf_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "prf",
        json!({}),
        identities.alice_key.clone(),
    );

    fixture
}

async fn invalid_proof_cids(identities: Rc<Identities<Ed25519KeyMaterial>>) -> RefuteFixture {
    let mut fixture = make_fixture(
        String::from("UCAN payload prf field is not an array of CIDs"),
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            proofs: vec![String::from("placeholder")],
            ..Default::default()
        },
        HashMap::new(),
        vec!["incorrectProofs".into()],
    )
    .await;

    *fixture.assertions.payload.prf_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "prf",
        json!(["we", "prove", "nothing"]),
        identities.alice_key.clone(),
    );

    fixture
}

// DELEGATION

async fn issuer_does_not_match_proof_audience(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
    )
    .await;

    let mut fixture = make_fixture(
        String::from("UCAN issuer does not match proof audience"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["invalidDelegation".into()],
    )
    .await;

    *fixture.assertions.payload.iss_mut() = None;
    *fixture.inputs.token_mut() = mutate_field(
        fixture.inputs.token.as_str(),
        "payload",
        "iss",
        json!("did:key:z6MktafZTREjJkvV5mfJxcLpNBoVPwDLhTuMg9ng7dY4zMAL"),
        identities.alice_key.clone(),
    );

    fixture
}

async fn claimed_capability_not_delegated(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            ..Default::default()
        },
    )
    .await;

    let mut fixture = make_fixture(
        String::from("UCAN claims a capability that has not been delegated"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["invalidDelegation".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;

    fixture
}

async fn caveats_escalate_with_new_caveat(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let caveat = json!({"templates": ["newsletter"]});
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
    )
    .await;

    let escalated_caveat = json!({"templates": ["newsletter", "marketing"]});
    let send_email_as_alice_escalated: Capability = EMAIL_SEMANTICS
        .parse(
            "mailto:alice@email.com",
            "email/send",
            Some(&escalated_caveat),
        )
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN escalates by adding a new caveat"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice_escalated],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["invalidDelegation".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;

    fixture
}

async fn caveats_escalate_to_no_caveats(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let caveat = json!({"templates": ["newsletter"]});
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
    )
    .await;

    let send_email_as_alice_escalated: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", None)
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN escalates to no caveats"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice_escalated],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["invalidDelegation".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;

    fixture
}

async fn caveats_escalate_with_different_caveat(
    identities: Rc<Identities<Ed25519KeyMaterial>>,
) -> RefuteFixture {
    let caveat = json!({"templates": ["newsletter"]});
    let send_email_as_alice: Capability = EMAIL_SEMANTICS
        .parse("mailto:alice@email.com", "email/send", Some(&caveat))
        .unwrap()
        .into();

    let (proof_ucan_cid, proof_token) = make_proof(
        &identities.alice_key,
        identities.bob_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice],
            ..Default::default()
        },
    )
    .await;

    let escalated_caveat = json!({"templates": ["marketing"]});
    let send_email_as_alice_escalated: Capability = EMAIL_SEMANTICS
        .parse(
            "mailto:alice@email.com",
            "email/send",
            Some(&escalated_caveat),
        )
        .unwrap()
        .into();

    let mut fixture = make_fixture(
        String::from("UCAN escalates by adding a different caveat"),
        &identities.bob_key,
        identities.mallory_did.clone(),
        UcanOptions {
            capabilities: vec![send_email_as_alice_escalated],
            proofs: vec![proof_ucan_cid.clone()],
            ..Default::default()
        },
        HashMap::from([(proof_ucan_cid, proof_token)]),
        vec!["invalidDelegation".into()],
    )
    .await;

    *fixture.assertions.payload.cap_mut() = None;

    fixture
}
