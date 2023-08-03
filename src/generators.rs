use cid::multihash::Code;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use std::{collections::BTreeMap, default::Default};
use ucan::{
    builder::Signable,
    capability::Capability,
    ucan::{UcanHeader, UcanPayload},
    Ucan,
};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

pub mod refute;
pub mod verify;

#[derive(Debug)]
pub struct UcanOptions {
    capabilities: Vec<Capability>,
    expiration: Option<u64>,
    not_before: Option<u64>,
    facts: BTreeMap<String, Value>,
    proofs: Vec<String>,
    add_nonce: bool,
}

impl Default for UcanOptions {
    fn default() -> Self {
        UcanOptions {
            capabilities: vec![],
            expiration: None,
            not_before: None,
            facts: BTreeMap::new(),
            proofs: vec![],
            add_nonce: false,
        }
    }
}

pub async fn make_proof(
    issuer: &Ed25519KeyMaterial,
    audience: String,
    options: UcanOptions,
) -> (String, String) {
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

    let cid = ucan.to_cid(Code::Sha2_256).unwrap().to_string();
    let token = Ucan::encode(&ucan).unwrap();

    (cid, token)
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct UcanAssertions {
    header: UcanHeader,
    payload: UcanPayload,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    signature: Vec<u8>,
}

fn ucan_to_assertions(ucan: Ucan) -> UcanAssertions {
    UcanAssertions {
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
        signature: ucan.signature().to_vec(),
    }
}
