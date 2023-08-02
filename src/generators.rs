use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use ucan::{
    ucan::{UcanHeader, UcanPayload},
    Ucan,
};

pub mod refute;
pub mod verify;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct UcanAssertions {
    header: UcanHeader,
    payload: UcanPayload,
    #[serde_as(as = "Base64")]
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
        signature: ucan.signature().into(),
    }
}
