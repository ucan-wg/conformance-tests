use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use ucan::{capability::Capabilities, ucan::FactsMap, Ucan};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct UcanAssertions {
    pub header: UcanHeaderAssertions,
    pub payload: UcanPayloadAssertions,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UcanHeaderAssertions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
}

impl UcanHeaderAssertions {
    pub fn alg_mut(&mut self) -> &mut Option<String> {
        &mut self.alg
    }

    pub fn typ_mut(&mut self) -> &mut Option<String> {
        &mut self.typ
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UcanPayloadAssertions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ucv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "is_skip_expiration_marker")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nnc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<Capabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fct: Option<FactsMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Vec<String>>,
}

impl UcanPayloadAssertions {
    pub fn ucv_mut(&mut self) -> &mut Option<String> {
        &mut self.ucv
    }

    pub fn iss_mut(&mut self) -> &mut Option<String> {
        &mut self.iss
    }

    pub fn aud_mut(&mut self) -> &mut Option<String> {
        &mut self.aud
    }

    pub fn nbf_mut(&mut self) -> &mut Option<u64> {
        &mut self.nbf
    }

    pub fn exp_mut(&mut self) -> &mut Option<u64> {
        &mut self.exp
    }

    pub fn nnc_mut(&mut self) -> &mut Option<String> {
        &mut self.nnc
    }

    pub fn fct_mut(&mut self) -> &mut Option<FactsMap> {
        &mut self.fct
    }

    pub fn cap_mut(&mut self) -> &mut Option<Capabilities> {
        &mut self.cap
    }

    pub fn prf_mut(&mut self) -> &mut Option<Vec<String>> {
        &mut self.prf
    }
}

// Hack to mark when we should skip serializing the exp
// field in the UCAN assertions. Note that this is a valid
// exp value, but we can't use None to skip exp because we want
// to serialize it as null. So we eighty-six it instead.
fn is_skip_expiration_marker(val: &Option<u64>) -> bool {
    *val == Some(86)
}

pub fn ucan_to_assertions(ucan: Ucan) -> UcanAssertions {
    UcanAssertions {
        header: UcanHeaderAssertions {
            alg: Some(ucan.algorithm().into()),
            typ: Some("JWT".into()),
        },
        payload: UcanPayloadAssertions {
            ucv: Some(ucan.version().into()),
            iss: Some(ucan.issuer().into()),
            aud: Some(ucan.audience().into()),
            exp: *ucan.expires_at(),
            nbf: *ucan.not_before(),
            nnc: ucan.nonce().clone(),
            cap: Some(ucan.capabilities().clone()),
            fct: ucan.facts().clone(),
            prf: ucan.proofs().clone(),
        },
        signature: ucan.signature().to_vec(),
    }
}
