use crate::crypto::ed25519_key_from_base64;
use ucan::crypto::KeyMaterial;
use ucan_key_support::ed25519::Ed25519KeyMaterial;

#[derive(Clone, Debug)]
pub struct Identities<K>
where
    K: KeyMaterial + Clone + 'static,
{
    pub alice_key: K,
    pub bob_key: K,
    pub mallory_key: K,

    pub alice_did: String,
    pub bob_did: String,
    pub mallory_did: String,
}

pub const ALICE_BASE64_KEY: &str =
    "U+bzp2GaFQHso587iSFWPSeCzbSfn/CbNHEz7ilKRZ1UQMmMS7qq4UhTzKn3X9Nj/4xgrwa+UqhMOeo4Ki8JUw==";

impl Identities<Ed25519KeyMaterial> {
    pub async fn new() -> Self {
        let alice_key = ed25519_key_from_base64(ALICE_BASE64_KEY).unwrap();
        let bob_key  = ed25519_key_from_base64("G4+QCX1b3a45IzQsQd4gFMMe0UB1UOx9bCsh8uOiKLER69eAvVXvc8P2yc4Iig42Bv7JD2zJxhyFALyTKBHipg==").unwrap();
        let mallory_key  = ed25519_key_from_base64("LR9AL2MYkMARuvmV3MJV8sKvbSOdBtpggFCW8K62oZDR6UViSXdSV/dDcD8S9xVjS61vh62JITx7qmLgfQUSZQ==").unwrap();

        Identities {
            alice_did: alice_key.get_did().await.unwrap(),
            bob_did: bob_key.get_did().await.unwrap(),
            mallory_did: mallory_key.get_did().await.unwrap(),

            alice_key,
            bob_key,
            mallory_key,
        }
    }

    #[allow(dead_code)]
    pub fn name_for(&self, did: String) -> String {
        match did {
            _ if did == self.alice_did => "alice".into(),
            _ if did == self.bob_did => "bob".into(),
            _ if did == self.mallory_did => "mallory".into(),
            _ => did,
        }
    }
}
