use base64::{engine::general_purpose, Engine as _};
use serde_json::{Map, Value};
use ucan_key_support::ed25519::Ed25519KeyMaterial;

pub fn remove_field(token: &str, part: &str, field: &str, signer: Ed25519KeyMaterial) -> String {
    let parts: Vec<&str> = token.split('.').collect();

    match part {
        "header" => {
            let mut header_map = part_to_map(parts[0]);
            header_map.remove(field);

            sign(map_to_part(header_map), String::from(parts[1]), signer)
        }

        "payload" => {
            let mut payload_map = part_to_map(parts[1]);
            payload_map.remove(field);

            sign(String::from(parts[0]), map_to_part(payload_map), signer)
        }

        _ => {
            panic!()
        }
    }
}

pub fn mutate_field(
    token: &str,
    part: &str,
    field: &str,
    value: Value,
    signer: Ed25519KeyMaterial,
) -> String {
    let parts: Vec<&str> = token.split('.').collect();

    match part {
        "header" => {
            let mut header_map = part_to_map(parts[0]);
            *header_map.get_mut(field).unwrap() = value;

            sign(map_to_part(header_map), String::from(parts[1]), signer)
        }

        "payload" => {
            let mut payload_map = part_to_map(parts[1]);
            *payload_map.get_mut(field).unwrap() = value;

            sign(String::from(parts[0]), map_to_part(payload_map), signer)
        }

        _ => {
            panic!()
        }
    }
}

fn part_to_map(part: &str) -> Map<String, Value> {
    let part_vec = general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap();
    let part_json_string = String::from_utf8(part_vec).unwrap();
    serde_json::from_str(&part_json_string[..]).unwrap()
}

fn map_to_part(map: Map<String, Value>) -> String {
    let json_string = Value::Object(map).to_string();
    general_purpose::URL_SAFE_NO_PAD.encode(json_string)
}

fn sign(header: String, payload: String, signer: Ed25519KeyMaterial) -> String {
    let private_key = signer.1.unwrap();
    let data_to_sign = format!("{header}.{payload}").as_bytes().to_vec();
    let raw_signature: [u8; 64] = private_key.sign(data_to_sign.as_slice()).into();
    let signature: String = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_signature);

    format!("{header}.{payload}.{signature}")
}
