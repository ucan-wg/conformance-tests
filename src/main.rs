//! ucan-fixture-generator

use serde_json::Value;
use std::fs;
use ucan_fixture_generator::generators::{refute, verify};

/// Main entry point
#[tokio::main]
async fn main() {
    const UCV: &str = "0.10.0";

    fs::create_dir_all(format!("fixtures/{}", UCV)).expect("Could not create fixtures directory");

    // Fixtures by task
    let verify_fixtures = verify::generate().await.unwrap();
    let refute_fixtures = refute::generate().await.unwrap();

    fs::write(
        format!("fixtures/{}/verify.json", UCV),
        serde_json::to_string(&verify_fixtures).unwrap(),
    )
    .unwrap_or_else(|err| println!("{:?}", err));

    fs::write(
        format!("fixtures/{}/refute.json", UCV),
        serde_json::to_string(&refute_fixtures).unwrap(),
    )
    .unwrap_or_else(|err| println!("{:?}", err));

    // All fixtures
    let mut all_fixtures: Vec<Value> = vec![];

    for fixture in verify_fixtures {
        let value = serde_json::to_value(&fixture).unwrap();
        all_fixtures.push(value);
    }

    for fixture in refute_fixtures {
        let value = serde_json::to_value(&fixture).unwrap();
        all_fixtures.push(value);
    }

    fs::write(
        format!("fixtures/{}/all.json", UCV),
        serde_json::to_string(&all_fixtures).unwrap(),
    )
    .unwrap_or_else(|err| println!("{:?}", err))
}
