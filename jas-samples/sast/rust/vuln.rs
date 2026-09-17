// JAS SAST demo fixture (Rust). Not part of any crate/build in this repo.
//
// Findings demonstrated:
//  - CWE-502 Deserialization of untrusted data: deserializing an
//    attacker-controlled byte stream with no type/size validation (Medium).
//  - CWE-798 Use of hard-coded credentials (Low/Medium).

use serde::Deserialize;

const API_TOKEN: &str = "rust-demo-hardcoded-token-not-real"; // Vulnerable: hardcoded credential

#[derive(Deserialize)]
struct SessionPayload {
    user_id: String,
    is_admin: bool,
}

// Vulnerable: deserializes attacker-supplied bytes straight into a struct
// that includes a privilege field (`is_admin`), with no source
// authentication or schema/allowlist validation upstream.
fn load_session(untrusted_bytes: &[u8]) -> Result<SessionPayload, serde_json::Error> {
    serde_json::from_slice(untrusted_bytes)
}

fn authenticate(token: &str) -> bool {
    token == API_TOKEN
}
