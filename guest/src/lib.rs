// ======================================================================
// Aptos Keyless via Jolt zkVM
//
// Reimplements the Aptos keyless-zk-proofs Circom circuit (~1.4M R1CS
// constraints) as a Jolt guest program.
//
// Given a JWT from an OAuth provider (Google, Apple, etc.), proves:
//   1. JWT has valid RSA-SHA256 signature (PKCS#1 v1.5, e=65537)
//   2. JWT contains expected claims: iss, aud, sub/email, nonce, iat
//   3. email_verified == true (when uid_key is "email")
//   4. Nonce binds to ephemeral key + expiration
//   5. Identity commitment (IDC) is correctly derived
//   6. Ephemeral key hasn't expired: exp_date < iat + exp_horizon
//   7. Optional extra field (e.g., family_name) is present if requested
//
// Hash choices (vs Circom original):
//   SHA-256: JWT signature verification (must match OAuth provider)
//   Blake2b-256: all internal commitments (replaces Poseidon-over-BN254)
// ======================================================================

use oauth_verify::{base64url, bignum, hash, json, pkcs1};

// Re-export for host binary usage
pub use base64url::base64url_encode_no_pad;

use ruint::Uint;
type Uint2048 = Uint<2048, 32>;
#[allow(dead_code)]
type Uint4096 = Uint<4096, 64>;

// ─── RSA-2048 advice-based modexp ────────────────────────────────────

#[jolt::advice]
fn modmul_2048_step(
    a: [u64; 32],
    b: [u64; 32],
    n: [u64; 32],
) -> jolt::UntrustedAdvice<([u64; 32], [u64; 32])> {
    let a_wide = Uint4096::from_limbs({
        let mut l = [0u64; 64];
        l[..32].copy_from_slice(&a);
        l
    });
    let b_wide = Uint4096::from_limbs({
        let mut l = [0u64; 64];
        l[..32].copy_from_slice(&b);
        l
    });
    let n_wide = Uint4096::from_limbs({
        let mut l = [0u64; 64];
        l[..32].copy_from_slice(&n);
        l
    });
    let product = a_wide * b_wide;
    let q = product / n_wide;
    let r = product % n_wide;
    let mut q_limbs = [0u64; 32];
    q_limbs.copy_from_slice(&q.as_limbs()[..32]);
    let mut r_limbs = [0u64; 32];
    r_limbs.copy_from_slice(&r.as_limbs()[..32]);
    (q_limbs, r_limbs)
}

fn rsa_modexp_2048_advice(sig_limbs: &[u64; 32], n_limbs: &[u64; 32]) -> [u64; 32] {
    let mut current = *sig_limbs;
    for _ in 0..16 {
        let (q, r) = *modmul_2048_step(current, current, *n_limbs);
        jolt::check_advice!(bignum::verify_modsquare(&current, &q, n_limbs, &r));
        jolt::check_advice!(bignum::lt(&r, n_limbs));
        current = r;
    }
    let (q, r) = *modmul_2048_step(current, *sig_limbs, *n_limbs);
    jolt::check_advice!(bignum::verify_modmul(&current, sig_limbs, &q, n_limbs, &r));
    jolt::check_advice!(bignum::lt(&r, n_limbs));
    r
}

pub fn rsa_verify_pkcs1_sha256(signature: &[u8], modulus: &[u8], message_hash: &[u8; 32]) {
    assert!(signature.len() == 256, "signature must be 256 bytes");
    assert!(modulus.len() == 256, "modulus must be 256 bytes");

    let sig_uint = Uint2048::from_be_slice(signature);
    let n_uint = Uint2048::from_be_slice(modulus);
    let sig_limbs = *sig_uint.as_limbs();
    let n_limbs = *n_uint.as_limbs();

    let em_limbs = rsa_modexp_2048_advice(&sig_limbs, &n_limbs);
    let em_uint = Uint2048::from_limbs(em_limbs);
    let em = em_uint.to_be_bytes_vec();

    pkcs1::verify_pkcs1_sha256_padding(&em, message_hash);
}

// ─── Main provable function ──────────────────────────────────────────

/// Aptos keyless verification as a Jolt guest program.
///
/// Proves that the caller possesses a valid OAuth JWT that:
///   - is correctly signed by the provider (RSA-SHA256)
///   - contains a nonce binding to an ephemeral key + expiration
///   - contains the claimed identity (sub/email)
///   - identity commitment (IDC) is correctly derived
///   - ephemeral key hasn't expired (exp_date < iat + exp_horizon)
///   - optional extra field (e.g., family_name) is present if requested
///
/// Returns a serialized KeylessProofOutput (public outputs for on-chain verification).
#[jolt::provable(
    max_trace_length = 1048576,
    stack_size = 1048576,
    heap_size = 33554432,
    max_input_size = 65536,
    max_output_size = 4096
)]
fn keyless_verify(
    // base64url(header) + "." + base64url(payload)
    unsigned_jwt: Vec<u8>,
    // RSA-2048 signature, 256 bytes big-endian
    jwt_signature: Vec<u8>,
    // RSA-2048 modulus, 256 bytes big-endian
    rsa_modulus: Vec<u8>,
    // Ephemeral public key bytes (variable length, e.g. 34 for Ed25519)
    epk: Vec<u8>,
    // Expiration date (seconds since epoch)
    exp_date: u64,
    // Maximum allowed time horizon for JWT validity
    exp_horizon: u64,
    // Blinder/randomness for nonce derivation
    epk_blinder: Vec<u8>,
    // Privacy pepper for identity commitment
    pepper: Vec<u8>,
    // User ID key name, e.g. b"sub" or b"email"
    uid_key: Vec<u8>,
    // User ID value
    uid_value: Vec<u8>,
    // Audience (OAuth client ID)
    aud_value: Vec<u8>,
    // Issuer (e.g. b"https://accounts.google.com")
    iss_value: Vec<u8>,
    // Whether to use an extra field
    use_extra_field: u8,
    // Extra field key (e.g. b"family_name"), empty if unused
    extra_field_key: Vec<u8>,
    // Extra field value, empty if unused
    extra_field_value: Vec<u8>,
    // Override aud for IDC (empty if not overriding)
    override_aud_value: Vec<u8>,
) -> Vec<u8> {
    use jolt::{end_cycle_tracking, start_cycle_tracking};

    // ── 1. SHA-256 of the unsigned JWT ────────────────────────────────
    start_cycle_tracking("sha256_jwt");
    use sha2::{Digest, Sha256};
    let jwt_hash: [u8; 32] = Sha256::digest(&unsigned_jwt).into();
    end_cycle_tracking("sha256_jwt");

    // ── 2. RSA-2048 signature verification ────────────────────────────
    start_cycle_tracking("rsa_verify");
    rsa_verify_pkcs1_sha256(&jwt_signature, &rsa_modulus, &jwt_hash);
    end_cycle_tracking("rsa_verify");

    // ── 3. Parse JWT and extract claims ───────────────────────────────
    start_cycle_tracking("jwt_parse_claims");
    let dot_pos = unsigned_jwt
        .iter()
        .position(|&b| b == b'.')
        .expect("JWT missing dot");
    let header_b64 = &unsigned_jwt[..dot_pos];
    let payload_b64 = &unsigned_jwt[dot_pos + 1..];
    let payload = base64url::base64url_decode(payload_b64);

    // Issuer
    let actual_iss = json::json_get_value(&payload, b"iss").expect("iss not found");
    assert!(actual_iss == iss_value.as_slice(), "iss mismatch");

    // Audience
    let actual_aud = json::json_get_value(&payload, b"aud").expect("aud not found");
    assert!(actual_aud == aud_value.as_slice(), "aud mismatch");

    // User ID (sub or email)
    let actual_uid = json::json_get_value(&payload, &uid_key).expect("uid not found");
    assert!(actual_uid == uid_value.as_slice(), "uid mismatch");

    // Issued-at timestamp
    let actual_iat_bytes = json::json_get_value(&payload, b"iat").expect("iat not found");
    let iat = json::parse_u64(actual_iat_bytes);

    // email_verified check (when uid_key is "email")
    if uid_key == b"email" {
        let ev = json::json_get_value(&payload, b"email_verified");
        assert!(ev == Some(b"true" as &[u8]), "email_verified must be true");
    }

    // Extra field (optional)
    let extra_field_hash = if use_extra_field == 1 {
        let actual_extra = json::json_get_value(&payload, &extra_field_key).expect("extra field not found");
        assert!(actual_extra == extra_field_value.as_slice(), "extra field mismatch");
        hash::internal_hash_multi(&[&extra_field_key, &extra_field_value])
    } else {
        [0u8; 32]
    };
    end_cycle_tracking("jwt_parse_claims");

    // ── 4. Nonce verification ─────────────────────────────────────────
    //    nonce = base64url(Blake2b(epk ‖ epk_len ‖ exp_date ‖ epk_blinder))
    start_cycle_tracking("nonce_verify");
    let mut nonce_pre = Vec::with_capacity(128);
    nonce_pre.extend_from_slice(&epk);
    nonce_pre.extend_from_slice(&(epk.len() as u32).to_le_bytes());
    nonce_pre.extend_from_slice(&exp_date.to_le_bytes());
    nonce_pre.extend_from_slice(&epk_blinder);
    let nonce_hash = hash::internal_hash(&nonce_pre);
    let expected_nonce = base64url::base64url_encode_no_pad(&nonce_hash);

    let actual_nonce = json::json_get_value(&payload, b"nonce").expect("nonce not found");
    assert!(actual_nonce == expected_nonce.as_slice(), "nonce mismatch");
    end_cycle_tracking("nonce_verify");

    // ── 5. Expiration check ───────────────────────────────────────────
    //    exp_date < iat + exp_horizon
    start_cycle_tracking("expiration_check");
    assert!(exp_date < iat + exp_horizon, "ephemeral key expired");
    end_cycle_tracking("expiration_check");

    // ── 6. Identity commitment (IDC) ──────────────────────────────────
    //    IDC = Blake2b(pepper ‖ aud_hash ‖ uid_value_hash ‖ uid_name_hash)
    start_cycle_tracking("identity_commitment");
    let aud_for_idc = if !override_aud_value.is_empty() {
        &override_aud_value
    } else {
        &aud_value
    };
    let aud_hash = hash::internal_hash(aud_for_idc);
    let uid_value_hash = hash::internal_hash(&uid_value);
    let uid_name_hash = hash::internal_hash(&uid_key);
    let idc = hash::internal_hash_multi(&[&pepper, &aud_hash, &uid_value_hash, &uid_name_hash]);
    end_cycle_tracking("identity_commitment");

    // ── 7. Public outputs commitment ──────────────────────────────────
    //    14-field hash matching the Aptos circuit's public_inputs_hash structure
    start_cycle_tracking("output_commitments");
    let iss_hash = hash::internal_hash(&iss_value);
    let header_hash = hash::internal_hash(header_b64);
    let modulus_hash = hash::internal_hash(&rsa_modulus);
    let override_aud_hash = hash::internal_hash(&override_aud_value);

    let use_aud_override: u8 = if override_aud_value.is_empty() { 0 } else { 1 };

    let public_inputs_hash = hash::internal_hash_multi(&[
        &epk,                                    // ephemeral public key
        &(epk.len() as u32).to_le_bytes(),       // epk length
        &idc,                                     // identity commitment
        &exp_date.to_le_bytes(),                  // expiration date
        &exp_horizon.to_le_bytes(),               // expiration horizon
        &iss_hash,                                // hashed issuer
        &[use_extra_field],                       // flag
        &extra_field_hash,                        // hashed extra field
        &header_hash,                             // hashed JWT header
        &modulus_hash,                            // hashed RSA modulus
        &override_aud_hash,                       // hashed override aud
        &[use_aud_override],                      // flag
    ]);
    end_cycle_tracking("output_commitments");

    // ── 8. Return public outputs ──────────────────────────────────────
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(&public_inputs_hash);  // 32 B: single commitment
    output.extend_from_slice(&idc);                  // 32 B: identity commitment
    output.extend_from_slice(&iss_hash);             // 32 B: issuer hash
    output.extend_from_slice(&header_hash);          // 32 B: JWT header hash
    output.extend_from_slice(&modulus_hash);          // 32 B: RSA modulus hash
    output.extend_from_slice(&extra_field_hash);      // 32 B: extra field hash
    output.extend_from_slice(&override_aud_hash);     // 32 B: override aud hash
    output.push(use_extra_field);                     // 1 B: flag
    output.push(use_aud_override);                    // 1 B: flag
    output
}
