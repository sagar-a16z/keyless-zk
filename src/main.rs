#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::time::Instant;
use tracing::info;

use guest::base64url_encode_no_pad;

fn internal_hash_host(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2b512;
    use sha2::Digest;
    let full = Blake2b512::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

fn pad_be(bytes: &[u8], target_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; target_len];
    let offset = target_len.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(target_len);
    out[offset..offset + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    out
}

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("=== Aptos Keyless via Jolt ===");

    // ── 1. Generate test RSA-2048 key pair ────────────────────────────
    info!("Generating RSA-2048 test key...");
    use rand::rngs::OsRng;
    use rsa::{pkcs1v15::SigningKey, signature::Signer, traits::PublicKeyParts, RsaPrivateKey};

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("keygen failed");
    let modulus_bytes = pad_be(&private_key.n().to_bytes_be(), 256);

    // ── 2. Build test JWT claims (matching Aptos test data structure) ──
    // Same Google OAuth claims as the Aptos keyless circuit test (input_gen.py)
    let epk = vec![0xABu8; 34]; // 34 bytes (Ed25519: 1 type + 32 key + 1)
    let exp_date: u64 = 111111111111;
    let exp_horizon: u64 = 999999999999;
    let epk_blinder = vec![42u8]; // matches Aptos test: blinder=42
    let pepper = vec![76u8]; // matches Aptos test: pepper=76
    let uid_key = b"sub".to_vec();
    let uid_value = b"113990307082899718775".to_vec(); // same sub as Aptos test
    let aud_value = b"407408718192.apps.googleusercontent.com".to_vec();
    let iss_value = b"https://accounts.google.com".to_vec();
    let use_extra_field: u8 = 1;
    let extra_field_key = b"family_name".to_vec();
    let extra_field_value = b"Straka".to_vec(); // same as Aptos test
    let override_aud_value: Vec<u8> = Vec::new();

    // Derive nonce: Blake2b(epk ‖ epk_len ‖ exp_date ‖ epk_blinder)
    let mut nonce_pre = Vec::new();
    nonce_pre.extend_from_slice(&epk);
    nonce_pre.extend_from_slice(&(epk.len() as u32).to_le_bytes());
    nonce_pre.extend_from_slice(&exp_date.to_le_bytes());
    nonce_pre.extend_from_slice(&epk_blinder);
    let nonce_hash = internal_hash_host(&nonce_pre);
    let nonce_b64 = base64url_encode_no_pad(&nonce_hash);
    let nonce_str = String::from_utf8(nonce_b64).unwrap();
    info!("Derived nonce: {}", nonce_str);

    // Build JSON payload with all Aptos keyless claims
    let payload_json = format!(
        r#"{{"iss":"{}","azp":"{}","aud":"{}","sub":"{}","at_hash":"lVeD4xP6Q1ZGrL3gFcCQLQ","name":"Michael Straka","family_name":"{}","given_name":"Michael","iat":1719866138,"exp":1719869738,"nonce":"{}","email_verified":true}}"#,
        std::str::from_utf8(&iss_value).unwrap(),
        std::str::from_utf8(&aud_value).unwrap(),
        std::str::from_utf8(&aud_value).unwrap(),
        std::str::from_utf8(&uid_value).unwrap(),
        std::str::from_utf8(&extra_field_value).unwrap(),
        nonce_str,
    );
    info!("Payload length: {} chars", payload_json.len());

    let header_json = r#"{"alg":"RS256","typ":"JWT","kid":"test-rsa"}"#;
    let header_b64 = base64url_encode_no_pad(header_json.as_bytes());
    let payload_b64 = base64url_encode_no_pad(payload_json.as_bytes());

    let mut unsigned_jwt = Vec::new();
    unsigned_jwt.extend_from_slice(&header_b64);
    unsigned_jwt.push(b'.');
    unsigned_jwt.extend_from_slice(&payload_b64);
    info!("Unsigned JWT: {} bytes", unsigned_jwt.len());

    // ── 3. Sign with RSA-SHA256 ───────────────────────────────────────
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let signature = signing_key.sign(&unsigned_jwt);
    let sig_bytes: Vec<u8> = Box::<[u8]>::from(signature).into_vec();
    let sig_padded = pad_be(&sig_bytes, 256);
    info!("RSA signature: {} bytes", sig_padded.len());

    // ── 4. Sanity check ───────────────────────────────────────────────
    {
        use rsa::{pkcs1v15::VerifyingKey, signature::Verifier, RsaPublicKey};
        let pub_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&modulus_bytes),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(pub_key);
        let sig_obj = rsa::pkcs1v15::Signature::try_from(sig_padded.as_slice()).unwrap();
        verifying_key
            .verify(&unsigned_jwt, &sig_obj)
            .expect("rsa crate verify failed");
        info!("Host-side RSA verification: OK");
    }

    // ── 5. Compile, preprocess, prove ─────────────────────────────────
    info!("Compiling guest program...");
    let target_dir = "/tmp/jolt-keyless-targets";
    let mut program = guest::compile_keyless_verify(target_dir);

    info!("Preprocessing...");
    let shared =
        guest::preprocess_shared_keyless_verify(&mut program).expect("shared preprocess failed");
    let prover_prep = guest::preprocess_prover_keyless_verify(shared.clone());
    let verifier_setup = prover_prep.generators.to_verifier_setup();
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep =
        guest::preprocess_verifier_keyless_verify(shared, verifier_setup, Some(blindfold_setup));

    let prove = guest::build_prover_keyless_verify(program, prover_prep);
    let verify = guest::build_verifier_keyless_verify(verifier_prep);

    info!("Generating proof...");
    let t = Instant::now();
    let (output, proof, io) = prove(
        unsigned_jwt.clone(),
        sig_padded.clone(),
        modulus_bytes.clone(),
        epk.clone(),
        exp_date,
        exp_horizon,
        epk_blinder.clone(),
        pepper.clone(),
        uid_key.clone(),
        uid_value.clone(),
        aud_value.clone(),
        iss_value.clone(),
        use_extra_field,
        extra_field_key.clone(),
        extra_field_value.clone(),
        override_aud_value.clone(),
    );
    let prove_time = t.elapsed();
    info!("Prover time: {:.2}s", prove_time.as_secs_f64());

    // ── 6. Measure proof size ─────────────────────────────────────────
    {
        use jolt_sdk::Serializable;
        let proof_size = proof.size().expect("proof size");
        info!(
            "Proof size: {} bytes ({:.1} KB)",
            proof_size,
            proof_size as f64 / 1024.0
        );
        proof.save_to_file("proof.bin").expect("write proof.bin");
        info!("Written proof.bin");
    }

    // ── 7. Display outputs ────────────────────────────────────────────
    info!("--- Proof Output ---");
    info!("public_inputs_hash: {:02x?}", &output[0..8]);
    info!("idc:                {:02x?}", &output[32..40]);
    info!("iss_hash:           {:02x?}", &output[64..72]);
    info!("header_hash:        {:02x?}", &output[96..104]);
    info!("modulus_hash:       {:02x?}", &output[128..136]);
    info!("extra_field_hash:   {:02x?}", &output[160..168]);
    info!("use_extra_field:    {}", output[224]);
    info!("use_aud_override:   {}", output[225]);

    // ── 8. Verify proof ───────────────────────────────────────────────
    info!("Verifying proof...");
    let t = Instant::now();
    let valid = verify(
        unsigned_jwt,
        sig_padded,
        modulus_bytes,
        epk,
        exp_date,
        exp_horizon,
        epk_blinder,
        pepper,
        uid_key,
        uid_value,
        aud_value,
        iss_value,
        use_extra_field,
        extra_field_key,
        extra_field_value,
        override_aud_value,
        output,
        io.panic,
        proof,
    );
    let verify_time = t.elapsed();
    info!("Verifier time: {:.2}s", verify_time.as_secs_f64());
    info!("Proof valid: {valid}");
    assert!(valid, "proof verification failed!");
    info!("Aptos keyless proof verified successfully.");
}
