# Aptos Keyless via Jolt

Zero-knowledge OAuth identity proof via [Jolt zkVM](https://github.com/a16z/jolt). A reimplementation of the [Aptos keyless-zk-proofs](https://github.com/aptos-labs/keyless-zk-proofs) Circom/Groth16 circuit (~1.4M R1CS constraints) as a Jolt guest program.

Given a JWT from an OAuth provider (Google, Apple, etc.), proves:
1. The JWT has a valid RSA-SHA256 signature (PKCS#1 v1.5, e=65537)
2. JWT contains expected claims: iss, aud, sub/email, nonce, iat
3. email_verified == true (when uid key is "email")
4. Nonce binds to an ephemeral key + expiration date
5. Identity commitment (IDC) is correctly derived
6. Ephemeral key hasn't expired: exp_date < iat + exp_horizon
7. Optional extra field (e.g., family_name) is present if requested

Test data uses the same Google OAuth claims as the Aptos circuit test suite (input_gen.py): same `sub`, `aud`, `iss`, `family_name`, `iat`.

## Performance (Apple M4, single-threaded, ZK/BlindFold enabled)

| Metric | Value |
|---|---|
| Total cycles | 792,922 |
| Prover time | 5.1s |
| Verifier time | 0.09s |
| Proof size | 90.1 KB |
| Peak memory (jemalloc) | ~1.5 GB |
| `max_trace_length` | 2^20 (1,048,576) |

### Per-section cycle breakdown

| Section | Cycles | % | What it does |
|---|---|---|---|
| `rsa_verify` | 470,182 | 59.3% | RSA-2048 modexp (17 advice-verified steps) + PKCS#1 v1.5 padding |
| `jwt_parse_claims` | 81,188 | 10.2% | Base64 decode + 7 claim extractions (iss, aud, sub, iat, ev, nonce, extra) |
| `sha256_jwt` | 55,254 | 7.0% | SHA-256 of unsigned JWT (564 bytes) |
| `output_commitments` | 46,156 | 5.8% | 12-field Blake2b public inputs hash |
| `nonce_verify` | 28,774 | 3.6% | Blake2b nonce derivation + base64 encode + JWT match |
| `identity_commitment` | 28,023 | 3.5% | IDC = Blake2b(pepper, aud_hash, uid_hash, uid_name_hash) |
| `expiration_check` | 15 | 0.0% | exp_date < iat + exp_horizon |
| serde + overhead | ~83,330 | 10.5% | Jolt postcard deserialization of function inputs |

### vs Aptos Keyless (Circom/Groth16)

| Metric | Aptos Keyless (Groth16) | Keyless-Jolt |
|---|---|---|
| **Constraints / cycles** | 1,376,867 R1CS | 792,922 RISC-V |
| **Proof system** | Groth16 BN254 (rapidsnark) | Jolt (Dory PCS) |
| **Trusted setup** | Required | **None** |
| **Internal hash** | Poseidon (BN254-native) | Blake2b-256 |
| **Proof size** | ~256 bytes | 90.1 KB |
| **ZK** | Groth16 (inherent) | BlindFold |
| **Guest code** | ~50 Circom templates + circomlib | ~450 lines Rust |

## Hash choices vs original

| Role | Original (Circom) | This (Jolt) | Why |
|---|---|---|---|
| JWT signature | SHA-256 | SHA-256 | Must match OAuth provider |
| Internal commitments | Poseidon (BN254) | Blake2b-256 | Poseidon needs BN254 field ops (no Jolt inline); Blake2b has inline (~5x faster than SHA-256) |

## RSA-2048 approach

Uses Jolt's `#[jolt::advice]` mechanism. The host computes `(quotient, remainder)` for each modular multiply; the guest only verifies `a*b == q*n + r` via schoolbook wide multiplication. For e=65537: 16 squarings + 1 multiply = 17 advice-verified steps at ~27K cycles each.

## Running

```bash
RUST_LOG=info cargo run --release
```

## Project structure

```
guest/src/lib.rs      # Jolt guest: provable keyless_verify function
guest/src/bignum.rs   # Wide multiply + advice verification (2048-bit)
guest/src/main.rs     # RISC-V binary stub
src/main.rs           # Host: test JWT generation, prove, verify
```
