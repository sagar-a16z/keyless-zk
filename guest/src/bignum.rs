//! Bignum arithmetic for advice-based RSA-2048 modular exponentiation verification.
//!
//! Little-endian u64 limb representation. The guest never computes modexp —
//! the host provides (quotient, remainder) via advice. The guest verifies:
//!   a*b == q*n + r  AND  r < n

const N: usize = 32; // 2048 bits / 64 bits per limb
const W: usize = 64; // 2 * N for wide (4096-bit) products

/// Schoolbook multiply: a * b -> 4096-bit result.
fn mul_wide(a: &[u64; N], b: &[u64; N]) -> [u64; W] {
    let mut result = [0u64; W];
    for i in 0..N {
        let mut carry: u64 = 0;
        for j in 0..N {
            let prod =
                (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + (carry as u128);
            result[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        result[i + N] = carry;
    }
    result
}

/// Squaring with symmetry optimization: a * a -> 4096-bit result.
fn square_wide(a: &[u64; N]) -> [u64; W] {
    let mut result = [0u64; W];

    // Cross terms (i < j)
    for i in 0..N {
        let mut carry: u64 = 0;
        for j in (i + 1)..N {
            let prod =
                (a[i] as u128) * (a[j] as u128) + (result[i + j] as u128) + (carry as u128);
            result[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        result[i + N] = carry;
    }

    // Double all cross terms
    let mut carry: u64 = 0;
    for r in result.iter_mut() {
        let doubled = (*r as u128) * 2 + (carry as u128);
        *r = doubled as u64;
        carry = (doubled >> 64) as u64;
    }

    // Add diagonal terms (a[i]^2)
    let mut carry: u64 = 0;
    for i in 0..N {
        let prod = (a[i] as u128) * (a[i] as u128) + (result[2 * i] as u128) + (carry as u128);
        result[2 * i] = prod as u64;
        carry = (prod >> 64) as u64;
        let sum = (result[2 * i + 1] as u128) + (carry as u128);
        result[2 * i + 1] = sum as u64;
        carry = (sum >> 64) as u64;
    }

    result
}

/// Verify wide == base + ext (4096-bit == 4096-bit + 2048-bit zero-extended).
fn verify_sum_eq(wide: &[u64; W], base: &[u64; W], ext: &[u64; N]) -> bool {
    let mut carry: u64 = 0;
    for i in 0..W {
        let ext_val = if i < N { ext[i] } else { 0 };
        let (s1, c1) = base[i].overflowing_add(ext_val);
        let (s2, c2) = s1.overflowing_add(carry);
        if s2 != wide[i] {
            return false;
        }
        carry = c1 as u64 + c2 as u64;
    }
    carry == 0
}

/// Verify a*b == q*n + r (modular multiplication).
pub fn verify_modmul(
    a: &[u64; N],
    b: &[u64; N],
    q: &[u64; N],
    n: &[u64; N],
    r: &[u64; N],
) -> bool {
    let ab = mul_wide(a, b);
    let qn = mul_wide(q, n);
    verify_sum_eq(&ab, &qn, r)
}

/// Verify a^2 == q*n + r (modular squaring).
pub fn verify_modsquare(
    a: &[u64; N],
    q: &[u64; N],
    n: &[u64; N],
    r: &[u64; N],
) -> bool {
    let a2 = square_wide(a);
    let qn = mul_wide(q, n);
    verify_sum_eq(&a2, &qn, r)
}

/// a < b (little-endian limb comparison).
pub fn lt(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}
