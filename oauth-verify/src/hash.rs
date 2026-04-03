pub fn internal_hash(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2b512;
    use sha2::Digest;
    let full = Blake2b512::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

pub fn internal_hash_multi(slices: &[&[u8]]) -> [u8; 32] {
    let mut preimage = Vec::new();
    for s in slices {
        preimage.extend_from_slice(&(s.len() as u32).to_le_bytes());
        preimage.extend_from_slice(s);
    }
    internal_hash(&preimage)
}
