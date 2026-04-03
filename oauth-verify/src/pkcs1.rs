pub fn verify_pkcs1_sha256_padding(em: &[u8], message_hash: &[u8; 32]) {
    assert!(em.len() == 256, "em must be 256 bytes");
    assert!(em[0] == 0x00, "PKCS1: byte 0");
    assert!(em[1] == 0x01, "PKCS1: byte 1");
    for i in 2..204 {
        assert!(em[i] == 0xFF, "PKCS1: padding byte");
    }
    assert!(em[204] == 0x00, "PKCS1: separator");
    const DER: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    for i in 0..19 {
        assert!(em[205 + i] == DER[i], "PKCS1: DER prefix");
    }
    for i in 0..32 {
        assert!(em[224 + i] == message_hash[i], "PKCS1: hash mismatch");
    }
}
