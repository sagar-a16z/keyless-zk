pub fn base64url_decode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &ch in input {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => panic!("invalid base64url char"),
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    output
}

pub fn base64url_encode_no_pad(input: &[u8]) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < input.len() {
        let (b0, b1, b2) = (input[i] as u32, input[i + 1] as u32, input[i + 2] as u32);
        out.push(T[(b0 >> 2) as usize]);
        out.push(T[((b0 & 3) << 4 | b1 >> 4) as usize]);
        out.push(T[((b1 & 0xf) << 2 | b2 >> 6) as usize]);
        out.push(T[(b2 & 0x3f) as usize]);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let b0 = input[i] as u32;
            out.push(T[(b0 >> 2) as usize]);
            out.push(T[((b0 & 3) << 4) as usize]);
        }
        2 => {
            let (b0, b1) = (input[i] as u32, input[i + 1] as u32);
            out.push(T[(b0 >> 2) as usize]);
            out.push(T[((b0 & 3) << 4 | b1 >> 4) as usize]);
            out.push(T[((b1 & 0xf) << 2) as usize]);
        }
        _ => {}
    }
    out
}
