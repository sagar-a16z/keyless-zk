fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Extract a JSON value for a given key from a flat JSON object.
/// Only matches keys at the top level (preceded by `{` or `,` + optional whitespace).
pub fn json_get_value<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pattern = Vec::with_capacity(key.len() + 2);
    pattern.push(b'"');
    pattern.extend_from_slice(key);
    pattern.push(b'"');

    let mut search_from = 0;
    let key_pos = loop {
        let pos = find_bytes(&json[search_from..], &pattern)?;
        let abs_pos = search_from + pos;
        let mut j = abs_pos;
        while j > 0 && matches!(json[j - 1], b' ' | b'\t' | b'\n' | b'\r') {
            j -= 1;
        }
        if j == 0 || json[j - 1] == b'{' || json[j - 1] == b',' {
            break abs_pos;
        }
        search_from = abs_pos + 1;
    };
    let mut i = key_pos + pattern.len();

    while i < json.len() && matches!(json[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= json.len() || json[i] != b':' {
        return None;
    }
    i += 1;
    while i < json.len() && matches!(json[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= json.len() {
        return None;
    }

    if json[i] == b'"' {
        i += 1;
        let start = i;
        while i < json.len() && json[i] != b'"' {
            if json[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        Some(&json[start..i])
    } else {
        let start = i;
        while i < json.len() && !matches!(json[i], b',' | b'}' | b']' | b' ' | b'\n' | b'\r') {
            i += 1;
        }
        Some(&json[start..i])
    }
}

/// Parse an ASCII decimal string to u64.
pub fn parse_u64(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes {
        assert!(b >= b'0' && b <= b'9', "not a digit");
        val = val * 10 + (b - b'0') as u64;
    }
    val
}
