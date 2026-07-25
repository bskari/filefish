use std::fmt::Write;

pub fn hex_dump(data: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut out = String::new();

    for (offset, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();

        for byte in chunk {
            let _ = write!(hex, "{byte:02x} ");
            ascii.push(if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..BYTES_PER_LINE {
            hex.push_str("   ");
        }

        let _ = writeln!(out, "{:08x}  {hex} {ascii}", offset * BYTES_PER_LINE);
    }

    out
}
