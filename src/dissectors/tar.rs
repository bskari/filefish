use super::{Block, ByteRange, Dissector};

const BLOCK_SIZE: u64 = 512;
const MAX_ENTRIES: usize = 100_000;

pub struct TarDissector;

impl Dissector for TarDissector {
    fn name(&self) -> &'static str {
        "TAR"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < BLOCK_SIZE as usize {
            return false;
        }
        match data.get(257..262) {
            Some(magic) => magic == b"ustar",
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut offset = 0u64;
        let data_len = data.len() as u64;
        let mut entries = 0usize;

        while offset + BLOCK_SIZE <= data_len {
            entries += 1;
            if entries > MAX_ENTRIES {
                break;
            }

            let header = &data[offset as usize..(offset + BLOCK_SIZE) as usize];
            if header.iter().all(|&b| b == 0) {
                blocks.push(Block::leaf(
                    "End of archive",
                    ByteRange::new(offset, offset + BLOCK_SIZE),
                ));
                break;
            }

            match file_entry_block(data, offset) {
                Some(block) => {
                    let next_offset = block.range.end;
                    if next_offset <= offset {
                        break;
                    }
                    offset = next_offset;
                    blocks.push(block);
                }
                None => break,
            }
        }

        blocks
    }
}

fn ascii_field(data: &[u8], offset: usize, len: usize) -> String {
    data.get(offset..offset + len)
        .map(|bytes| {
            let trimmed: Vec<u8> = bytes
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect();
            String::from_utf8_lossy(&trimmed)
                .trim()
                .to_string()
        })
        .unwrap_or_default()
}

fn octal_field(data: &[u8], offset: usize, len: usize) -> u64 {
    let raw = match data.get(offset..offset + len) {
        Some(bytes) => bytes,
        None => return 0,
    };
    let trimmed: String = raw
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect();
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return 0;
    }
    u64::from_str_radix(trimmed, 8).unwrap_or(0)
}

fn typeflag_name(flag: u8) -> String {
    match flag {
        b'0' | 0 => "Regular file".to_string(),
        b'1' => "Hard link".to_string(),
        b'2' => "Symbolic link".to_string(),
        b'3' => "Character device".to_string(),
        b'4' => "Block device".to_string(),
        b'5' => "Directory".to_string(),
        b'6' => "FIFO".to_string(),
        b'g' => "PAX global extended header".to_string(),
        b'x' => "PAX extended header".to_string(),
        c => format!("unknown ('{}')", c as char),
    }
}

fn file_entry_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + BLOCK_SIZE as usize {
        return None;
    }

    let name = ascii_field(data, off, 100);
    let mode = ascii_field(data, off + 100, 8);
    let uid = octal_field(data, off + 108, 8);
    let gid = octal_field(data, off + 116, 8);
    let size = octal_field(data, off + 124, 12);
    let mtime = octal_field(data, off + 136, 12);
    let typeflag = data[off + 156];
    let linkname = ascii_field(data, off + 157, 100);
    let uname = ascii_field(data, off + 265, 32);
    let gname = ascii_field(data, off + 297, 32);
    let prefix = ascii_field(data, off + 345, 155);

    let data_len = data.len() as u64;
    let header_end = offset + BLOCK_SIZE;
    let data_start = header_end;
    let data_end = (data_start + size).min(data_len);

    let padded_size = size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    // Clamp to the actual file length if the declared size overruns a
    // truncated archive; forward progress is still guaranteed since
    // header_end already advanced by a full BLOCK_SIZE from offset.
    let entry_end = (header_end + padded_size).min(data_len).max(header_end);

    let display_name = if prefix.is_empty() {
        name.clone()
    } else {
        format!("{prefix}/{name}")
    };

    let mut children = vec![
        Block::leaf(
            format!("Name: {name}"),
            ByteRange::new(offset, offset + 100),
        ),
        Block::leaf(
            format!("Mode: {mode}"),
            ByteRange::new(offset + 100, offset + 108),
        ),
        Block::leaf(
            format!("UID: {uid}"),
            ByteRange::new(offset + 108, offset + 116),
        ),
        Block::leaf(
            format!("GID: {gid}"),
            ByteRange::new(offset + 116, offset + 124),
        ),
        Block::leaf(
            format!("Size: {size}"),
            ByteRange::new(offset + 124, offset + 136),
        ),
        Block::leaf(
            format!("Mtime: {mtime}"),
            ByteRange::new(offset + 136, offset + 148),
        ),
        Block::leaf(
            format!("Type: {}", typeflag_name(typeflag)),
            ByteRange::new(offset + 156, offset + 157),
        ),
        Block::leaf(
            format!("Link name: {linkname}"),
            ByteRange::new(offset + 157, offset + 257),
        ),
        Block::leaf(
            format!("Owner user name: {uname}"),
            ByteRange::new(offset + 265, offset + 297),
        ),
        Block::leaf(
            format!("Owner group name: {gname}"),
            ByteRange::new(offset + 297, offset + 329),
        ),
    ];

    if !prefix.is_empty() {
        children.push(Block::leaf(
            format!("Prefix: {prefix}"),
            ByteRange::new(offset + 345, offset + 500),
        ));
    }

    if data_end > data_start {
        children.push(Block::leaf(
            "File data",
            ByteRange::new(data_start, data_end),
        ));
    }

    Some(Block::node(
        format!("File: {display_name}"),
        ByteRange::new(offset, entry_end),
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn octal_bytes(value: u64, width: usize) -> Vec<u8> {
        // e.g. width 12 -> 11 octal digits + trailing NUL
        let digits = width - 1;
        let s = format!("{:0width$o}", value, width = digits);
        let mut bytes = s.into_bytes();
        bytes.push(0);
        assert_eq!(bytes.len(), width);
        bytes
    }

    fn put_field(buf: &mut [u8], offset: usize, bytes: &[u8]) {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn build_tar(name: &str, file_data: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 512];

        let name_bytes = name.as_bytes();
        put_field(&mut header, 0, name_bytes);
        put_field(&mut header, 100, &octal_bytes(0o644, 8));
        put_field(&mut header, 108, &octal_bytes(0, 8));
        put_field(&mut header, 116, &octal_bytes(0, 8));
        put_field(&mut header, 124, &octal_bytes(file_data.len() as u64, 12));
        put_field(&mut header, 136, &octal_bytes(0, 12));
        // chksum (148..156) left as spaces/zero; not validated by dissector
        header[156] = b'0'; // typeflag: regular file
        put_field(&mut header, 257, b"ustar\0");
        put_field(&mut header, 263, b"00");

        let mut data = Vec::new();
        data.extend_from_slice(&header);
        data.extend_from_slice(file_data);
        let padded_len = (file_data.len() as u64).div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
        let padding = padded_len - file_data.len() as u64;
        data.extend(std::iter::repeat(0u8).take(padding as usize));

        // Two all-zero end-of-archive blocks.
        data.extend(std::iter::repeat(0u8).take(1024));

        data
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn matches_tar_magic() {
        let data = build_tar("hello.txt", b"hello world");
        assert!(TarDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_tar_data() {
        assert!(!TarDissector.matches(b""));
        assert!(!TarDissector.matches(b"not a tar file"));
        let mut short = vec![0u8; 100];
        put_field(&mut short, 0, b"ustar");
        assert!(!TarDissector.matches(&short));
        let garbage = vec![0xAAu8; 600];
        assert!(!TarDissector.matches(&garbage));
    }

    #[test]
    fn dissect_returns_empty_or_graceful_for_truncated_header() {
        let blocks = TarDissector.dissect(b"too short");
        assert!(blocks.is_empty());

        let truncated = vec![0xAAu8; 100];
        let blocks = TarDissector.dissect(&truncated);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_single_file_entry() {
        let data = build_tar("hello.txt", b"hello world");
        let blocks = TarDissector.dissect(&data);

        let file = find_block(&blocks, "File: hello.txt");
        assert!(file.children.iter().any(|b| b.label == "Name: hello.txt"));
        assert!(file.children.iter().any(|b| b.label == "Size: 11"));

        let file_data = file
            .children
            .iter()
            .find(|b| b.label == "File data")
            .expect("File data block present");
        assert_eq!(file_data.range, ByteRange::new(512, 523));
    }

    #[test]
    fn identify_reports_tar() {
        let data = build_tar("a.txt", b"data");
        assert_eq!(super::super::identify(&data), "TAR");
    }
}
