use super::{Block, ByteRange, Dissector};

const MAGIC: &[u8] = &[0x1f, 0x8b];

#[allow(dead_code)]
const FTEXT: u8 = 0x01;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

pub struct GzipDissector;

impl Dissector for GzipDissector {
    fn name(&self) -> &'static str {
        "Gzip"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        let Some(header) = header_block(data) else {
            return blocks;
        };
        let header_end = header.range.end;
        blocks.push(header);

        let data_len = data.len() as u64;
        let trailer_start = if data_len >= header_end + 8 {
            data_len - 8
        } else {
            data_len
        };

        if trailer_start > header_end {
            blocks.push(Block::leaf(
                "Compressed data",
                ByteRange::new(header_end, trailer_start),
            ));
        }

        if let Some(trailer) = trailer_block(data, trailer_start) {
            blocks.push(trailer);
        }

        blocks
    }
}

fn compression_method_name(value: u8) -> String {
    match value {
        8 => "Deflate".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn os_name(value: u8) -> String {
    match value {
        0 => "FAT".to_string(),
        1 => "Amiga".to_string(),
        2 => "VMS".to_string(),
        3 => "Unix".to_string(),
        4 => "VM/CMS".to_string(),
        5 => "Atari TOS".to_string(),
        6 => "HPFS".to_string(),
        7 => "Macintosh".to_string(),
        8 => "Z-System".to_string(),
        9 => "CP/M".to_string(),
        10 => "TOPS-20".to_string(),
        11 => "NTFS".to_string(),
        12 => "QDOS".to_string(),
        13 => "Acorn RISCOS".to_string(),
        255 => "unknown".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Finds the offset of a null terminator starting at `offset`, returning the
/// end offset (exclusive of the byte after the terminator) if found.
fn find_null_terminated_end(data: &[u8], offset: usize) -> Option<u64> {
    let rest = data.get(offset..)?;
    let pos = rest.iter().position(|&b| b == 0)?;
    Some((offset + pos + 1) as u64)
}

fn header_block(data: &[u8]) -> Option<Block> {
    if data.len() < 10 {
        return None;
    }

    let cm = data[2];
    let flg = data[3];
    let mtime = read_u32(data, 4)?;
    let xfl = data[8];
    let os = data[9];

    let mut children = vec![
        Block::leaf("ID1: 0x1f", ByteRange::new(0, 1)),
        Block::leaf("ID2: 0x8b", ByteRange::new(1, 2)),
        Block::leaf(
            format!("Compression method: {}", compression_method_name(cm)),
            ByteRange::new(2, 3),
        ),
        Block::leaf(format!("Flags: {flg:#04x}"), ByteRange::new(3, 4)),
        Block::leaf(format!("Modification time: {mtime}"), ByteRange::new(4, 8)),
        Block::leaf(format!("Extra flags: {xfl:#04x}"), ByteRange::new(8, 9)),
        Block::leaf(format!("OS: {}", os_name(os)), ByteRange::new(9, 10)),
    ];

    let mut offset = 10u64;

    if flg & FEXTRA != 0 {
        let xlen = read_u16(data, offset as usize)? as u64;
        children.push(Block::leaf(
            format!("Extra field length: {xlen}"),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
        let extra_end = (offset + xlen).min(data.len() as u64);
        if extra_end > offset {
            children.push(Block::leaf(
                "Extra field",
                ByteRange::new(offset, extra_end),
            ));
        }
        if extra_end < offset + xlen {
            // Truncated extra field; stop parsing further optional fields.
            let header_end = extra_end;
            return Some(Block::node(
                "Gzip header",
                ByteRange::new(0, header_end),
                children,
            ));
        }
        offset = extra_end;
    }

    if flg & FNAME != 0 {
        let name_end = find_null_terminated_end(data, offset as usize)?;
        let name = String::from_utf8_lossy(&data[offset as usize..(name_end - 1) as usize])
            .into_owned();
        children.push(Block::leaf(
            format!("Original file name: {name}"),
            ByteRange::new(offset, name_end),
        ));
        offset = name_end;
    }

    if flg & FCOMMENT != 0 {
        let comment_end = find_null_terminated_end(data, offset as usize)?;
        let comment =
            String::from_utf8_lossy(&data[offset as usize..(comment_end - 1) as usize])
                .into_owned();
        children.push(Block::leaf(
            format!("Comment: {comment}"),
            ByteRange::new(offset, comment_end),
        ));
        offset = comment_end;
    }

    if flg & FHCRC != 0 {
        if offset + 2 > data.len() as u64 {
            return Some(Block::node(
                "Gzip header",
                ByteRange::new(0, offset),
                children,
            ));
        }
        let crc16 = read_u16(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Header CRC16: {crc16:#06x}"),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }

    Some(Block::node("Gzip header", ByteRange::new(0, offset), children).expanded())
}

fn trailer_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 8 {
        return None;
    }

    let crc32 = read_u32(data, off)?;
    let isize = read_u32(data, off + 4)?;

    let children = vec![
        Block::leaf(
            format!("CRC-32: {crc32:#010x}"),
            ByteRange::new(offset, offset + 4),
        ),
        Block::leaf(
            format!("Input size (mod 2^32): {isize}"),
            ByteRange::new(offset + 4, offset + 8),
        ),
    ];

    Some(Block::node(
        "Trailer",
        ByteRange::new(offset, offset + 8),
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_gzip(name: &str, compressed: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, MAGIC);
        data.push(8); // CM: deflate
        data.push(FNAME); // FLG: FNAME set
        push_bytes(&mut data, &0u32.to_le_bytes()); // MTIME
        data.push(0); // XFL
        data.push(3); // OS: Unix
        push_bytes(&mut data, name.as_bytes());
        data.push(0); // null terminator
        push_bytes(&mut data, compressed);
        push_bytes(&mut data, &0xdeadbeefu32.to_le_bytes()); // CRC32 (fake)
        push_bytes(&mut data, &42u32.to_le_bytes()); // ISIZE (fake)
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
    fn matches_gzip_magic() {
        let data = build_gzip("hello.txt", b"fake compressed data");
        assert!(GzipDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_gzip_data() {
        assert!(!GzipDissector.matches(b"not a gzip file"));
        assert!(!GzipDissector.matches(b""));
        assert!(!GzipDissector.matches(b"\x1f\x00"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = GzipDissector.dissect(&[0x1f, 0x8b, 8, 0]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_header_data_and_trailer() {
        let data = build_gzip("hello.txt", b"fake compressed data");
        let blocks = GzipDissector.dissect(&data);

        let header = find_block(&blocks, "Gzip header");
        assert!(
            header
                .children
                .iter()
                .any(|b| b.label == "Original file name: hello.txt")
        );
        assert!(
            header
                .children
                .iter()
                .any(|b| b.label == "Compression method: Deflate")
        );

        assert!(blocks.iter().any(|b| b.label == "Compressed data"));

        let trailer = find_block(&blocks, "Trailer");
        assert!(
            trailer
                .children
                .iter()
                .any(|b| b.label == "CRC-32: 0xdeadbeef")
        );
        assert!(
            trailer
                .children
                .iter()
                .any(|b| b.label == "Input size (mod 2^32): 42")
        );
    }

    #[test]
    fn identify_reports_gzip() {
        let data = build_gzip("a.txt", b"data");
        assert_eq!(super::super::identify(&data), "Gzip");
    }
}
