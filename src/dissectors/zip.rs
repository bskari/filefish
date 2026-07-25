use super::{Block, ByteRange, Dissector};

const LOCAL_FILE_SIGNATURE: u32 = 0x04034b50;
const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x02014b50;
const EOCD_SIGNATURE: u32 = 0x06054b50;
const LOCAL_FILE_MAGIC: &[u8] = &[0x50, 0x4B, 0x03, 0x04];

pub struct ZipDissector;

impl Dissector for ZipDissector {
    fn name(&self) -> &'static str {
        "ZIP"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(LOCAL_FILE_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut offset = 0u64;

        while let Some(signature) = read_u32(data, offset as usize) {
            if signature == LOCAL_FILE_SIGNATURE {
                match local_file_block(data, offset) {
                    Some(block) => {
                        offset = block.range.end;
                        blocks.push(block);
                    }
                    None => break,
                }
            } else {
                break;
            }
        }

        while let Some(signature) = read_u32(data, offset as usize) {
            if signature == CENTRAL_DIRECTORY_SIGNATURE {
                match central_directory_block(data, offset) {
                    Some(block) => {
                        offset = block.range.end;
                        blocks.push(block);
                    }
                    None => break,
                }
            } else {
                break;
            }
        }

        if let Some(signature) = read_u32(data, offset as usize) {
            if signature == EOCD_SIGNATURE {
                if let Some(block) = eocd_block(data, offset) {
                    blocks.push(block);
                }
            }
        }

        blocks
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

fn compression_name(value: u16) -> String {
    match value {
        0 => "Stored".to_string(),
        8 => "Deflated".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn read_name(data: &[u8], offset: usize, len: usize) -> String {
    data.get(offset..offset + len)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default()
}

fn local_file_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 30 {
        return None;
    }

    let version_needed = read_u16(data, off + 4)?;
    let flags = read_u16(data, off + 6)?;
    let compression_method = read_u16(data, off + 8)?;
    let last_mod_time = read_u16(data, off + 10)?;
    let last_mod_date = read_u16(data, off + 12)?;
    let crc32 = read_u32(data, off + 14)?;
    let compressed_size = read_u32(data, off + 18)? as u64;
    let uncompressed_size = read_u32(data, off + 22)?;
    let name_len = read_u16(data, off + 26)? as usize;
    let extra_len = read_u16(data, off + 28)? as usize;

    let name_start = offset + 30;
    let name_end = name_start + name_len as u64;
    let extra_end = name_end + extra_len as u64;
    let data_start = extra_end;
    let data_len = data.len() as u64;
    let data_end = (data_start + compressed_size).min(data_len);

    if name_end > data_len || extra_end > data_len {
        return None;
    }

    let name = read_name(data, name_start as usize, name_len);

    let mut children = vec![
        Block::leaf("Signature: PK\\x03\\x04", ByteRange::new(offset, offset + 4)),
        Block::leaf(
            format!("Version needed: {version_needed}"),
            ByteRange::new(offset + 4, offset + 6),
        ),
        Block::leaf(
            format!("General purpose flags: {flags:#06x}"),
            ByteRange::new(offset + 6, offset + 8),
        ),
        Block::leaf(
            format!(
                "Compression method: {}",
                compression_name(compression_method)
            ),
            ByteRange::new(offset + 8, offset + 10),
        ),
        Block::leaf(
            format!("Last mod time: {last_mod_time}"),
            ByteRange::new(offset + 10, offset + 12),
        ),
        Block::leaf(
            format!("Last mod date: {last_mod_date}"),
            ByteRange::new(offset + 12, offset + 14),
        ),
        Block::leaf(
            format!("CRC-32: {crc32:#010x}"),
            ByteRange::new(offset + 14, offset + 18),
        ),
        Block::leaf(
            format!("Compressed size: {compressed_size}"),
            ByteRange::new(offset + 18, offset + 22),
        ),
        Block::leaf(
            format!("Uncompressed size: {uncompressed_size}"),
            ByteRange::new(offset + 22, offset + 26),
        ),
        Block::leaf(
            format!("File name length: {name_len}"),
            ByteRange::new(offset + 26, offset + 28),
        ),
        Block::leaf(
            format!("Extra field length: {extra_len}"),
            ByteRange::new(offset + 28, offset + 30),
        ),
        Block::leaf(
            format!("File name: {name}"),
            ByteRange::new(name_start, name_end),
        ),
    ];

    if extra_len > 0 {
        children.push(Block::leaf(
            "Extra field",
            ByteRange::new(name_end, extra_end),
        ));
    }

    if data_end > data_start {
        children.push(Block::leaf(
            "File data",
            ByteRange::new(data_start, data_end),
        ));
    }

    Some(Block::node(
        format!("Local file header: {name}"),
        ByteRange::new(offset, data_end),
        children,
    ))
}

fn central_directory_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 46 {
        return None;
    }

    let version_made_by = read_u16(data, off + 4)?;
    let version_needed = read_u16(data, off + 6)?;
    let flags = read_u16(data, off + 8)?;
    let compression_method = read_u16(data, off + 10)?;
    let last_mod_time = read_u16(data, off + 12)?;
    let last_mod_date = read_u16(data, off + 14)?;
    let crc32 = read_u32(data, off + 16)?;
    let compressed_size = read_u32(data, off + 20)?;
    let uncompressed_size = read_u32(data, off + 24)?;
    let name_len = read_u16(data, off + 28)? as usize;
    let extra_len = read_u16(data, off + 30)? as usize;
    let comment_len = read_u16(data, off + 32)? as usize;
    let disk_number_start = read_u16(data, off + 34)?;
    let internal_attrs = read_u16(data, off + 36)?;
    let external_attrs = read_u32(data, off + 38)?;
    let local_header_offset = read_u32(data, off + 42)?;

    let name_start = offset + 46;
    let name_end = name_start + name_len as u64;
    let extra_end = name_end + extra_len as u64;
    let comment_end = extra_end + comment_len as u64;
    let data_len = data.len() as u64;

    if comment_end > data_len {
        return None;
    }

    let name = read_name(data, name_start as usize, name_len);

    let mut children = vec![
        Block::leaf("Signature: PK\\x01\\x02", ByteRange::new(offset, offset + 4)),
        Block::leaf(
            format!("Version made by: {version_made_by}"),
            ByteRange::new(offset + 4, offset + 6),
        ),
        Block::leaf(
            format!("Version needed: {version_needed}"),
            ByteRange::new(offset + 6, offset + 8),
        ),
        Block::leaf(
            format!("General purpose flags: {flags:#06x}"),
            ByteRange::new(offset + 8, offset + 10),
        ),
        Block::leaf(
            format!(
                "Compression method: {}",
                compression_name(compression_method)
            ),
            ByteRange::new(offset + 10, offset + 12),
        ),
        Block::leaf(
            format!("Last mod time: {last_mod_time}"),
            ByteRange::new(offset + 12, offset + 14),
        ),
        Block::leaf(
            format!("Last mod date: {last_mod_date}"),
            ByteRange::new(offset + 14, offset + 16),
        ),
        Block::leaf(
            format!("CRC-32: {crc32:#010x}"),
            ByteRange::new(offset + 16, offset + 20),
        ),
        Block::leaf(
            format!("Compressed size: {compressed_size}"),
            ByteRange::new(offset + 20, offset + 24),
        ),
        Block::leaf(
            format!("Uncompressed size: {uncompressed_size}"),
            ByteRange::new(offset + 24, offset + 28),
        ),
        Block::leaf(
            format!("File name length: {name_len}"),
            ByteRange::new(offset + 28, offset + 30),
        ),
        Block::leaf(
            format!("Extra field length: {extra_len}"),
            ByteRange::new(offset + 30, offset + 32),
        ),
        Block::leaf(
            format!("File comment length: {comment_len}"),
            ByteRange::new(offset + 32, offset + 34),
        ),
        Block::leaf(
            format!("Disk number start: {disk_number_start}"),
            ByteRange::new(offset + 34, offset + 36),
        ),
        Block::leaf(
            format!("Internal attributes: {internal_attrs}"),
            ByteRange::new(offset + 36, offset + 38),
        ),
        Block::leaf(
            format!("External attributes: {external_attrs}"),
            ByteRange::new(offset + 38, offset + 42),
        ),
        Block::leaf(
            format!("Local header offset: {local_header_offset}"),
            ByteRange::new(offset + 42, offset + 46),
        ),
        Block::leaf(
            format!("File name: {name}"),
            ByteRange::new(name_start, name_end),
        ),
    ];

    if extra_len > 0 {
        children.push(Block::leaf(
            "Extra field",
            ByteRange::new(name_end, extra_end),
        ));
    }
    if comment_len > 0 {
        children.push(Block::leaf(
            "File comment",
            ByteRange::new(extra_end, comment_end),
        ));
    }

    Some(Block::node(
        format!("Central directory entry: {name}"),
        ByteRange::new(offset, comment_end),
        children,
    ))
}

fn eocd_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 22 {
        return None;
    }

    let disk_number = read_u16(data, off + 4)?;
    let cd_start_disk = read_u16(data, off + 6)?;
    let cd_records_this_disk = read_u16(data, off + 8)?;
    let cd_records_total = read_u16(data, off + 10)?;
    let cd_size = read_u32(data, off + 12)?;
    let cd_offset = read_u32(data, off + 16)?;
    let comment_len = read_u16(data, off + 20)? as usize;

    let comment_start = offset + 22;
    let comment_end = (comment_start + comment_len as u64).min(data.len() as u64);

    let mut children = vec![
        Block::leaf("Signature: PK\\x05\\x06", ByteRange::new(offset, offset + 4)),
        Block::leaf(
            format!("Disk number: {disk_number}"),
            ByteRange::new(offset + 4, offset + 6),
        ),
        Block::leaf(
            format!("Disk with central directory start: {cd_start_disk}"),
            ByteRange::new(offset + 6, offset + 8),
        ),
        Block::leaf(
            format!("Central directory records on this disk: {cd_records_this_disk}"),
            ByteRange::new(offset + 8, offset + 10),
        ),
        Block::leaf(
            format!("Total central directory records: {cd_records_total}"),
            ByteRange::new(offset + 10, offset + 12),
        ),
        Block::leaf(
            format!("Central directory size: {cd_size}"),
            ByteRange::new(offset + 12, offset + 16),
        ),
        Block::leaf(
            format!("Central directory offset: {cd_offset}"),
            ByteRange::new(offset + 16, offset + 20),
        ),
        Block::leaf(
            format!("Comment length: {comment_len}"),
            ByteRange::new(offset + 20, offset + 22),
        ),
    ];

    if comment_end > comment_start {
        children.push(Block::leaf(
            "Comment",
            ByteRange::new(comment_start, comment_end),
        ));
    }

    Some(
        Block::node(
            "End of central directory",
            ByteRange::new(offset, comment_end),
            children,
        )
        .expanded(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_zip(name: &str, file_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        let name_bytes = name.as_bytes();
        let local_header_offset = 0u32;

        // Local file header
        let local_start = data.len();
        push_bytes(&mut data, &LOCAL_FILE_SIGNATURE.to_le_bytes());
        push_bytes(&mut data, &20u16.to_le_bytes()); // version needed
        push_bytes(&mut data, &0u16.to_le_bytes()); // flags
        push_bytes(&mut data, &0u16.to_le_bytes()); // compression: stored
        push_bytes(&mut data, &0u16.to_le_bytes()); // mod time
        push_bytes(&mut data, &0u16.to_le_bytes()); // mod date
        push_bytes(&mut data, &0u32.to_le_bytes()); // crc32 (fake)
        push_bytes(&mut data, &(file_data.len() as u32).to_le_bytes()); // compressed size
        push_bytes(&mut data, &(file_data.len() as u32).to_le_bytes()); // uncompressed size
        push_bytes(&mut data, &(name_bytes.len() as u16).to_le_bytes());
        push_bytes(&mut data, &0u16.to_le_bytes()); // extra length
        push_bytes(&mut data, name_bytes);
        push_bytes(&mut data, file_data);
        let _ = local_start;

        // Central directory entry
        let cd_start = data.len();
        push_bytes(&mut data, &CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes());
        push_bytes(&mut data, &20u16.to_le_bytes()); // version made by
        push_bytes(&mut data, &20u16.to_le_bytes()); // version needed
        push_bytes(&mut data, &0u16.to_le_bytes()); // flags
        push_bytes(&mut data, &0u16.to_le_bytes()); // compression: stored
        push_bytes(&mut data, &0u16.to_le_bytes()); // mod time
        push_bytes(&mut data, &0u16.to_le_bytes()); // mod date
        push_bytes(&mut data, &0u32.to_le_bytes()); // crc32 (fake)
        push_bytes(&mut data, &(file_data.len() as u32).to_le_bytes()); // compressed size
        push_bytes(&mut data, &(file_data.len() as u32).to_le_bytes()); // uncompressed size
        push_bytes(&mut data, &(name_bytes.len() as u16).to_le_bytes());
        push_bytes(&mut data, &0u16.to_le_bytes()); // extra length
        push_bytes(&mut data, &0u16.to_le_bytes()); // comment length
        push_bytes(&mut data, &0u16.to_le_bytes()); // disk number start
        push_bytes(&mut data, &0u16.to_le_bytes()); // internal attrs
        push_bytes(&mut data, &0u32.to_le_bytes()); // external attrs
        push_bytes(&mut data, &local_header_offset.to_le_bytes());
        push_bytes(&mut data, name_bytes);
        let cd_size = (data.len() - cd_start) as u32;

        // EOCD
        push_bytes(&mut data, &EOCD_SIGNATURE.to_le_bytes());
        push_bytes(&mut data, &0u16.to_le_bytes()); // disk number
        push_bytes(&mut data, &0u16.to_le_bytes()); // cd start disk
        push_bytes(&mut data, &1u16.to_le_bytes()); // cd records this disk
        push_bytes(&mut data, &1u16.to_le_bytes()); // cd records total
        push_bytes(&mut data, &cd_size.to_le_bytes());
        push_bytes(&mut data, &(cd_start as u32).to_le_bytes());
        push_bytes(&mut data, &0u16.to_le_bytes()); // comment length

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
    fn matches_zip_magic() {
        let data = build_zip("hello.txt", b"hello world");
        assert!(ZipDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_zip_data() {
        assert!(!ZipDissector.matches(b"not a zip file"));
        assert!(!ZipDissector.matches(b""));
        assert!(!ZipDissector.matches(b"PK\x05\x06"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = ZipDissector.dissect(b"PK\x03\x04");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_local_file_and_central_directory_and_eocd() {
        let data = build_zip("hello.txt", b"hello world");
        let blocks = ZipDissector.dissect(&data);

        let local = find_block(&blocks, "Local file header: hello.txt");
        assert!(
            local
                .children
                .iter()
                .any(|b| b.label == "File name: hello.txt")
        );
        assert!(
            local
                .children
                .iter()
                .any(|b| b.label == "Compression method: Stored")
        );
        assert!(local.children.iter().any(|b| b.label == "File data"));

        let cd = find_block(&blocks, "Central directory entry: hello.txt");
        assert!(
            cd.children
                .iter()
                .any(|b| b.label == "File name: hello.txt")
        );

        let eocd = find_block(&blocks, "End of central directory");
        assert!(
            eocd.children
                .iter()
                .any(|b| b.label == "Total central directory records: 1")
        );
    }

    #[test]
    fn identify_reports_zip() {
        let data = build_zip("a.txt", b"data");
        assert_eq!(super::super::identify(&data), "ZIP");
    }
}
