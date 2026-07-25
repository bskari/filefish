use super::{Block, ByteRange, Dissector};

const MAGIC: &[u8] = b"SQLite format 3\0";
const HEADER_SIZE: u64 = 100;

pub struct SqliteDissector;

impl Dissector for SqliteDissector {
    fn name(&self) -> &'static str {
        "SQLite"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.is_empty() {
            return blocks;
        }

        blocks.push(header_block(data));

        if data.len() as u64 > HEADER_SIZE {
            blocks.push(Block::leaf(
                "Database pages",
                ByteRange::new(HEADER_SIZE, data.len() as u64),
            ));
        }

        blocks
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn text_encoding_name(value: u32) -> &'static str {
    match value {
        1 => "UTF-8",
        2 => "UTF-16le",
        3 => "UTF-16be",
        _ => "unknown",
    }
}

fn page_size_display(value: u16) -> u32 {
    if value == 1 {
        65536
    } else {
        value as u32
    }
}

fn header_block(data: &[u8]) -> Block {
    let end = data.len().min(HEADER_SIZE as usize) as u64;
    let mut fields = Vec::new();

    fields.push(Block::leaf(
        "magic: SQLite format 3",
        ByteRange::new(0, data.len().min(16) as u64),
    ));

    if let Some(page_size) = read_u16(data, 16) {
        fields.push(Block::leaf(
            format!("page_size: {}", page_size_display(page_size)),
            ByteRange::new(16, 18),
        ));
    }

    if let Some(&b) = data.get(18) {
        fields.push(Block::leaf(
            format!("file_format_write_version: {b}"),
            ByteRange::new(18, 19),
        ));
    }
    if let Some(&b) = data.get(19) {
        fields.push(Block::leaf(
            format!("file_format_read_version: {b}"),
            ByteRange::new(19, 20),
        ));
    }
    if let Some(&b) = data.get(20) {
        fields.push(Block::leaf(
            format!("reserved_space: {b}"),
            ByteRange::new(20, 21),
        ));
    }
    if let Some(&b) = data.get(21) {
        fields.push(Block::leaf(
            format!("max_embedded_payload_fraction: {b}"),
            ByteRange::new(21, 22),
        ));
    }
    if let Some(&b) = data.get(22) {
        fields.push(Block::leaf(
            format!("min_embedded_payload_fraction: {b}"),
            ByteRange::new(22, 23),
        ));
    }
    if let Some(&b) = data.get(23) {
        fields.push(Block::leaf(
            format!("leaf_payload_fraction: {b}"),
            ByteRange::new(23, 24),
        ));
    }
    if let Some(v) = read_u32(data, 24) {
        fields.push(Block::leaf(
            format!("file_change_counter: {v}"),
            ByteRange::new(24, 28),
        ));
    }
    if let Some(v) = read_u32(data, 28) {
        fields.push(Block::leaf(
            format!("database_size_pages: {v}"),
            ByteRange::new(28, 32),
        ));
    }
    if let Some(v) = read_u32(data, 32) {
        fields.push(Block::leaf(
            format!("first_freelist_trunk_page: {v}"),
            ByteRange::new(32, 36),
        ));
    }
    if let Some(v) = read_u32(data, 36) {
        fields.push(Block::leaf(
            format!("total_freelist_pages: {v}"),
            ByteRange::new(36, 40),
        ));
    }
    if let Some(v) = read_u32(data, 40) {
        fields.push(Block::leaf(
            format!("schema_cookie: {v}"),
            ByteRange::new(40, 44),
        ));
    }
    if let Some(v) = read_u32(data, 44) {
        fields.push(Block::leaf(
            format!("schema_format_number: {v}"),
            ByteRange::new(44, 48),
        ));
    }
    if let Some(v) = read_u32(data, 48) {
        fields.push(Block::leaf(
            format!("default_page_cache_size: {v}"),
            ByteRange::new(48, 52),
        ));
    }
    if let Some(v) = read_u32(data, 52) {
        fields.push(Block::leaf(
            format!("largest_root_btree_page: {v}"),
            ByteRange::new(52, 56),
        ));
    }
    if let Some(v) = read_u32(data, 56) {
        fields.push(Block::leaf(
            format!("text_encoding: {} ({v})", text_encoding_name(v)),
            ByteRange::new(56, 60),
        ));
    }
    if let Some(v) = read_u32(data, 60) {
        fields.push(Block::leaf(
            format!("user_version: {v}"),
            ByteRange::new(60, 64),
        ));
    }
    if let Some(v) = read_u32(data, 64) {
        fields.push(Block::leaf(
            format!("incremental_vacuum_mode: {v}"),
            ByteRange::new(64, 68),
        ));
    }
    if let Some(v) = read_u32(data, 68) {
        fields.push(Block::leaf(
            format!("application_id: {v}"),
            ByteRange::new(68, 72),
        ));
    }
    if data.len() >= 92 {
        fields.push(Block::leaf(
            "reserved_for_expansion",
            ByteRange::new(72, 92),
        ));
    }
    if let Some(v) = read_u32(data, 92) {
        fields.push(Block::leaf(
            format!("version_valid_for: {v}"),
            ByteRange::new(92, 96),
        ));
    }
    if let Some(v) = read_u32(data, 96) {
        fields.push(Block::leaf(
            format!("sqlite_version_number: {v}"),
            ByteRange::new(96, 100),
        ));
    }

    Block::node("Database header", ByteRange::new(0, end), fields).expanded()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label == label)
            .unwrap_or_else(|| panic!("block {label:?} not found; have {:?}", blocks.iter().map(|b| &b.label).collect::<Vec<_>>()))
    }

    fn build_header() -> Vec<u8> {
        let mut data = vec![0u8; 120];
        data[0..16].copy_from_slice(MAGIC);
        data[16..18].copy_from_slice(&1024u16.to_be_bytes());
        data[18] = 1; // write version
        data[19] = 1; // read version
        data[20] = 0; // reserved space
        data[21] = 64; // max embedded payload fraction
        data[22] = 32; // min embedded payload fraction
        data[23] = 32; // leaf payload fraction
        data[24..28].copy_from_slice(&5u32.to_be_bytes()); // change counter
        data[28..32].copy_from_slice(&10u32.to_be_bytes()); // size in pages
        data[40..44].copy_from_slice(&7u32.to_be_bytes()); // schema cookie
        data[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding: utf8
        data[96..100].copy_from_slice(&3045000u32.to_be_bytes()); // version number
        data
    }

    #[test]
    fn matches_magic() {
        let data = build_header();
        assert!(SqliteDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_sqlite_data() {
        assert!(!SqliteDissector.matches(b"not a sqlite file"));
        assert!(!SqliteDissector.matches(b""));
    }

    #[test]
    fn dissect_empty_data_returns_empty() {
        let blocks = SqliteDissector.dissect(&[]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_header_fields() {
        let data = build_header();
        let blocks = SqliteDissector.dissect(&data);

        let header = find_block(&blocks, "Database header");
        assert!(header.children.iter().any(|b| b.label == "page_size: 1024"));
        assert!(header.children.iter().any(|b| b.label == "schema_cookie: 7"));
        assert!(header.children.iter().any(|b| b.label == "text_encoding: UTF-8 (1)"));
        assert!(header.children.iter().any(|b| b.label == "sqlite_version_number: 3045000"));

        let pages = find_block(&blocks, "Database pages");
        assert_eq!(pages.range, ByteRange::new(100, 120));
    }

    #[test]
    fn dissect_handles_page_size_one_as_65536() {
        let mut data = build_header();
        data[16..18].copy_from_slice(&1u16.to_be_bytes());
        let blocks = SqliteDissector.dissect(&data);
        let header = find_block(&blocks, "Database header");
        assert!(header.children.iter().any(|b| b.label == "page_size: 65536"));
    }

    #[test]
    fn dissect_handles_truncated_header() {
        let data = build_header();
        let truncated = &data[..30];
        let blocks = SqliteDissector.dissect(truncated);

        let header = find_block(&blocks, "Database header");
        assert_eq!(header.range, ByteRange::new(0, 30));
        assert!(header.children.iter().any(|b| b.label == "page_size: 1024"));
        assert!(!header.children.iter().any(|b| b.label.starts_with("schema_cookie")));
        assert!(blocks.iter().find(|b| b.label == "Database pages").is_none());
    }

    #[test]
    fn identify_reports_sqlite() {
        let data = build_header();
        assert_eq!(super::super::identify(&data), "SQLite");
    }
}
