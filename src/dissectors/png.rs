use super::{Block, ByteRange, Dissector};

const PNG_SIGNATURE: &[u8] = &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

pub struct PngDissector;

impl Dissector for PngDissector {
    fn name(&self) -> &'static str {
        "PNG"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(PNG_SIGNATURE)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < PNG_SIGNATURE.len() {
            return blocks;
        }
        blocks.push(Block::leaf(
            "Signature",
            ByteRange::new(0, PNG_SIGNATURE.len() as u64),
        ));

        let mut offset = PNG_SIGNATURE.len() as u64;
        while let Some(chunk) = chunk_block(data, offset) {
            offset = chunk.range.end;
            blocks.push(chunk);
        }

        blocks
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn color_type_name(value: u8) -> &'static str {
    match value {
        0 => "grayscale",
        2 => "truecolor",
        3 => "indexed",
        4 => "grayscale + alpha",
        6 => "truecolor + alpha",
        _ => "unknown",
    }
}

fn ihdr_fields(data: &[u8], offset: u64) -> Vec<Block> {
    let off = offset as usize;
    let mut fields = Vec::new();

    if let Some(width) = read_u32(data, off) {
        fields.push(Block::leaf(
            format!("Width: {width}"),
            ByteRange::new(offset, offset + 4),
        ));
    }
    if let Some(height) = read_u32(data, off + 4) {
        fields.push(Block::leaf(
            format!("Height: {height}"),
            ByteRange::new(offset + 4, offset + 8),
        ));
    }
    if let Some(&bit_depth) = data.get(off + 8) {
        fields.push(Block::leaf(
            format!("Bit depth: {bit_depth}"),
            ByteRange::new(offset + 8, offset + 9),
        ));
    }
    if let Some(&color_type) = data.get(off + 9) {
        fields.push(Block::leaf(
            format!("Color type: {}", color_type_name(color_type)),
            ByteRange::new(offset + 9, offset + 10),
        ));
    }
    if let Some(&compression) = data.get(off + 10) {
        fields.push(Block::leaf(
            format!("Compression method: {compression}"),
            ByteRange::new(offset + 10, offset + 11),
        ));
    }
    if let Some(&filter) = data.get(off + 11) {
        fields.push(Block::leaf(
            format!("Filter method: {filter}"),
            ByteRange::new(offset + 11, offset + 12),
        ));
    }
    if let Some(&interlace) = data.get(off + 12) {
        fields.push(Block::leaf(
            format!("Interlace method: {interlace}"),
            ByteRange::new(offset + 12, offset + 13),
        ));
    }

    fields
}

fn chunk_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 8 {
        return None;
    }

    let length = read_u32(data, off)? as u64;
    let type_bytes = &data[off + 4..off + 8];
    let chunk_type = String::from_utf8_lossy(type_bytes).into_owned();

    let data_start = offset + 8;
    let available = data.len() as u64 - data_start.min(data.len() as u64);
    let data_end = data_start + length.min(available);
    let crc_end = (data_end + 4).min(data.len() as u64);

    let mut children = vec![
        Block::leaf(
            format!("Length: {length}"),
            ByteRange::new(offset, offset + 4),
        ),
        Block::leaf(
            format!("Type: {chunk_type}"),
            ByteRange::new(offset + 4, offset + 8),
        ),
    ];

    if chunk_type == "IHDR" {
        children.extend(ihdr_fields(data, data_start));
    } else if data_end > data_start {
        children.push(Block::leaf(
            "Data",
            ByteRange::new(data_start, data_end),
        ));
    }

    if crc_end > data_end {
        children.push(Block::leaf("CRC", ByteRange::new(data_end, crc_end)));
    }

    Some(
        Block::node(
            format!("Chunk: {chunk_type}"),
            ByteRange::new(offset, crc_end),
            children,
        )
        .expanded_if(matches!(chunk_type.as_str(), "IHDR" | "IEND")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn push_chunk(buf: &mut Vec<u8>, chunk_type: &[u8; 4], chunk_data: &[u8]) {
        push_bytes(buf, &(chunk_data.len() as u32).to_be_bytes());
        push_bytes(buf, chunk_type);
        push_bytes(buf, chunk_data);
        push_bytes(buf, &[0, 0, 0, 0]); // fake CRC
    }

    fn build_png() -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, PNG_SIGNATURE);

        let mut ihdr = Vec::new();
        push_bytes(&mut ihdr, &100u32.to_be_bytes()); // width
        push_bytes(&mut ihdr, &50u32.to_be_bytes()); // height
        ihdr.push(8); // bit depth
        ihdr.push(2); // color type: truecolor
        ihdr.push(0); // compression
        ihdr.push(0); // filter
        ihdr.push(0); // interlace
        push_chunk(&mut data, b"IHDR", &ihdr);

        push_chunk(&mut data, b"IDAT", &[1, 2, 3, 4]);
        push_chunk(&mut data, b"IEND", &[]);

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
    fn matches_png_signature() {
        let data = build_png();
        assert!(PngDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_png_data() {
        assert!(!PngDissector.matches(b"not a png file"));
        assert!(!PngDissector.matches(b""));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = PngDissector.dissect(&PNG_SIGNATURE[..4]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_ihdr_idat_iend_chunks() {
        let data = build_png();
        let blocks = PngDissector.dissect(&data);

        let sig = find_block(&blocks, "Signature");
        assert_eq!(sig.range, ByteRange::new(0, 8));

        let ihdr = find_block(&blocks, "Chunk: IHDR");
        assert!(ihdr.children.iter().any(|b| b.label == "Width: 100"));
        assert!(ihdr.children.iter().any(|b| b.label == "Height: 50"));
        assert!(
            ihdr.children
                .iter()
                .any(|b| b.label == "Color type: truecolor")
        );

        let idat = find_block(&blocks, "Chunk: IDAT");
        assert!(idat.children.iter().any(|b| b.label == "Data"));

        let iend = find_block(&blocks, "Chunk: IEND");
        assert!(!iend.children.iter().any(|b| b.label == "Data"));
    }

    #[test]
    fn identify_reports_png() {
        let data = build_png();
        assert_eq!(super::super::identify(&data), "PNG");
    }
}
