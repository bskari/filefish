use super::{Block, ByteRange, Dissector};

const RIFF_MAGIC: &[u8] = b"RIFF";
const WEBP_MAGIC: &[u8] = b"WEBP";

pub struct WebpDissector;

impl Dissector for WebpDissector {
    fn name(&self) -> &'static str {
        "WebP"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= 12 && data.starts_with(RIFF_MAGIC) && &data[8..12] == WEBP_MAGIC
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 12 {
            return blocks;
        }
        blocks.push(riff_header_block(data));

        let mut offset = 12u64;
        while let Some(chunk) = chunk_block(data, offset) {
            offset = chunk.range.end;
            blocks.push(chunk);
        }

        blocks
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u24_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 3)?;
    Some(bytes[0] as u32 | (bytes[1] as u32) << 8 | (bytes[2] as u32) << 16)
}

fn riff_header_block(data: &[u8]) -> Block {
    let chunk_size = read_u32(data, 4).unwrap_or(0);
    Block::node(
        "RIFF header",
        ByteRange::new(0, 12),
        vec![
            Block::leaf("Chunk ID: RIFF", ByteRange::new(0, 4)),
            Block::leaf(format!("Chunk size: {chunk_size}"), ByteRange::new(4, 8)),
            Block::leaf("Format: WEBP", ByteRange::new(8, 12)),
        ],
    )
    .expanded()
}

fn vp8x_chunk_block(data: &[u8], offset: u64, size: u64) -> Block {
    let off = offset as usize;
    let mut fields = Vec::new();

    if let Some(&flags) = data.get(off) {
        let mut set = Vec::new();
        if flags & 0x20 != 0 {
            set.push("ICC profile");
        }
        if flags & 0x10 != 0 {
            set.push("alpha");
        }
        if flags & 0x08 != 0 {
            set.push("EXIF");
        }
        if flags & 0x04 != 0 {
            set.push("XMP");
        }
        if flags & 0x02 != 0 {
            set.push("animation");
        }
        let label = if set.is_empty() {
            "Feature flags: none".to_string()
        } else {
            format!("Feature flags: {}", set.join(", "))
        };
        fields.push(Block::leaf(label, ByteRange::new(offset, offset + 1)));
    }

    if let Some(width_minus_one) = read_u24_le(data, off + 4) {
        fields.push(Block::leaf(
            format!("Canvas width: {}", width_minus_one + 1),
            ByteRange::new(offset + 4, offset + 7),
        ));
    }
    if let Some(height_minus_one) = read_u24_le(data, off + 7) {
        fields.push(Block::leaf(
            format!("Canvas height: {}", height_minus_one + 1),
            ByteRange::new(offset + 7, offset + 10),
        ));
    }

    Block::node("VP8X", ByteRange::new(offset, offset + size), fields).expanded()
}

fn chunk_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 8 {
        return None;
    }

    let id_bytes = &data[off..off + 4];
    let id = String::from_utf8_lossy(id_bytes).into_owned();
    let size = read_u32(data, off + 4)? as u64;

    let data_start = offset + 8;
    let available = data.len() as u64 - data_start;
    let data_end = data_start + size.min(available);
    // RIFF chunks are word-aligned: an odd-sized chunk is followed by a pad byte.
    let padded_end = (data_end + size % 2).min(data.len() as u64);

    let header = vec![
        Block::leaf(
            format!("Chunk ID: {id}"),
            ByteRange::new(offset, offset + 4),
        ),
        Block::leaf(
            format!("Chunk size: {size}"),
            ByteRange::new(offset + 4, offset + 8),
        ),
    ];

    if id == "VP8X" {
        let mut vp8x = vp8x_chunk_block(data, data_start, size);
        let mut children = header;
        children.append(&mut vp8x.children);
        return Some(
            Block::node(
                format!("Chunk: {id}"),
                ByteRange::new(offset, padded_end),
                children,
            )
            .expanded(),
        );
    }

    let mut children = header;
    if data_end > data_start {
        let label = match id.as_str() {
            "VP8 " => "VP8 bitstream data".to_string(),
            "VP8L" => "VP8L bitstream data".to_string(),
            "ICCP" => "ICC profile data".to_string(),
            "EXIF" => "EXIF data".to_string(),
            "XMP " => "XMP data".to_string(),
            _ => format!("Data ({id})"),
        };
        children.push(Block::leaf(label, ByteRange::new(data_start, data_end)));
    }

    Some(Block::node(
        format!("Chunk: {}", id.trim_end()),
        ByteRange::new(offset, padded_end),
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_webp(vp8x_flags: u8, width: u32, height: u32, vp8_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();

        let vp8x_size: u32 = 10;
        let vp8_size = vp8_data.len() as u32;
        let riff_size = 4 + (8 + vp8x_size) + (8 + vp8_size);

        push_bytes(&mut data, b"RIFF");
        push_bytes(&mut data, &riff_size.to_le_bytes());
        push_bytes(&mut data, b"WEBP");

        push_bytes(&mut data, b"VP8X");
        push_bytes(&mut data, &vp8x_size.to_le_bytes());
        push_bytes(&mut data, &[vp8x_flags]);
        push_bytes(&mut data, &[0u8; 3]); // reserved
        let width_minus_one = width - 1;
        let height_minus_one = height - 1;
        push_bytes(&mut data, &width_minus_one.to_le_bytes()[0..3]);
        push_bytes(&mut data, &height_minus_one.to_le_bytes()[0..3]);

        push_bytes(&mut data, b"VP8 ");
        push_bytes(&mut data, &vp8_size.to_le_bytes());
        push_bytes(&mut data, vp8_data);

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
    fn matches_webp_magic() {
        let data = build_webp(0x10, 100, 200, &[1, 2, 3, 4]);
        assert!(WebpDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_webp_data() {
        assert!(!WebpDissector.matches(b"not a webp file"));
        assert!(!WebpDissector.matches(b""));
        assert!(!WebpDissector.matches(b"RIFF1234AVI "));

        // WAV is also RIFF-based; make sure it's correctly rejected.
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        assert!(!WebpDissector.matches(&wav));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = WebpDissector.dissect(b"RIFF");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_vp8x_and_bitstream_chunks() {
        let data = build_webp(0x10 | 0x08, 320, 240, &[9, 9, 9, 9]);
        let blocks = WebpDissector.dissect(&data);

        let riff = find_block(&blocks, "RIFF header");
        assert_eq!(riff.children[0].label, "Chunk ID: RIFF");
        assert_eq!(riff.children[2].label, "Format: WEBP");

        let vp8x = find_block(&blocks, "Chunk: VP8X");
        assert!(
            vp8x.children
                .iter()
                .any(|b| b.label.contains("alpha") && b.label.contains("EXIF"))
        );
        assert!(
            vp8x.children
                .iter()
                .any(|b| b.label == "Canvas width: 320")
        );
        assert!(
            vp8x.children
                .iter()
                .any(|b| b.label == "Canvas height: 240")
        );

        let vp8 = find_block(&blocks, "Chunk: VP8");
        assert!(
            vp8.children
                .iter()
                .any(|b| b.label == "VP8 bitstream data")
        );
    }

    #[test]
    fn dissect_handles_odd_sized_chunk_padding() {
        let mut data = build_webp(0, 10, 10, &[1, 2, 3]);
        data.push(0); // RIFF pad byte for the odd-sized VP8 chunk

        let blocks = WebpDissector.dissect(&data);
        let vp8 = find_block(&blocks, "Chunk: VP8");
        // VP8 chunk starts at 30 (12 RIFF header + 18 VP8X chunk), header 8 bytes + 3 bytes data + 1 pad byte = 12
        assert_eq!(vp8.range, ByteRange::new(30, 42));
    }

    #[test]
    fn identify_reports_webp() {
        let data = build_webp(0, 1, 1, &[0u8; 4]);
        assert_eq!(super::super::identify(&data), "WebP");
    }
}
