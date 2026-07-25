use super::{Block, ByteRange, Dissector};

const OGG_MAGIC: &[u8] = b"OggS";
const PAGE_HEADER_LEN: usize = 27;

pub struct OggDissector;

impl Dissector for OggDissector {
    fn name(&self) -> &'static str {
        "OGG"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= 4 && data.starts_with(OGG_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut offset = 0u64;
        let mut index = 0usize;

        while let Some(page) = page_block(data, offset, index) {
            offset = page.range.end;
            blocks.push(page);
            index += 1;
        }

        blocks
    }
}

fn read_i64(data: &[u8], offset: usize) -> Option<i64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(i64::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn header_type_description(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("continued packet");
    }
    if flags & 0x02 != 0 {
        parts.push("first page (bos)");
    }
    if flags & 0x04 != 0 {
        parts.push("last page (eos)");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn codec_label(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 7 && &data[0..7] == b"\x01vorbis" {
        Some("Vorbis identification header")
    } else if data.len() >= 8 && &data[0..8] == b"OpusHead" {
        Some("Opus header")
    } else {
        None
    }
}

fn page_block(data: &[u8], offset: u64, index: usize) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + PAGE_HEADER_LEN {
        return None;
    }
    if &data[off..off + 4] != OGG_MAGIC {
        return None;
    }

    let stream_structure_version = data[off + 4];
    let header_type_flag = data[off + 5];
    let granule_position = read_i64(data, off + 6)?;
    let bitstream_serial_number = read_u32(data, off + 14)?;
    let page_sequence_number = read_u32(data, off + 18)?;
    let page_segments = data[off + 26] as usize;

    let segment_table_start = off + PAGE_HEADER_LEN;
    if data.len() < segment_table_start + page_segments {
        return None;
    }
    let segment_table = &data[segment_table_start..segment_table_start + page_segments];
    let payload_len: u64 = segment_table.iter().map(|&b| b as u64).sum();

    let payload_start = (segment_table_start + page_segments) as u64;
    let available = data.len() as u64 - payload_start.min(data.len() as u64);
    let payload_len = payload_len.min(available);
    let payload_end = payload_start + payload_len;

    let mut children = vec![
        Block::leaf(
            "Capture pattern: OggS",
            ByteRange::new(offset, offset + 4),
        ),
        Block::leaf(
            format!("Stream structure version: {stream_structure_version}"),
            ByteRange::new(offset + 4, offset + 5),
        ),
        Block::leaf(
            format!(
                "Header type flag: 0x{header_type_flag:02x} ({})",
                header_type_description(header_type_flag)
            ),
            ByteRange::new(offset + 5, offset + 6),
        ),
        Block::leaf(
            format!("Granule position: {granule_position}"),
            ByteRange::new(offset + 6, offset + 14),
        ),
        Block::leaf(
            format!("Bitstream serial number: {bitstream_serial_number}"),
            ByteRange::new(offset + 14, offset + 18),
        ),
        Block::leaf(
            format!("Page sequence number: {page_sequence_number}"),
            ByteRange::new(offset + 18, offset + 22),
        ),
        Block::leaf("CRC checksum", ByteRange::new(offset + 22, offset + 26)),
        Block::leaf(
            format!("Page segments: {page_segments}"),
            ByteRange::new(offset + 26, offset + 27),
        ),
    ];

    children.push(Block::leaf(
        "Segment table",
        ByteRange::new(
            segment_table_start as u64,
            (segment_table_start + page_segments) as u64,
        ),
    ));

    if payload_end > payload_start {
        let payload = &data[payload_start as usize..payload_end as usize];
        let label = match codec_label(payload) {
            Some(codec) => format!("Payload data ({codec})"),
            None => "Payload data".to_string(),
        };
        children.push(Block::leaf(label, ByteRange::new(payload_start, payload_end)));
    }

    Some(
        Block::node(
            format!("Page {index}"),
            ByteRange::new(offset, payload_end),
            children,
        )
        .expanded_if(index == 0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_ogg_page(header_type_flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, b"OggS");
        data.push(0); // stream structure version
        data.push(header_type_flag);
        push_bytes(&mut data, &0i64.to_le_bytes()); // granule position
        push_bytes(&mut data, &1u32.to_le_bytes()); // bitstream serial number
        push_bytes(&mut data, &0u32.to_le_bytes()); // page sequence number
        push_bytes(&mut data, &0u32.to_le_bytes()); // CRC checksum (fake)

        let mut remaining = payload.len();
        let mut segment_table = Vec::new();
        loop {
            if remaining >= 255 {
                segment_table.push(255u8);
                remaining -= 255;
            } else {
                segment_table.push(remaining as u8);
                break;
            }
        }
        data.push(segment_table.len() as u8);
        push_bytes(&mut data, &segment_table);
        push_bytes(&mut data, payload);

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
    fn matches_ogg_magic() {
        let data = build_ogg_page(0x02, b"\x01vorbishello");
        assert!(OggDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_ogg_data() {
        assert!(!OggDissector.matches(b"not an ogg file"));
        assert!(!OggDissector.matches(b""));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = OggDissector.dissect(b"OggS");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_single_page_with_vorbis_header() {
        let payload = b"\x01vorbis_extra_data_here";
        let data = build_ogg_page(0x02, payload);
        let blocks = OggDissector.dissect(&data);

        assert_eq!(blocks.len(), 1);
        let page = find_block(&blocks, "Page 0");
        assert!(
            page.children
                .iter()
                .any(|b| b.label == "Capture pattern: OggS")
        );
        assert!(
            page.children
                .iter()
                .any(|b| b.label.contains("first page (bos)"))
        );
        let payload_block = page
            .children
            .iter()
            .find(|b| b.label.contains("Payload data"))
            .unwrap();
        assert!(payload_block.label.contains("Vorbis identification header"));
        assert_eq!(
            payload_block.range,
            ByteRange::new(page.range.end - payload.len() as u64, page.range.end)
        );
    }

    #[test]
    fn dissect_handles_multiple_pages() {
        let mut data = build_ogg_page(0x02, b"OpusHeadxxxx");
        data.extend(build_ogg_page(0x00, b"more audio data"));
        let blocks = OggDissector.dissect(&data);

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "Page 0");
        assert_eq!(blocks[1].label, "Page 1");
        assert_eq!(blocks[1].range.start, blocks[0].range.end);
    }

    #[test]
    fn identify_reports_ogg() {
        let data = build_ogg_page(0x02, b"\x01vorbis");
        assert_eq!(super::super::identify(&data), "OGG");
    }
}
