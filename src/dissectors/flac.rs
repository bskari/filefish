use super::{Block, ByteRange, Dissector};

const FLAC_MAGIC: &[u8] = b"fLaC";

pub struct FlacDissector;

impl Dissector for FlacDissector {
    fn name(&self) -> &'static str {
        "FLAC"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(FLAC_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 4 {
            return blocks;
        }
        blocks.push(Block::leaf("Marker: fLaC", ByteRange::new(0, 4)));

        let mut offset = 4u64;
        loop {
            match metadata_block(data, offset) {
                Some((block, is_last, end)) => {
                    blocks.push(block);
                    offset = end;
                    if is_last {
                        break;
                    }
                }
                None => {
                    // Truncated/malformed metadata block header; stop parsing here.
                    return blocks;
                }
            }
        }

        if offset < data.len() as u64 {
            blocks.push(Block::leaf(
                "Audio frames",
                ByteRange::new(offset, data.len() as u64),
            ));
        }

        blocks
    }
}

fn block_type_name(block_type: u8) -> &'static str {
    match block_type {
        0 => "STREAMINFO",
        1 => "PADDING",
        2 => "APPLICATION",
        3 => "SEEKTABLE",
        4 => "VORBIS_COMMENT",
        5 => "CUESHEET",
        6 => "PICTURE",
        127 => "INVALID",
        _ => "RESERVED",
    }
}

/// Parses a single METADATA_BLOCK at `offset`. Returns the block, whether it
/// was marked "is-last", and the offset just past the block.
fn metadata_block(data: &[u8], offset: u64) -> Option<(Block, bool, u64)> {
    let off = offset as usize;
    let header = data.get(off..off + 4)?;

    let is_last = header[0] & 0x80 != 0;
    let block_type = header[0] & 0x7F;
    let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as u64;

    let data_start = offset + 4;
    let available = data.len() as u64 - data_start.min(data.len() as u64);
    let data_end = data_start + length.min(available);

    let type_name = block_type_name(block_type);
    let label = format!("Metadata block: {type_name}");

    let mut children = vec![
        Block::leaf(
            format!("Last-metadata-block flag: {is_last}"),
            ByteRange::new(offset, offset + 1),
        ),
        Block::leaf(
            format!("Block type: {type_name} ({block_type})"),
            ByteRange::new(offset, offset + 1),
        ),
        Block::leaf(
            format!("Length: {length}"),
            ByteRange::new(offset + 1, offset + 4),
        ),
    ];

    if block_type == 0 {
        children.extend(streaminfo_fields(data, data_start, data_end));
    } else if data_end > data_start {
        children.push(Block::leaf(
            format!("{type_name} data"),
            ByteRange::new(data_start, data_end),
        ));
    }

    let block = Block::node(label, ByteRange::new(offset, data_end), children).expanded_if(block_type == 0);

    Some((block, is_last, data_end))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u24(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 3)?;
    Some(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
}

fn streaminfo_fields(data: &[u8], start: u64, end: u64) -> Vec<Block> {
    let mut fields = Vec::new();
    let off = start as usize;

    if end < start + 34 {
        // Truncated STREAMINFO block; fall back to a single leaf covering
        // whatever bytes are present.
        if end > start {
            fields.push(Block::leaf("STREAMINFO data", ByteRange::new(start, end)));
        }
        return fields;
    }

    if let Some(min_block) = read_u16(data, off) {
        fields.push(Block::leaf(
            format!("Minimum block size: {min_block}"),
            ByteRange::new(start, start + 2),
        ));
    }
    if let Some(max_block) = read_u16(data, off + 2) {
        fields.push(Block::leaf(
            format!("Maximum block size: {max_block}"),
            ByteRange::new(start + 2, start + 4),
        ));
    }
    if let Some(min_frame) = read_u24(data, off + 4) {
        fields.push(Block::leaf(
            format!("Minimum frame size: {min_frame}"),
            ByteRange::new(start + 4, start + 7),
        ));
    }
    if let Some(max_frame) = read_u24(data, off + 7) {
        fields.push(Block::leaf(
            format!("Maximum frame size: {max_frame}"),
            ByteRange::new(start + 7, start + 10),
        ));
    }

    // 8 bytes at off+10..off+18: 20-bit sample rate, 3-bit channels-1,
    // 5-bit bits-per-sample-1, 36-bit total samples, packed big-endian.
    if let Some(packed) = data.get(off + 10..off + 18) {
        let b = packed;
        let sample_rate = ((b[0] as u32) << 12) | ((b[1] as u32) << 4) | ((b[2] as u32) >> 4);
        let channels = ((b[2] >> 1) & 0x07) + 1;
        let bits_per_sample = (((b[2] & 0x01) << 4) | (b[3] >> 4)) + 1;
        let total_samples = (((b[3] & 0x0F) as u64) << 32)
            | ((b[4] as u64) << 24)
            | ((b[5] as u64) << 16)
            | ((b[6] as u64) << 8)
            | (b[7] as u64);

        fields.push(Block::leaf(
            format!(
                "Sample rate: {sample_rate} Hz, Channels: {channels}, \
                 Bits per sample: {bits_per_sample}, Total samples: {total_samples}"
            ),
            ByteRange::new(start + 10, start + 18),
        ));
    }

    if end >= start + 34 {
        fields.push(Block::leaf(
            "MD5 signature",
            ByteRange::new(start + 18, start + 34),
        ));
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_streaminfo() -> Vec<u8> {
        let mut info = Vec::new();
        push_bytes(&mut info, &4096u16.to_be_bytes()); // min block size
        push_bytes(&mut info, &4096u16.to_be_bytes()); // max block size
        push_bytes(&mut info, &[0, 0, 16]); // min frame size (24-bit)
        push_bytes(&mut info, &[0, 0, 32]); // max frame size (24-bit)

        // sample rate = 44100, channels = 2, bits per sample = 16, total samples = 1000
        let sample_rate: u32 = 44100;
        let channels_minus1: u32 = 1;
        let bps_minus1: u32 = 15;
        let total_samples: u64 = 1000;

        let mut packed: u64 = 0;
        packed |= (sample_rate as u64) << 44;
        packed |= (channels_minus1 as u64) << 41;
        packed |= (bps_minus1 as u64) << 36;
        packed |= total_samples & 0xF_FFFF_FFFF;
        push_bytes(&mut info, &packed.to_be_bytes());

        push_bytes(&mut info, &[0xAB; 16]); // MD5
        info
    }

    fn build_flac() -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, b"fLaC");

        let streaminfo = build_streaminfo();
        assert_eq!(streaminfo.len(), 34);

        // header: is-last=1, type=0 (STREAMINFO), length=34
        let header: u32 = (1u32 << 31) | (0u32 << 24) | 34u32;
        push_bytes(&mut data, &header.to_be_bytes());
        push_bytes(&mut data, &streaminfo);

        // trailing "audio frames"
        push_bytes(&mut data, &[0xFF, 0xF8, 0x00, 0x00]);

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
    fn matches_flac_magic() {
        assert!(FlacDissector.matches(&build_flac()));
        assert!(!FlacDissector.matches(b"not flac"));
        assert!(!FlacDissector.matches(b""));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = FlacDissector.dissect(b"fLa");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_streaminfo_and_audio_frames() {
        let data = build_flac();
        let blocks = FlacDissector.dissect(&data);

        assert_eq!(blocks[0].label, "Marker: fLaC");

        let streaminfo = find_block(&blocks, "Metadata block: STREAMINFO");
        assert!(
            streaminfo
                .children
                .iter()
                .any(|b| b.label.contains("Sample rate: 44100 Hz"))
        );
        assert!(
            streaminfo
                .children
                .iter()
                .any(|b| b.label.contains("Channels: 2"))
        );
        assert!(
            streaminfo
                .children
                .iter()
                .any(|b| b.label.contains("Bits per sample: 16"))
        );
        assert!(
            streaminfo
                .children
                .iter()
                .any(|b| b.label.contains("Total samples: 1000"))
        );
        assert!(
            streaminfo
                .children
                .iter()
                .any(|b| b.label == "MD5 signature")
        );

        let audio = find_block(&blocks, "Audio frames");
        assert_eq!(audio.range, ByteRange::new(4 + 4 + 34, data.len() as u64));
    }

    #[test]
    fn dissect_handles_truncated_metadata_gracefully() {
        let mut data = build_flac();
        data.truncate(4 + 4 + 10); // cut off mid-STREAMINFO, no audio frames
        let blocks = FlacDissector.dissect(&data);
        // Should not panic, and should still surface the marker + block.
        assert_eq!(blocks[0].label, "Marker: fLaC");
        find_block(&blocks, "Metadata block: STREAMINFO");
    }

    #[test]
    fn identify_reports_flac() {
        assert_eq!(super::super::identify(&build_flac()), "FLAC");
    }
}
