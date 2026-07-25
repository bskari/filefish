use super::{Block, ByteRange, Dissector};

const RIFF_MAGIC: &[u8] = b"RIFF";
const WAVE_MAGIC: &[u8] = b"WAVE";

pub struct WavDissector;

impl Dissector for WavDissector {
    fn name(&self) -> &'static str {
        "WAV"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= 12 && data.starts_with(RIFF_MAGIC) && &data[8..12] == WAVE_MAGIC
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

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn audio_format_name(value: u16) -> &'static str {
    match value {
        1 => "PCM",
        2 => "ADPCM",
        3 => "IEEE float",
        6 => "A-law",
        7 => "mu-law",
        17 => "IMA ADPCM",
        0xFFFE => "extensible",
        _ => "unknown",
    }
}

fn riff_header_block(data: &[u8]) -> Block {
    let chunk_size = read_u32(data, 4).unwrap_or(0);
    Block::node(
        "RIFF header",
        ByteRange::new(0, 12),
        vec![
            Block::leaf("Chunk ID: RIFF", ByteRange::new(0, 4)),
            Block::leaf(format!("Chunk size: {chunk_size}"), ByteRange::new(4, 8)),
            Block::leaf("Format: WAVE", ByteRange::new(8, 12)),
        ],
    )
    .expanded()
}

fn fmt_chunk_block(data: &[u8], offset: u64, size: u64) -> Block {
    let off = offset as usize;
    let mut fields = Vec::new();

    if let Some(audio_format) = read_u16(data, off) {
        fields.push(Block::leaf(
            format!("Audio format: {}", audio_format_name(audio_format)),
            ByteRange::new(offset, offset + 2),
        ));
    }
    if let Some(channels) = read_u16(data, off + 2) {
        fields.push(Block::leaf(
            format!("Channels: {channels}"),
            ByteRange::new(offset + 2, offset + 4),
        ));
    }
    if let Some(sample_rate) = read_u32(data, off + 4) {
        fields.push(Block::leaf(
            format!("Sample rate: {sample_rate}"),
            ByteRange::new(offset + 4, offset + 8),
        ));
    }
    if let Some(byte_rate) = read_u32(data, off + 8) {
        fields.push(Block::leaf(
            format!("Byte rate: {byte_rate}"),
            ByteRange::new(offset + 8, offset + 12),
        ));
    }
    if let Some(block_align) = read_u16(data, off + 12) {
        fields.push(Block::leaf(
            format!("Block align: {block_align}"),
            ByteRange::new(offset + 12, offset + 14),
        ));
    }
    if let Some(bits_per_sample) = read_u16(data, off + 14) {
        fields.push(Block::leaf(
            format!("Bits per sample: {bits_per_sample}"),
            ByteRange::new(offset + 14, offset + 16),
        ));
    }

    Block::node("fmt chunk", ByteRange::new(offset, offset + size), fields)
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

    if id == "fmt " {
        let mut fmt = fmt_chunk_block(data, data_start, size);
        let mut children = header;
        children.append(&mut fmt.children);
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
        let label = if id == "data" {
            "Data".to_string()
        } else {
            format!("Data ({id})")
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

    fn build_wav(pcm_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        let fmt_size: u32 = 16;
        let data_size = pcm_data.len() as u32;
        let riff_size = 4 + (8 + fmt_size) + (8 + data_size);

        push_bytes(&mut data, b"RIFF");
        push_bytes(&mut data, &riff_size.to_le_bytes());
        push_bytes(&mut data, b"WAVE");

        push_bytes(&mut data, b"fmt ");
        push_bytes(&mut data, &fmt_size.to_le_bytes());
        push_bytes(&mut data, &1u16.to_le_bytes()); // PCM
        push_bytes(&mut data, &2u16.to_le_bytes()); // channels
        push_bytes(&mut data, &44100u32.to_le_bytes()); // sample rate
        push_bytes(&mut data, &176400u32.to_le_bytes()); // byte rate
        push_bytes(&mut data, &4u16.to_le_bytes()); // block align
        push_bytes(&mut data, &16u16.to_le_bytes()); // bits per sample

        push_bytes(&mut data, b"data");
        push_bytes(&mut data, &data_size.to_le_bytes());
        push_bytes(&mut data, pcm_data);

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
    fn matches_wav_magic() {
        let data = build_wav(&[0u8; 8]);
        assert!(WavDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_wav_data() {
        assert!(!WavDissector.matches(b"not a wav file"));
        assert!(!WavDissector.matches(b""));
        assert!(!WavDissector.matches(b"RIFF1234AVI "));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = WavDissector.dissect(b"RIFF");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_fmt_and_data_chunks() {
        let data = build_wav(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let blocks = WavDissector.dissect(&data);

        let riff = find_block(&blocks, "RIFF header");
        assert_eq!(riff.children[0].label, "Chunk ID: RIFF");
        assert_eq!(riff.children[2].label, "Format: WAVE");

        let fmt = find_block(&blocks, "Chunk: fmt ");
        assert!(fmt.children.iter().any(|b| b.label == "Audio format: PCM"));
        assert!(fmt.children.iter().any(|b| b.label == "Channels: 2"));
        assert!(fmt.children.iter().any(|b| b.label == "Sample rate: 44100"));
        assert!(
            fmt.children
                .iter()
                .any(|b| b.label == "Bits per sample: 16")
        );

        let data_chunk = find_block(&blocks, "Chunk: data");
        assert!(data_chunk.children.iter().any(|b| b.label == "Data"));
        let data_block = data_chunk
            .children
            .iter()
            .find(|b| b.label == "Data")
            .unwrap();
        assert_eq!(data_block.range, ByteRange::new(44, 52));
    }

    #[test]
    fn dissect_handles_odd_sized_chunk_padding() {
        let mut data = build_wav(&[1, 2, 3]);
        data.push(0); // RIFF pad byte for the odd-sized data chunk
        let blocks = WavDissector.dissect(&data);

        let data_chunk = find_block(&blocks, "Chunk: data");
        // data chunk starts at 36, header 8 bytes + 3 bytes data + 1 pad byte = 12
        assert_eq!(data_chunk.range, ByteRange::new(36, 48));
    }

    #[test]
    fn identify_reports_wav() {
        let data = build_wav(&[0u8; 4]);
        assert_eq!(super::super::identify(&data), "WAV");
    }
}
