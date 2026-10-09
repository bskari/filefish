use super::{Block, ByteRange, Dissector};

const FWS_MAGIC: &[u8] = b"FWS";
const CWS_MAGIC: &[u8] = b"CWS";
const ZWS_MAGIC: &[u8] = b"ZWS";

/// Size of the signature, version and file length fields shared by all forms.
const COMMON_HEADER_LEN: usize = 8;
/// ZWS adds a 4-byte compressed length and 5 bytes of LZMA properties.
const ZWS_HEADER_LEN: usize = 17;
/// Highest SWF version accepted by `matches`; real files stop in the 40s.
const MAX_VERSION: u8 = 64;

const TAG_END: u16 = 0;
const LONG_LENGTH_MARKER: u16 = 0x3F;

pub struct SwfDissector;

impl Dissector for SwfDissector {
    fn name(&self) -> &'static str {
        "SWF"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < COMMON_HEADER_LEN {
            return false;
        }
        let magic = &data[0..3];
        if magic != FWS_MAGIC && magic != CWS_MAGIC && magic != ZWS_MAGIC {
            return false;
        }
        // A three-letter magic is weak, so also require a plausible version.
        (1..=MAX_VERSION).contains(&data[3])
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < COMMON_HEADER_LEN {
            return blocks;
        }

        match &data[0..3] {
            m if m == FWS_MAGIC => dissect_uncompressed(data, &mut blocks),
            m if m == CWS_MAGIC => dissect_zlib(data, &mut blocks),
            m if m == ZWS_MAGIC => dissect_lzma(data, &mut blocks),
            _ => {}
        }
        blocks
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn common_fields(data: &[u8], compression: &str) -> Vec<Block> {
    let signature = String::from_utf8_lossy(&data[0..3]);
    let version = data[3];
    let file_length = read_u32(data, 4).unwrap_or(0);
    let length_label = if compression == "none" {
        format!("File length: {file_length}")
    } else {
        format!("File length (uncompressed): {file_length}")
    };
    vec![
        Block::leaf(
            format!("Signature: {signature} (compression: {compression})"),
            span(0, 3),
        ),
        Block::leaf(format!("Version: {version}"), span(3, 4)),
        Block::leaf(length_label, span(4, 8)),
    ]
}

fn dissect_zlib(data: &[u8], blocks: &mut Vec<Block>) {
    blocks.push(
        Block::node(
            "SWF header",
            span(0, COMMON_HEADER_LEN),
            common_fields(data, "zlib"),
        )
        .expanded(),
    );
    if data.len() > COMMON_HEADER_LEN {
        blocks.push(Block::leaf(
            "Compressed body (zlib)",
            span(COMMON_HEADER_LEN, data.len()),
        ));
    }
}

fn dissect_lzma(data: &[u8], blocks: &mut Vec<Block>) {
    let mut children = common_fields(data, "LZMA");
    let mut header_end = COMMON_HEADER_LEN;
    if let Some(compressed_len) = read_u32(data, 8) {
        children.push(Block::leaf(
            format!("Compressed length: {compressed_len}"),
            span(8, 12),
        ));
        header_end = 12;
    }
    if let Some(props) = data.get(12..ZWS_HEADER_LEN) {
        let dict_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
        children.push(Block::leaf(
            format!(
                "LZMA properties: 0x{:02X}, dictionary size {dict_size}",
                props[0]
            ),
            span(12, ZWS_HEADER_LEN),
        ));
        header_end = ZWS_HEADER_LEN;
    }
    blocks.push(Block::node("SWF header", span(0, header_end), children).expanded());
    if header_end == ZWS_HEADER_LEN && data.len() > ZWS_HEADER_LEN {
        blocks.push(Block::leaf(
            "Compressed body (LZMA)",
            span(ZWS_HEADER_LEN, data.len()),
        ));
    }
}

/// Reads `count` bits MSB-first starting at bit `bit` of `bytes`.
fn read_bits(bytes: &[u8], bit: usize, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for i in bit..bit + count {
        let byte = *bytes.get(i / 8)?;
        value = (value << 1) | u32::from((byte >> (7 - i % 8)) & 1);
    }
    Some(value)
}

fn sign_extend(value: u32, bits: usize) -> i32 {
    if bits == 0 {
        return 0;
    }
    let shift = 32 - bits as u32;
    ((value << shift) as i32) >> shift
}

/// Parses the bit-packed RECT at `offset`, returning the block and its end.
fn rect_block(data: &[u8], offset: usize) -> Option<(Block, usize)> {
    let bytes = data.get(offset..)?;
    let nbits = read_bits(bytes, 0, 5)? as usize;
    let total_bits = 5 + 4 * nbits;
    let end = offset + total_bits.div_ceil(8);
    if end > data.len() {
        return None;
    }

    // Each field spans the bytes holding any of its bits.
    let bit_span = |first: usize, len: usize| {
        let last = first + len.max(1) - 1;
        span(offset + first / 8, offset + last / 8 + 1)
    };

    let mut children = vec![Block::leaf(format!("Nbits: {nbits}"), bit_span(0, 5))];
    let mut values = [0i32; 4];
    for (i, name) in ["Xmin", "Xmax", "Ymin", "Ymax"].iter().enumerate() {
        let first = 5 + i * nbits;
        values[i] = sign_extend(read_bits(bytes, first, nbits)?, nbits);
        children.push(Block::leaf(
            format!("{name}: {} twips", values[i]),
            bit_span(first, nbits),
        ));
    }

    let width = f64::from(values[1] - values[0]) / 20.0;
    let height = f64::from(values[3] - values[2]) / 20.0;
    let block = Block::node(
        format!("Frame size: {width} x {height} px"),
        span(offset, end),
        children,
    );
    Some((block, end))
}

fn dissect_uncompressed(data: &[u8], blocks: &mut Vec<Block>) {
    let mut children = common_fields(data, "none");
    let mut header_end = COMMON_HEADER_LEN;
    let mut complete = false;

    if let Some((rect, rect_end)) = rect_block(data, COMMON_HEADER_LEN) {
        children.push(rect);
        header_end = rect_end;
        if let Some(rate) = read_u16(data, rect_end) {
            let fps = f64::from(rate) / 256.0;
            children.push(Block::leaf(
                format!("Frame rate: {fps} fps"),
                span(rect_end, rect_end + 2),
            ));
            header_end = rect_end + 2;
            if let Some(count) = read_u16(data, rect_end + 2) {
                children.push(Block::leaf(
                    format!("Frame count: {count}"),
                    span(rect_end + 2, rect_end + 4),
                ));
                header_end = rect_end + 4;
                complete = true;
            }
        }
    }

    blocks.push(Block::node("SWF header", span(0, header_end), children).expanded());
    if complete && header_end < data.len() {
        blocks.extend(tag_list(data, header_end));
    }
}

fn tag_list(data: &[u8], start: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut tags = Vec::new();
    let mut offset = start;

    while let Some(record) = read_u16(data, offset) {
        let code = record >> 6;
        let short_len = record & 0x3F;
        let name = tag_name(code);
        let mut children = Vec::new();

        let (length, data_start) = if short_len == LONG_LENGTH_MARKER {
            children.push(Block::leaf(
                format!("Record header (long): code {code}, length in next field"),
                span(offset, offset + 2),
            ));
            let Some(length) = read_u32(data, offset + 2) else {
                tags.push(Block::node(
                    format!("{name} (truncated)"),
                    span(offset, data.len()),
                    children,
                ));
                offset = data.len();
                break;
            };
            children.push(Block::leaf(
                format!("Length: {length}"),
                span(offset + 2, offset + 6),
            ));
            (length as usize, offset + 6)
        } else {
            children.push(Block::leaf(
                format!("Record header (short): code {code}, length {short_len}"),
                span(offset, offset + 2),
            ));
            (short_len as usize, offset + 2)
        };

        let declared_end = data_start.saturating_add(length);
        let end = declared_end.min(data.len());
        if end > data_start {
            children.push(Block::leaf(
                format!("Data ({} bytes)", end - data_start),
                span(data_start, end),
            ));
        }
        let label = if declared_end > data.len() {
            format!("{name} (truncated)")
        } else {
            name
        };
        tags.push(Block::node(label, span(offset, end), children));
        offset = end;

        if code == TAG_END {
            break;
        }
    }

    if !tags.is_empty() {
        let count = tags.len();
        blocks.push(Block::node(format!("Tags ({count})"), span(start, offset), tags).expanded());
    }
    if offset < data.len() {
        blocks.push(Block::leaf("Trailing data", span(offset, data.len())));
    }
    blocks
}

fn tag_name(code: u16) -> String {
    let name = match code {
        0 => "End",
        1 => "ShowFrame",
        2 => "DefineShape",
        4 => "PlaceObject",
        5 => "RemoveObject",
        6 => "DefineBits",
        7 => "DefineButton",
        8 => "JPEGTables",
        9 => "SetBackgroundColor",
        10 => "DefineFont",
        11 => "DefineText",
        12 => "DoAction",
        13 => "DefineFontInfo",
        14 => "DefineSound",
        15 => "StartSound",
        17 => "DefineButtonSound",
        18 => "SoundStreamHead",
        19 => "SoundStreamBlock",
        20 => "DefineBitsLossless",
        21 => "DefineBitsJPEG2",
        22 => "DefineShape2",
        23 => "DefineButtonCxform",
        24 => "Protect",
        26 => "PlaceObject2",
        28 => "RemoveObject2",
        32 => "DefineShape3",
        33 => "DefineText2",
        34 => "DefineButton2",
        35 => "DefineBitsJPEG3",
        36 => "DefineBitsLossless2",
        37 => "DefineEditText",
        39 => "DefineSprite",
        41 => "ProductInfo",
        43 => "FrameLabel",
        45 => "SoundStreamHead2",
        46 => "DefineMorphShape",
        48 => "DefineFont2",
        56 => "ExportAssets",
        57 => "ImportAssets",
        58 => "EnableDebugger",
        59 => "DoInitAction",
        60 => "DefineVideoStream",
        61 => "VideoFrame",
        62 => "DefineFontInfo2",
        63 => "DebugID",
        64 => "EnableDebugger2",
        65 => "ScriptLimits",
        66 => "SetTabIndex",
        69 => "FileAttributes",
        70 => "PlaceObject3",
        71 => "ImportAssets2",
        72 => "DoABCDefine",
        73 => "DefineFontAlignZones",
        74 => "CSMTextSettings",
        75 => "DefineFont3",
        76 => "SymbolClass",
        77 => "Metadata",
        78 => "DefineScalingGrid",
        82 => "DoABC",
        83 => "DefineShape4",
        84 => "DefineMorphShape2",
        86 => "DefineSceneAndFrameLabelData",
        87 => "DefineBinaryData",
        88 => "DefineFontName",
        89 => "StartSound2",
        90 => "DefineBitsJPEG4",
        91 => "DefineFont4",
        93 => "EnableTelemetry",
        94 => "PlaceObject4",
        _ => return format!("Unknown tag ({code})"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes values MSB-first into a byte buffer, padding the last byte.
    struct BitWriter {
        bytes: Vec<u8>,
        bits: usize,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                bits: 0,
            }
        }

        fn write(&mut self, value: u32, count: usize) {
            for i in (0..count).rev() {
                if self.bits % 8 == 0 {
                    self.bytes.push(0);
                }
                let bit = ((value >> i) & 1) as u8;
                let last = self.bytes.len() - 1;
                self.bytes[last] |= bit << (7 - self.bits % 8);
                self.bits += 1;
            }
        }
    }

    fn short_tag(code: u16, body: &[u8]) -> Vec<u8> {
        let mut out = ((code << 6) | body.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn long_tag(code: u16, body: &[u8]) -> Vec<u8> {
        let mut out = ((code << 6) | 0x3F).to_le_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Builds an FWS file: 550x400 px stage, 24 fps, 1 frame, with a
    /// SetBackgroundColor, a long-form DefineBinaryData, ShowFrame and End.
    fn build_swf() -> Vec<u8> {
        let mut rect = BitWriter::new();
        rect.write(15, 5);
        for v in [0i32, 11000, 0, 8000] {
            rect.write(v as u32 & 0x7FFF, 15);
        }

        let mut body = rect.bytes;
        body.extend_from_slice(&(24u16 << 8).to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend(short_tag(9, &[0xFF, 0x80, 0x00]));
        body.extend(long_tag(87, &[1, 2, 3, 4]));
        body.extend(short_tag(1, &[]));
        body.extend(short_tag(0, &[]));

        let mut data = b"FWS".to_vec();
        data.push(10);
        data.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        data.extend(body);
        data
    }

    fn build_compressed(magic: &[u8], body: &[u8]) -> Vec<u8> {
        let mut data = magic.to_vec();
        data.push(13);
        data.extend_from_slice(&1234u32.to_le_bytes());
        data.extend_from_slice(body);
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
    fn matches_all_signatures() {
        assert!(SwfDissector.matches(&build_swf()));
        assert!(SwfDissector.matches(&build_compressed(b"CWS", &[0x78, 0x9C])));
        assert!(SwfDissector.matches(&build_compressed(b"ZWS", &[0; 9])));
    }

    #[test]
    fn does_not_match_non_swf_data() {
        assert!(!SwfDissector.matches(b""));
        assert!(!SwfDissector.matches(b"FWS"));
        assert!(!SwfDissector.matches(b"FWS\x0a\x00\x00"));
        assert!(!SwfDissector.matches(b"not a swf file"));
        assert!(!SwfDissector.matches(b"FWSx plain text"));
        assert!(!SwfDissector.matches(b"FWS\x00\x10\x00\x00\x00"));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        assert!(SwfDissector.dissect(b"FWS\x0a").is_empty());
        let full = build_swf();
        for len in 0..full.len() {
            let blocks = SwfDissector.dissect(&full[..len]);
            if let Some(last) = blocks.last() {
                assert!(last.range.end <= len as u64);
            }
        }
        let header_only = SwfDissector.dissect(&full[..12]);
        assert_eq!(header_only.len(), 1);
        assert_eq!(header_only[0].range, ByteRange::new(0, 8));
        for magic in [b"CWS", b"ZWS"] {
            let data = build_compressed(magic, &[0; 12]);
            for len in 0..data.len() {
                SwfDissector.dissect(&data[..len]);
            }
        }
    }

    #[test]
    fn dissect_parses_uncompressed_header() {
        let data = build_swf();
        let blocks = SwfDissector.dissect(&data);
        let header = find_block(&blocks, "SWF header");
        assert_eq!(header.range, ByteRange::new(0, 21));

        let sig = find_block(&header.children, "Signature: FWS (compression: none)");
        assert_eq!(sig.range, ByteRange::new(0, 3));
        assert_eq!(
            find_block(&header.children, "Version: 10").range,
            ByteRange::new(3, 4)
        );
        assert_eq!(
            find_block(&header.children, "File length: 40").range,
            ByteRange::new(4, 8)
        );

        let rect = find_block(&header.children, "Frame size: 550 x 400 px");
        assert_eq!(rect.range, ByteRange::new(8, 17));
        let fields: Vec<_> = rect
            .children
            .iter()
            .map(|b| (b.label.as_str(), b.range))
            .collect();
        assert_eq!(
            fields,
            vec![
                ("Nbits: 15", ByteRange::new(8, 9)),
                ("Xmin: 0 twips", ByteRange::new(8, 11)),
                ("Xmax: 11000 twips", ByteRange::new(10, 13)),
                ("Ymin: 0 twips", ByteRange::new(12, 15)),
                ("Ymax: 8000 twips", ByteRange::new(14, 17)),
            ]
        );

        assert_eq!(
            find_block(&header.children, "Frame rate: 24 fps").range,
            ByteRange::new(17, 19)
        );
        assert_eq!(
            find_block(&header.children, "Frame count: 1").range,
            ByteRange::new(19, 21)
        );
    }

    #[test]
    fn dissect_parses_tag_list() {
        let data = build_swf();
        let blocks = SwfDissector.dissect(&data);
        assert_eq!(blocks.len(), 2);
        let tags = find_block(&blocks, "Tags (4)");
        assert_eq!(tags.range, ByteRange::new(21, 40));

        let bg = find_block(&tags.children, "SetBackgroundColor");
        assert_eq!(bg.range, ByteRange::new(21, 26));
        assert_eq!(
            find_block(&bg.children, "Record header (short): code 9, length 3").range,
            ByteRange::new(21, 23)
        );
        assert_eq!(
            find_block(&bg.children, "Data (3 bytes)").range,
            ByteRange::new(23, 26)
        );

        let bin = find_block(&tags.children, "DefineBinaryData");
        assert_eq!(bin.range, ByteRange::new(26, 36));
        assert_eq!(
            find_block(
                &bin.children,
                "Record header (long): code 87, length in next field"
            )
            .range,
            ByteRange::new(26, 28)
        );
        assert_eq!(
            find_block(&bin.children, "Length: 4").range,
            ByteRange::new(28, 32)
        );
        assert_eq!(
            find_block(&bin.children, "Data (4 bytes)").range,
            ByteRange::new(32, 36)
        );

        let show = find_block(&tags.children, "ShowFrame");
        assert_eq!(show.range, ByteRange::new(36, 38));
        assert_eq!(show.children.len(), 1);
        assert_eq!(
            find_block(&tags.children, "End").range,
            ByteRange::new(38, 40)
        );
    }

    #[test]
    fn dissect_marks_truncated_tag_and_trailing_data() {
        let full = build_swf();
        let blocks = SwfDissector.dissect(&full[..34]);
        let tags = find_block(&blocks, "Tags (2)");
        let bin = find_block(&tags.children, "DefineBinaryData (truncated)");
        assert_eq!(bin.range, ByteRange::new(26, 34));

        let mut extra = full.clone();
        extra.extend_from_slice(&[0xAA; 5]);
        let blocks = SwfDissector.dissect(&extra);
        assert_eq!(
            find_block(&blocks, "Trailing data").range,
            ByteRange::new(40, 45)
        );
    }

    #[test]
    fn dissect_parses_zlib_header() {
        let data = build_compressed(b"CWS", &[0x78, 0x9C, 1, 2, 3]);
        let blocks = SwfDissector.dissect(&data);
        let header = find_block(&blocks, "SWF header");
        assert_eq!(header.range, ByteRange::new(0, 8));
        assert!(
            header
                .children
                .iter()
                .any(|b| b.label == "Signature: CWS (compression: zlib)")
        );
        assert_eq!(
            find_block(&header.children, "File length (uncompressed): 1234").range,
            ByteRange::new(4, 8)
        );
        assert_eq!(
            find_block(&blocks, "Compressed body (zlib)").range,
            ByteRange::new(8, 13)
        );
    }

    #[test]
    fn dissect_parses_lzma_header() {
        let mut body = 3u32.to_le_bytes().to_vec();
        body.extend_from_slice(&[0x5D, 0x00, 0x00, 0x10, 0x00]);
        body.extend_from_slice(&[9, 9, 9]);
        let data = build_compressed(b"ZWS", &body);
        let blocks = SwfDissector.dissect(&data);
        let header = find_block(&blocks, "SWF header");
        assert_eq!(header.range, ByteRange::new(0, 17));
        assert!(
            header
                .children
                .iter()
                .any(|b| b.label == "Signature: ZWS (compression: LZMA)")
        );
        assert_eq!(
            find_block(&header.children, "Compressed length: 3").range,
            ByteRange::new(8, 12)
        );
        assert_eq!(
            find_block(
                &header.children,
                "LZMA properties: 0x5D, dictionary size 1048576"
            )
            .range,
            ByteRange::new(12, 17)
        );
        assert_eq!(
            find_block(&blocks, "Compressed body (LZMA)").range,
            ByteRange::new(17, 20)
        );
    }

    #[test]
    fn identify_reports_swf() {
        assert_eq!(super::super::identify(&build_swf()), "SWF");
        assert_eq!(
            super::super::identify(&build_compressed(b"CWS", &[0x78, 0x9C])),
            "SWF"
        );
        assert_eq!(
            super::super::identify(&build_compressed(b"ZWS", &[0; 9])),
            "SWF"
        );
    }
}
