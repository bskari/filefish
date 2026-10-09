use super::{Block, ByteRange, Dissector};

const BPG_MAGIC: &[u8] = &[0x42, 0x50, 0x47, 0xFB];
/// Magic plus the two flag bytes.
const FIXED_HEADER_LEN: usize = 6;
/// Thumbnails are themselves BPG files; limit how deep we recurse into them.
const MAX_THUMBNAIL_DEPTH: u32 = 4;
/// Stop listing individual NAL units after this many.
const MAX_NAL_UNITS: usize = 10_000;

pub struct BpgDissector;

impl Dissector for BpgDissector {
    fn name(&self) -> &'static str {
        "BPG"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= FIXED_HEADER_LEN && data.starts_with(BPG_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        dissect_bpg(data, 0)
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

/// Reads a ue7(max_bits) value: big-endian groups of 7 bits, high bit set on
/// every byte except the last. Returns the value and the number of bytes used.
fn read_ue7(data: &[u8], offset: usize, max_bits: u32) -> Option<(u32, usize)> {
    let max_bytes = max_bits.div_ceil(7) as usize;
    let mut value: u64 = 0;
    for i in 0..max_bytes {
        let byte = *data.get(offset.checked_add(i)?)?;
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            if value >> max_bits != 0 {
                return None;
            }
            return Some((value as u32, i + 1));
        }
    }
    None
}

fn pixel_format_name(value: u8) -> &'static str {
    match value {
        0 => "Grayscale",
        1 => "4:2:0 (JPEG chroma position)",
        2 => "4:2:2 (JPEG chroma position)",
        3 => "4:4:4",
        4 => "4:2:0 (MPEG2 chroma position)",
        5 => "4:2:2 (MPEG2 chroma position)",
        _ => "Reserved",
    }
}

fn color_space_name(value: u8) -> &'static str {
    match value {
        0 => "YCbCr (BT 601)",
        1 => "RGB",
        2 => "YCgCo",
        3 => "YCbCr (BT 709)",
        4 => "YCbCr (BT 2020 non-constant luminance)",
        5 => "YCbCr (BT 2020 constant luminance, reserved)",
        _ => "Reserved",
    }
}

fn alpha_name(alpha1: bool, alpha2: bool) -> &'static str {
    match (alpha1, alpha2) {
        (false, false) => "none",
        (true, false) => "alpha (not premultiplied)",
        (true, true) => "alpha (premultiplied)",
        (false, true) => "W plane (CMYK)",
    }
}

fn extension_tag_name(tag: u32) -> &'static str {
    match tag {
        1 => "EXIF",
        2 => "ICC profile",
        3 => "XMP",
        4 => "Thumbnail",
        5 => "Animation control",
        _ => "Unknown",
    }
}

fn nal_type_name(nal_type: u8) -> &'static str {
    match nal_type {
        0 => "TRAIL_N",
        1 => "TRAIL_R",
        2 => "TSA_N",
        3 => "TSA_R",
        4 => "STSA_N",
        5 => "STSA_R",
        6 => "RADL_N",
        7 => "RADL_R",
        8 => "RASL_N",
        9 => "RASL_R",
        16 => "BLA_W_LP",
        17 => "BLA_W_RADL",
        18 => "BLA_N_LP",
        19 => "IDR_W_RADL",
        20 => "IDR_N_LP",
        21 => "CRA_NUT",
        32 => "VPS",
        33 => "SPS",
        34 => "PPS",
        35 => "AUD",
        36 => "EOS",
        37 => "EOB",
        38 => "FD",
        39 => "PREFIX_SEI",
        40 => "SUFFIX_SEI",
        _ => "Reserved",
    }
}

fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

fn shift_block(mut block: Block, base: usize) -> Block {
    block.range = ByteRange::new(
        block.range.start + base as u64,
        block.range.end + base as u64,
    );
    block.children = block
        .children
        .into_iter()
        .map(|c| shift_block(c, base))
        .collect();
    block
}

fn dissect_bpg(data: &[u8], depth: u32) -> Vec<Block> {
    let mut blocks = Vec::new();
    if data.len() < FIXED_HEADER_LEN || !data.starts_with(BPG_MAGIC) {
        return blocks;
    }

    let b4 = data[4];
    let b5 = data[5];
    let pixel_format = b4 >> 5;
    let alpha1 = b4 & 0x10 != 0;
    let bit_depth = (b4 & 0x0F) + 8;
    let color_space = b5 >> 4;
    let has_extension = b5 & 0x08 != 0;
    let alpha2 = b5 & 0x04 != 0;
    let limited_range = b5 & 0x02 != 0;
    let animation = b5 & 0x01 != 0;

    let mut header = vec![
        Block::leaf("Magic: BPG\\xFB", range(0, 4)),
        Block::leaf(
            format!(
                "Pixel format: {} ({pixel_format})",
                pixel_format_name(pixel_format)
            ),
            range(4, 5),
        ),
        Block::leaf(format!("Alpha1 flag: {}", u8::from(alpha1)), range(4, 5)),
        Block::leaf(format!("Bit depth: {bit_depth}"), range(4, 5)),
        Block::leaf(
            format!(
                "Color space: {} ({color_space})",
                color_space_name(color_space)
            ),
            range(5, 6),
        ),
        Block::leaf(
            format!("Extension present: {}", yes_no(has_extension)),
            range(5, 6),
        ),
        Block::leaf(format!("Alpha2 flag: {}", u8::from(alpha2)), range(5, 6)),
        Block::leaf(
            format!("Limited range: {}", yes_no(limited_range)),
            range(5, 6),
        ),
        Block::leaf(format!("Animation: {}", yes_no(animation)), range(5, 6)),
        Block::leaf(
            format!("Alpha: {}", alpha_name(alpha1, alpha2)),
            range(4, 6),
        ),
    ];

    let mut off = FIXED_HEADER_LEN;
    let mut fields: [Option<u32>; 3] = [None; 3];
    for (i, name) in ["Width", "Height", "Picture data length"]
        .iter()
        .enumerate()
    {
        let Some((value, len)) = read_ue7(data, off, 32) else {
            break;
        };
        let label = if i == 2 && value == 0 {
            format!("{name}: 0 (until end of file)")
        } else {
            format!("{name}: {value}")
        };
        header.push(Block::leaf(label, range(off, off + len)));
        fields[i] = Some(value);
        off += len;
    }

    let Some(pic_len) = fields[2] else {
        blocks.push(Block::node("BPG header", range(0, off), header).expanded());
        return blocks;
    };

    let mut ext_range = None;
    if has_extension {
        match read_ue7(data, off, 32) {
            Some((ext_len, len)) => {
                header.push(Block::leaf(
                    format!("Extension data length: {ext_len}"),
                    range(off, off + len),
                ));
                off += len;
                let ext_end = off.saturating_add(ext_len as usize);
                ext_range = Some((off, ext_end));
            }
            None => {
                blocks.push(Block::node("BPG header", range(0, off), header).expanded());
                return blocks;
            }
        }
    }
    blocks.push(Block::node("BPG header", range(0, off), header).expanded());

    if let Some((ext_start, ext_end)) = ext_range {
        let clamped_end = ext_end.min(data.len());
        blocks.push(
            Block::node(
                "Extension data",
                range(ext_start, clamped_end),
                extension_blocks(data, ext_start, clamped_end, depth),
            )
            .expanded(),
        );
        off = ext_end;
    }

    if off >= data.len() {
        return blocks;
    }

    let pic_end = if pic_len == 0 {
        data.len()
    } else {
        off.saturating_add(pic_len as usize).min(data.len())
    };
    blocks.push(
        Block::node(
            "Picture data",
            range(off, pic_end),
            picture_blocks(data, off, pic_end, alpha1, alpha2),
        )
        .expanded(),
    );
    if pic_end < data.len() {
        blocks.push(Block::leaf("Trailing data", range(pic_end, data.len())));
    }
    blocks
}

fn extension_blocks(data: &[u8], start: usize, end: usize, depth: u32) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut off = start;
    while off < end {
        let Some((tag, tag_len)) = read_ue7(&data[..end], off, 32) else {
            blocks.push(Block::leaf("Malformed extension", range(off, end)));
            break;
        };
        let Some((len, len_len)) = read_ue7(&data[..end], off + tag_len, 32) else {
            blocks.push(Block::leaf("Malformed extension", range(off, end)));
            break;
        };
        let name = extension_tag_name(tag);
        let payload_start = off + tag_len + len_len;
        let payload_end = payload_start.saturating_add(len as usize).min(end);
        let mut children = vec![
            Block::leaf(format!("Tag: {tag} ({name})"), range(off, off + tag_len)),
            Block::leaf(
                format!("Length: {len}"),
                range(off + tag_len, payload_start),
            ),
        ];
        if payload_end > payload_start {
            let payload = &data[payload_start..payload_end];
            match tag {
                5 => children.extend(animation_control_blocks(payload, payload_start)),
                4 if depth < MAX_THUMBNAIL_DEPTH && payload.starts_with(BPG_MAGIC) => {
                    children.push(Block::node(
                        "Thumbnail (BPG)",
                        range(payload_start, payload_end),
                        dissect_bpg(payload, depth + 1)
                            .into_iter()
                            .map(|b| shift_block(b, payload_start))
                            .collect(),
                    ));
                }
                _ => children.push(Block::leaf("Data", range(payload_start, payload_end))),
            }
        }
        blocks.push(Block::node(
            format!("Extension: {name} ({len} bytes)"),
            range(off, payload_end),
            children,
        ));
        off = payload_start.saturating_add(len as usize);
    }
    blocks
}

fn animation_control_blocks(payload: &[u8], base: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut off = 0;
    let mut values = [0u32; 3];
    let mut num_start = 0;
    for (i, name) in [
        "Loop count",
        "Frame period numerator",
        "Frame period denominator",
    ]
    .iter()
    .enumerate()
    {
        let Some((value, len)) = read_ue7(payload, off, 16) else {
            return blocks;
        };
        let label = if i == 0 && value == 0 {
            format!("{name}: 0 (infinite)")
        } else {
            format!("{name}: {value}")
        };
        if i == 1 {
            num_start = off;
        }
        blocks.push(Block::leaf(label, range(base + off, base + off + len)));
        values[i] = value;
        off += len;
    }
    if values[2] != 0 {
        blocks.push(Block::leaf(
            format!(
                "Frame period: {}/{} s ({:.3} s)",
                values[1],
                values[2],
                f64::from(values[1]) / f64::from(values[2])
            ),
            range(base + num_start, base + off),
        ));
    }
    if off < payload.len() {
        blocks.push(Block::leaf(
            "Padding",
            range(base + off, base + payload.len()),
        ));
    }
    blocks
}

fn picture_blocks(data: &[u8], start: usize, end: usize, alpha1: bool, alpha2: bool) -> Vec<Block> {
    let mut blocks = Vec::new();
    let data = &data[..end];
    let mut off = start;
    let mut headers: Vec<&str> = Vec::new();
    if alpha1 || alpha2 {
        headers.push(if alpha1 {
            "Alpha HEVC header"
        } else {
            "W plane HEVC header (CMYK)"
        });
    }
    headers.push("Color HEVC header");
    for name in headers {
        let Some((len, len_len)) = read_ue7(data, off, 32) else {
            if off < end {
                blocks.push(Block::leaf("Malformed HEVC header", range(off, end)));
            }
            return blocks;
        };
        let body_start = off + len_len;
        let body_end = body_start.saturating_add(len as usize).min(end);
        let mut children = vec![Block::leaf(
            format!("HEVC header length: {len}"),
            range(off, body_start),
        )];
        children.extend(hevc_header_fields(&data[body_start..body_end], body_start));
        blocks.push(Block::node(name, range(off, body_end), children));
        off = body_start.saturating_add(len as usize);
        if off >= end {
            return blocks;
        }
    }
    blocks.push(Block::node(
        "HEVC data",
        range(off, end),
        nal_blocks(data, off, end, alpha1 || alpha2),
    ));
    blocks
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    fn bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.pos / 8)?;
        let bit = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(u32::from(bit))
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut value = 0;
        for _ in 0..n {
            value = (value << 1) | self.bit()?;
        }
        Some(value)
    }

    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        let rest = self.bits(zeros)?;
        Some(((1u64 << zeros) - 1 + u64::from(rest)) as u32)
    }
}

/// Decodes the bit-packed HEVC SPS subset in a BPG hevc_header(). Each field
/// is labeled with the bytes its bits fall in.
fn hevc_header_fields(body: &[u8], base: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut r = BitReader { data: body, pos: 0 };

    macro_rules! field {
        ($name:expr, $read:expr) => {{
            let before = r.pos;
            let Some(v) = $read else {
                return blocks;
            };
            blocks.push(Block::leaf(
                format!("{}: {v}", $name),
                range(base + before / 8, base + r.pos.div_ceil(8)),
            ));
            v
        }};
    }

    field!("log2_min_luma_coding_block_size_minus3", r.ue());
    field!("log2_diff_max_min_luma_coding_block_size", r.ue());
    field!("log2_min_transform_block_size_minus2", r.ue());
    field!("log2_diff_max_min_transform_block_size", r.ue());
    field!("max_transform_hierarchy_depth_intra", r.ue());
    field!("sample_adaptive_offset_enabled_flag", r.bits(1));
    let pcm = field!("pcm_enabled_flag", r.bits(1));
    if pcm != 0 {
        field!("pcm_sample_bit_depth_luma_minus1", r.bits(4));
        field!("pcm_sample_bit_depth_chroma_minus1", r.bits(4));
        field!("log2_min_pcm_luma_coding_block_size_minus3", r.ue());
        field!("log2_diff_max_min_pcm_luma_coding_block_size", r.ue());
        field!("pcm_loop_filter_disabled_flag", r.bits(1));
    }
    field!("strong_intra_smoothing_enabled_flag", r.bits(1));
    let ext = field!("sps_extension_present_flag", r.bits(1));
    if ext != 0 {
        let range_ext = field!("sps_range_extension_flag", r.bits(1));
        field!("sps_extension_7bits", r.bits(7));
        if range_ext != 0 {
            for name in [
                "transform_skip_rotation_enabled_flag",
                "transform_skip_context_enabled_flag",
                "implicit_rdpcm_enabled_flag",
                "explicit_rdpcm_enabled_flag",
                "extended_precision_processing_flag",
                "intra_smoothing_disabled_flag",
                "high_precision_offsets_enabled_flag",
                "persistent_rice_adaptation_enabled_flag",
                "cabac_bypass_alignment_enabled_flag",
            ] {
                field!(name, r.bits(1));
            }
        }
    }
    let used = r.pos.div_ceil(8);
    if used < body.len() {
        blocks.push(Block::leaf(
            "Extra header bytes",
            range(base + used, base + body.len()),
        ));
    }
    blocks
}

/// Finds the next 00 00 01 start code at or after `from`, returning the start
/// of the start code (including a preceding zero for the 4-byte form, as long
/// as it stays at or after `min_start`).
fn find_start_code(
    data: &[u8],
    from: usize,
    end: usize,
    min_start: usize,
) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= end {
        if data[i + 2] > 1 {
            i += 3;
            continue;
        }
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let sc_start = if i > min_start && data[i - 1] == 0 {
                i - 1
            } else {
                i
            };
            return Some((sc_start, i + 3));
        }
        i += 1;
    }
    None
}

/// Walks the HEVC NAL units. The first NAL has no start code; subsequent ones
/// are separated by 00 00 01 or 00 00 00 01.
fn nal_blocks(data: &[u8], start: usize, end: usize, has_alpha: bool) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut block_start = start;
    let mut nal_start = start;
    loop {
        if blocks.len() >= MAX_NAL_UNITS {
            blocks.push(Block::leaf("Remaining NAL units", range(block_start, end)));
            break;
        }
        let search_from = nal_start + 2;
        let (next_block, next_nal) =
            match find_start_code(data, search_from.min(end), end, search_from) {
                Some(found) => found,
                None => (end, end),
            };
        let mut children = Vec::new();
        if nal_start > block_start {
            children.push(Block::leaf("Start code", range(block_start, nal_start)));
        }
        let label = if nal_start + 2 <= next_block {
            let h0 = data[nal_start];
            let h1 = data[nal_start + 1];
            let nal_type = (h0 >> 1) & 0x3F;
            let layer = ((h0 & 1) << 5) | (h1 >> 3);
            let tid = h1 & 7;
            children.push(Block::leaf(
                format!(
                    "NAL header: type {nal_type} ({}), layer {layer}, temporal_id_plus1 {tid}",
                    nal_type_name(nal_type)
                ),
                range(nal_start, nal_start + 2),
            ));
            if next_block > nal_start + 2 {
                children.push(Block::leaf("Payload", range(nal_start + 2, next_block)));
            }
            let plane = if !has_alpha {
                ""
            } else if layer == 1 {
                ", alpha"
            } else {
                ", color"
            };
            format!("NAL unit: {}{plane}", nal_type_name(nal_type))
        } else {
            "Truncated NAL unit".to_string()
        };
        blocks.push(Block::node(label, range(block_start, next_block), children));
        if next_block >= end {
            break;
        }
        block_start = next_block;
        nal_start = next_nal;
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_ue7(buf: &mut Vec<u8>, value: u32) {
        let mut groups = vec![(value & 0x7F) as u8];
        let mut v = value >> 7;
        while v != 0 {
            groups.push((v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }
        groups.reverse();
        buf.extend_from_slice(&groups);
    }

    /// Minimal SPS subset: 15 bits of fields plus one trailing bit.
    const HEVC_HEADER: [u8; 2] = [0xA9, 0x34];

    fn build_bpg(
        alpha1: bool,
        alpha2: bool,
        animation: bool,
        extensions: &[u8],
        hevc_data: &[u8],
        pic_len_zero: bool,
    ) -> Vec<u8> {
        let mut pic = Vec::new();
        let headers = if alpha1 || alpha2 { 2 } else { 1 };
        for _ in 0..headers {
            push_ue7(&mut pic, HEVC_HEADER.len() as u32);
            pic.extend_from_slice(&HEVC_HEADER);
        }
        pic.extend_from_slice(hevc_data);

        let mut data = BPG_MAGIC.to_vec();
        data.push((1 << 5) | (u8::from(alpha1) << 4)); // 4:2:0, 8-bit
        data.push(
            (3 << 4)
                | (u8::from(!extensions.is_empty()) << 3)
                | (u8::from(alpha2) << 2)
                | u8::from(animation),
        );
        push_ue7(&mut data, 300);
        push_ue7(&mut data, 8);
        push_ue7(&mut data, if pic_len_zero { 0 } else { pic.len() as u32 });
        if !extensions.is_empty() {
            push_ue7(&mut data, extensions.len() as u32);
            data.extend_from_slice(extensions);
        }
        data.extend_from_slice(&pic);
        data
    }

    fn two_nals() -> Vec<u8> {
        vec![0x26, 0x01, 0xAA, 0xBB, 0, 0, 0, 1, 0x26, 0x09, 0xCC]
    }

    fn full_sample() -> Vec<u8> {
        let ext = [5, 3, 0, 1, 25, 1, 4, b'E', b'x', b'i', b'f'];
        let mut data = build_bpg(true, true, true, &ext, &two_nals(), false);
        data.extend_from_slice(b"XY");
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

    fn assert_nested(blocks: &[Block], parent: ByteRange) {
        for b in blocks {
            assert!(b.range.start <= b.range.end, "{}", b.label);
            assert!(
                b.range.start >= parent.start && b.range.end <= parent.end,
                "{} {:?} outside {:?}",
                b.label,
                b.range,
                parent
            );
            assert_nested(&b.children, b.range);
        }
    }

    #[test]
    fn read_ue7_spec_examples() {
        assert_eq!(read_ue7(&[0x08], 0, 32), Some((8, 1)));
        assert_eq!(read_ue7(&[0x84, 0x1E], 0, 32), Some((542, 2)));
        assert_eq!(read_ue7(&[0xAC, 0xBE, 0x17], 0, 32), Some((728855, 3)));
        assert_eq!(read_ue7(&[0x84], 0, 32), None);
        assert_eq!(
            read_ue7(&[0x8F, 0xFF, 0xFF, 0xFF, 0x7F], 0, 32),
            Some((u32::MAX, 5))
        );
        assert_eq!(read_ue7(&[0x9F, 0xFF, 0xFF, 0xFF, 0x7F], 0, 32), None);
        assert_eq!(read_ue7(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00], 0, 32), None);
        assert_eq!(read_ue7(&[0x84, 0x80, 0x00], 0, 16), None);
        assert_eq!(read_ue7(&[0x83, 0xFF, 0x7F], 0, 16), Some((0xFFFF, 3)));
    }

    #[test]
    fn matches_bpg_magic() {
        assert!(BpgDissector.matches(&full_sample()));
    }

    #[test]
    fn does_not_match_non_bpg_data() {
        assert!(!BpgDissector.matches(b""));
        assert!(!BpgDissector.matches(b"not a bpg file"));
        assert!(!BpgDissector.matches(b"BPG\xFB\x20"));
        assert!(!BpgDissector.matches(b"BPGX\x20\x30"));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = full_sample();
        let full = BpgDissector.dissect(&data).len();
        for len in 0..data.len() {
            let blocks = BpgDissector.dissect(&data[..len]);
            assert!(blocks.len() <= full);
            assert_nested(&blocks, ByteRange::new(0, len as u64));
        }
        assert!(BpgDissector.dissect(b"BPG").is_empty());
    }

    #[test]
    fn dissect_parses_header() {
        let data = full_sample();
        let blocks = BpgDissector.dissect(&data);
        assert_nested(&blocks, ByteRange::new(0, data.len() as u64));

        let header = find_block(&blocks, "BPG header");
        assert_eq!(header.range, ByteRange::new(0, 11));
        let c = &header.children;
        assert_eq!(find_block(c, "Magic: BPG\\xFB").range, ByteRange::new(0, 4));
        find_block(c, "Pixel format: 4:2:0 (JPEG chroma position) (1)");
        find_block(c, "Bit depth: 8");
        find_block(c, "Color space: YCbCr (BT 709) (3)");
        find_block(c, "Extension present: yes");
        find_block(c, "Animation: yes");
        find_block(c, "Limited range: no");
        assert_eq!(
            find_block(c, "Alpha: alpha (premultiplied)").range,
            ByteRange::new(4, 6)
        );
        assert_eq!(find_block(c, "Width: 300").range, ByteRange::new(6, 8));
        assert_eq!(find_block(c, "Height: 8").range, ByteRange::new(8, 9));
        assert_eq!(
            find_block(c, "Picture data length: 17").range,
            ByteRange::new(9, 10)
        );
        assert_eq!(
            find_block(c, "Extension data length: 11").range,
            ByteRange::new(10, 11)
        );
    }

    #[test]
    fn dissect_parses_extensions() {
        let data = full_sample();
        let blocks = BpgDissector.dissect(&data);
        let ext = find_block(&blocks, "Extension data");
        assert_eq!(ext.range, ByteRange::new(11, 22));

        let anim = find_block(&ext.children, "Extension: Animation control (3 bytes)");
        assert_eq!(anim.range, ByteRange::new(11, 16));
        find_block(&anim.children, "Tag: 5 (Animation control)");
        assert_eq!(
            find_block(&anim.children, "Loop count: 0 (infinite)").range,
            ByteRange::new(13, 14)
        );
        assert_eq!(
            find_block(&anim.children, "Frame period: 1/25 s (0.040 s)").range,
            ByteRange::new(14, 16)
        );

        let exif = find_block(&ext.children, "Extension: EXIF (4 bytes)");
        assert_eq!(exif.range, ByteRange::new(16, 22));
        assert_eq!(
            find_block(&exif.children, "Data").range,
            ByteRange::new(18, 22)
        );
    }

    #[test]
    fn dissect_parses_picture_data() {
        let data = full_sample();
        let blocks = BpgDissector.dissect(&data);
        let pic = find_block(&blocks, "Picture data");
        assert_eq!(pic.range, ByteRange::new(22, 39));

        let alpha = find_block(&pic.children, "Alpha HEVC header");
        assert_eq!(alpha.range, ByteRange::new(22, 25));
        let color = find_block(&pic.children, "Color HEVC header");
        assert_eq!(color.range, ByteRange::new(25, 28));
        let c = &color.children;
        find_block(c, "HEVC header length: 2");
        find_block(c, "log2_min_luma_coding_block_size_minus3: 0");
        find_block(c, "log2_diff_max_min_luma_coding_block_size: 1");
        assert_eq!(
            find_block(c, "log2_diff_max_min_transform_block_size: 3").range,
            ByteRange::new(26, 28)
        );
        find_block(c, "sample_adaptive_offset_enabled_flag: 1");
        find_block(c, "pcm_enabled_flag: 0");
        find_block(c, "strong_intra_smoothing_enabled_flag: 1");
        find_block(c, "sps_extension_present_flag: 0");

        let hevc = find_block(&pic.children, "HEVC data");
        assert_eq!(hevc.range, ByteRange::new(28, 39));
        let first = find_block(&hevc.children, "NAL unit: IDR_W_RADL, color");
        assert_eq!(first.range, ByteRange::new(28, 32));
        let second = find_block(&hevc.children, "NAL unit: IDR_W_RADL, alpha");
        assert_eq!(second.range, ByteRange::new(32, 39));
        assert_eq!(
            find_block(&second.children, "Start code").range,
            ByteRange::new(32, 36)
        );
        assert_eq!(
            find_block(
                &second.children,
                "NAL header: type 19 (IDR_W_RADL), layer 1, temporal_id_plus1 1"
            )
            .range,
            ByteRange::new(36, 38)
        );
        assert_eq!(
            find_block(&second.children, "Payload").range,
            ByteRange::new(38, 39)
        );

        assert_eq!(
            find_block(&blocks, "Trailing data").range,
            ByteRange::new(39, 41)
        );
    }

    #[test]
    fn dissect_picture_length_zero_runs_to_end() {
        let data = build_bpg(false, false, false, &[], &two_nals(), true);
        let blocks = BpgDissector.dissect(&data);
        let header = find_block(&blocks, "BPG header");
        find_block(
            &header.children,
            "Picture data length: 0 (until end of file)",
        );
        find_block(&header.children, "Alpha: none");
        let pic = find_block(&blocks, "Picture data");
        assert_eq!(pic.range, ByteRange::new(10, data.len() as u64));
        assert!(pic.children.iter().all(|b| b.label != "Alpha HEVC header"));
        let hevc = find_block(&pic.children, "HEVC data");
        find_block(&hevc.children, "NAL unit: IDR_W_RADL");
        assert!(blocks.iter().all(|b| b.label != "Trailing data"));
    }

    #[test]
    fn dissect_cmyk_alpha_label() {
        let data = build_bpg(false, true, false, &[], &two_nals(), false);
        let blocks = BpgDissector.dissect(&data);
        let header = find_block(&blocks, "BPG header");
        find_block(&header.children, "Alpha: W plane (CMYK)");
        let pic = find_block(&blocks, "Picture data");
        find_block(&pic.children, "W plane HEVC header (CMYK)");
    }

    #[test]
    fn dissect_nested_thumbnail() {
        let thumb = build_bpg(false, false, false, &[], &[0x26, 0x01, 0xAA], false);
        let mut ext = vec![4];
        push_ue7(&mut ext, thumb.len() as u32);
        ext.extend_from_slice(&thumb);
        let data = build_bpg(false, false, false, &ext, &two_nals(), false);
        let blocks = BpgDissector.dissect(&data);
        assert_nested(&blocks, ByteRange::new(0, data.len() as u64));
        let ext_block = find_block(&blocks, "Extension data");
        let entry = &ext_block.children[0];
        let node = find_block(&entry.children, "Thumbnail (BPG)");
        // Main header is 11 bytes; tag and length take 2 more.
        let payload_start = 13;
        assert_eq!(node.range.start, payload_start);
        let inner = find_block(&node.children, "BPG header");
        assert_eq!(
            find_block(&inner.children, "Magic: BPG\\xFB").range,
            ByteRange::new(payload_start, payload_start + 4)
        );
    }

    #[test]
    fn identify_reports_bpg() {
        assert_eq!(super::super::identify(&full_sample()), "BPG");
    }
}
