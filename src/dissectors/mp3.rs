use std::borrow::Cow;

use super::{Block, ByteRange, Dissector};

const ID3V2_MAGIC: &[u8] = b"ID3";
const ID3V2_FOOTER_MAGIC: &[u8] = b"3DI";
const ID3V1_MAGIC: &[u8] = b"TAG";
const ID3V1_ENHANCED_MAGIC: &[u8] = b"TAG+";
const APE_MAGIC: &[u8] = b"APETAGEX";
const LYRICS3_BEGIN: &[u8] = b"LYRICSBEGIN";
const LYRICS3V1_END: &[u8] = b"LYRICSEND";
const LYRICS3V2_END: &[u8] = b"LYRICS200";

const ID3V1_LEN: usize = 128;
const ID3V1_ENHANCED_LEN: usize = 227;
const APE_FOOTER_LEN: usize = 32;
const LYRICS3V1_MAX_LEN: usize = 5100;

/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct Mp3Dissector;

impl Dissector for Mp3Dissector {
    fn name(&self) -> &'static str {
        "MP3"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if parse_id3v2_header(data, 0).is_some() {
            return true;
        }
        // Without a tag, require two consecutive matching frame headers (or a
        // single frame filling the file) so stray 0xFFE sync bits don't match.
        frame_at(data, 0, data.len(), None).is_some()
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        let mut start = 0;
        while let Some(header) = parse_id3v2_header(data, start) {
            let tag = id3v2_block(data, start, &header);
            start = tag.range.end as usize;
            blocks.push(tag);
        }

        let (trailing, audio_end) = trailing_tags(data, start);
        if audio_end > start {
            blocks.push(audio_block(data, start, audio_end));
        }
        blocks.extend(trailing);

        blocks
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u24_be(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 3)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Reads a 28-bit ID3v2 "synchsafe" integer (7 bits per byte, MSB clear).
fn read_synchsafe(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    if b.iter().any(|&x| x & 0x80 != 0) {
        return None;
    }
    Some(b.iter().fold(0u32, |acc, &x| (acc << 7) | x as u32))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Formats the names of the set bits in `flags`, e.g. " (footer, experimental)".
fn flag_names(flags: u32, names: &[(u32, &str)]) -> String {
    let set: Vec<&str> = names
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if set.is_empty() {
        String::new()
    } else {
        format!(" ({})", set.join(", "))
    }
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Makes `text` fit on a single, reasonably short tree line.
fn display(text: &str) -> String {
    let single_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = single_line.trim();
    if trimmed.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = trimmed.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        trimmed.to_string()
    }
}

fn format_duration(seconds: f64) -> String {
    let total_ms = (seconds * 1000.0).round() as u64;
    let (minutes, ms) = (total_ms / 60_000, total_ms % 60_000);
    format!("{minutes}:{:02}.{:03}", ms / 1000, ms % 1000)
}

/// CRC-16 as used by MPEG audio frame headers (poly 0x8005, init 0xFFFF).
fn crc16_mpeg<'a>(bytes: impl IntoIterator<Item = &'a u8>) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in bytes {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8005
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// CRC-16/ARC (reflected poly 0x8005, init 0), as used by the LAME tag.
fn crc16_arc(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

fn crc_label(name: &str, stored: u16, computed: u16) -> String {
    if stored == computed {
        format!("{name}: 0x{stored:04X} (valid)")
    } else {
        format!("{name}: 0x{stored:04X} (invalid, computed 0x{computed:04X})")
    }
}

// ---------------------------------------------------------------------------
// MPEG audio frames
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum MpegVersion {
    V1,
    V2,
    V25,
}

impl MpegVersion {
    fn name(self) -> &'static str {
        match self {
            MpegVersion::V1 => "MPEG-1",
            MpegVersion::V2 => "MPEG-2",
            MpegVersion::V25 => "MPEG-2.5",
        }
    }
}

const BITRATES_V1_L1: [u32; 16] = [
    0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0,
];
const BITRATES_V1_L2: [u32; 16] = [
    0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0,
];
const BITRATES_V1_L3: [u32; 16] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
];
const BITRATES_V2_L1: [u32; 16] = [
    0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0,
];
const BITRATES_V2_L23: [u32; 16] = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
];

const CHANNEL_MODE_MONO: u8 = 3;

#[derive(Clone, Copy, Debug)]
struct FrameHeader {
    raw: u32,
    version: MpegVersion,
    layer: u8,
    crc: bool,
    bitrate: u32, // kbps
    sample_rate: u32,
    padding: bool,
    channel_mode: u8,
    frame_len: usize,
}

impl FrameHeader {
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        let raw = read_u32_be(data, offset)?;
        if raw >> 21 != 0x7FF {
            return None;
        }
        let version = match (raw >> 19) & 3 {
            0 => MpegVersion::V25,
            2 => MpegVersion::V2,
            3 => MpegVersion::V1,
            _ => return None,
        };
        let layer = match (raw >> 17) & 3 {
            1 => 3,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let bitrate_index = ((raw >> 12) & 0xF) as usize;
        let sample_rate_index = ((raw >> 10) & 3) as usize;
        // Free-format (index 0) streams aren't supported: their frame length
        // can't be computed from the header alone.
        if bitrate_index == 0 || bitrate_index == 15 || sample_rate_index == 3 || raw & 3 == 2 {
            return None;
        }

        let bitrates = match (version, layer) {
            (MpegVersion::V1, 1) => &BITRATES_V1_L1,
            (MpegVersion::V1, 2) => &BITRATES_V1_L2,
            (MpegVersion::V1, _) => &BITRATES_V1_L3,
            (_, 1) => &BITRATES_V2_L1,
            _ => &BITRATES_V2_L23,
        };
        let bitrate = bitrates[bitrate_index];
        let sample_rate = match version {
            MpegVersion::V1 => [44100, 48000, 32000][sample_rate_index],
            MpegVersion::V2 => [22050, 24000, 16000][sample_rate_index],
            MpegVersion::V25 => [11025, 12000, 8000][sample_rate_index],
        };
        let padding = (raw >> 9) & 1 == 1;
        let pad = padding as u32;
        let frame_len = match layer {
            1 => (12 * bitrate * 1000 / sample_rate + pad) * 4,
            2 => 144 * bitrate * 1000 / sample_rate + pad,
            _ if version == MpegVersion::V1 => 144 * bitrate * 1000 / sample_rate + pad,
            _ => 72 * bitrate * 1000 / sample_rate + pad,
        } as usize;

        Some(Self {
            raw,
            version,
            layer,
            crc: (raw >> 16) & 1 == 0,
            bitrate,
            sample_rate,
            padding,
            channel_mode: ((raw >> 6) & 3) as u8,
            frame_len,
        })
    }

    fn samples(&self) -> u32 {
        match (self.layer, self.version) {
            (1, _) => 384,
            (2, _) | (3, MpegVersion::V1) => 1152,
            _ => 576,
        }
    }

    fn side_info_len(&self) -> usize {
        if self.layer != 3 {
            return 0;
        }
        let mono = self.channel_mode == CHANNEL_MODE_MONO;
        match (self.version, mono) {
            (MpegVersion::V1, true) => 17,
            (MpegVersion::V1, false) => 32,
            (_, true) => 9,
            (_, false) => 17,
        }
    }

    fn same_stream(&self, other: &FrameHeader) -> bool {
        self.version == other.version
            && self.layer == other.layer
            && self.sample_rate == other.sample_rate
    }

    fn layer_name(&self) -> &'static str {
        ["", "I", "II", "III"][self.layer as usize]
    }

    fn summary(&self) -> String {
        format!(
            "{} Layer {}, {} kbps, {} Hz, {}",
            self.version.name(),
            self.layer_name(),
            self.bitrate,
            self.sample_rate,
            channel_mode_name(self.channel_mode)
        )
    }
}

fn channel_mode_name(mode: u8) -> &'static str {
    match mode {
        0 => "Stereo",
        1 => "Joint stereo",
        2 => "Dual channel",
        _ => "Mono",
    }
}

fn mode_extension_name(header: &FrameHeader) -> String {
    let value = (header.raw >> 4) & 3;
    if header.channel_mode != 1 {
        return format!("{value} (unused)");
    }
    if header.layer == 3 {
        format!(
            "{value} (intensity stereo {}, MS stereo {})",
            if value & 1 != 0 { "on" } else { "off" },
            if value & 2 != 0 { "on" } else { "off" }
        )
    } else {
        format!("{value} (bands {}-31)", 4 + value * 4)
    }
}

fn emphasis_name(value: u32) -> &'static str {
    match value {
        0 => "none",
        1 => "50/15 ms",
        2 => "reserved",
        _ => "CCIT J.17",
    }
}

/// Returns the frame header at `offset` if it looks like part of a real
/// stream: consistent with `stream` (when known) and followed either by
/// another matching frame or by the end of the audio.
fn frame_at(
    data: &[u8],
    offset: usize,
    end: usize,
    stream: Option<&FrameHeader>,
) -> Option<FrameHeader> {
    let header = FrameHeader::parse(data, offset)?;
    if stream.is_some_and(|s| !s.same_stream(&header)) {
        return None;
    }
    let next = offset + header.frame_len;
    if next + 4 > end {
        return Some(header);
    }
    let following = FrameHeader::parse(data, next)?;
    header.same_stream(&following).then_some(header)
}

fn find_next_frame(data: &[u8], from: usize, end: usize, stream: Option<&FrameHeader>) -> usize {
    (from..end.saturating_sub(3))
        .find(|&i| match data[i] {
            0xFF => frame_at(data, i, end, stream).is_some(),
            b'I' => parse_id3v2_header(data, i).is_some(),
            _ => false,
        })
        .unwrap_or(end)
}

fn audio_block(data: &[u8], start: usize, end: usize) -> Block {
    let mut children = Vec::new();
    let mut offset = start;
    let mut stream: Option<FrameHeader> = None;
    let mut frame_count = 0usize;
    let mut audio_frames = 0u64;
    let mut audio_bytes = 0u64;
    let mut samples = 0u64;
    let mut vbr_kind: Option<&'static str> = None;
    let mut bitrates_vary = false;

    while offset < end {
        let header = match stream {
            // Mid-stream, trust any header consistent with the stream so far.
            Some(s) => FrameHeader::parse(data, offset).filter(|h| s.same_stream(h)),
            None => frame_at(data, offset, end, None),
        };

        let Some(header) = header else {
            if let Some(tag_header) = parse_id3v2_header(data, offset) {
                let tag = id3v2_block(data, offset, &tag_header);
                offset = tag.range.end as usize;
                children.push(tag);
                continue;
            }
            let next = find_next_frame(data, offset + 1, end, stream.as_ref());
            children.push(Block::leaf(
                format!("Unrecognized data ({} bytes)", next - offset),
                span(offset, next),
            ));
            offset = next;
            continue;
        };

        frame_count += 1;
        let frame_end = (offset + header.frame_len).min(end);
        let (frame, vbr) = frame_block(data, offset, frame_end, &header, frame_count);
        children.push(frame);

        if let Some(kind) = vbr {
            vbr_kind = Some(kind);
        } else {
            audio_frames += 1;
            audio_bytes += (frame_end - offset) as u64;
            samples += header.samples() as u64;
            if stream.is_some_and(|s| s.bitrate != header.bitrate) && frame_count > 2 {
                bitrates_vary = true;
            }
        }

        stream = Some(header);
        offset = frame_end;
    }

    let label = match stream {
        Some(s) => {
            let seconds = samples as f64 / s.sample_rate as f64;
            let bitrate = if seconds > 0.0 {
                format!("{:.0} kbps", audio_bytes as f64 * 8.0 / seconds / 1000.0)
            } else {
                format!("{} kbps", s.bitrate)
            };
            let mode = match (bitrates_vary, vbr_kind) {
                (true, _) => "VBR".to_string(),
                (false, Some(kind)) => format!("CBR, {kind} header"),
                (false, None) => "CBR".to_string(),
            };
            format!(
                "Audio: {audio_frames} frames, {} Layer {}, {} Hz, {bitrate} ({mode}), {}",
                s.version.name(),
                s.layer_name(),
                s.sample_rate,
                format_duration(seconds)
            )
        }
        None => "Audio: no MPEG frames found".to_string(),
    };

    Block::node(label, span(start, end), children)
}

/// Builds the block for one frame. The first frame may instead be a Xing,
/// Info or VBRI header frame; in that case the header's name is returned.
fn frame_block(
    data: &[u8],
    offset: usize,
    end: usize,
    header: &FrameHeader,
    number: usize,
) -> (Block, Option<&'static str>) {
    let mut children = vec![header_block(offset, header, number == 1)];
    let mut pos = offset + 4;

    if header.crc && pos + 2 <= end {
        let stored = read_u16_be(data, pos).unwrap_or(0);
        let side_end = pos + 2 + header.side_info_len();
        let label = if header.layer == 3 && side_end <= end {
            let covered = data[offset + 2..offset + 4]
                .iter()
                .chain(&data[pos + 2..side_end]);
            crc_label("CRC", stored, crc16_mpeg(covered))
        } else {
            format!("CRC: 0x{stored:04X}")
        };
        children.push(Block::leaf(label, span(pos, pos + 2)));
        pos += 2;
    }

    let mut vbr = None;
    if header.layer == 3 {
        let side_len = header.side_info_len();
        if pos + side_len <= end {
            let main_data_begin = match header.version {
                MpegVersion::V1 => read_u16_be(data, pos).unwrap_or(0) >> 7,
                _ => data[pos] as u16,
            };
            children.push(Block::leaf(
                format!("Side information (main_data_begin: {main_data_begin})"),
                span(pos, pos + side_len),
            ));
            pos += side_len;
        }

        if number == 1 {
            // Xing/Info normally follows the side info; LAME ignores the CRC
            // when placing it, so check both positions.
            let xing = [pos, offset + 4 + side_len]
                .into_iter()
                .find_map(|at| xing_block(data, at, offset, end));
            if let Some((block, block_end, kind)) = xing {
                children.push(block);
                pos = block_end;
                vbr = Some(kind);
            } else if let Some((block, block_end)) = vbri_block(data, offset + 36, end) {
                children.push(block);
                pos = block_end;
                vbr = Some("VBRI");
            }
        }
    }

    if pos < end {
        let label = if vbr.is_some() {
            "Padding"
        } else {
            "Audio data"
        };
        children.push(Block::leaf(label, span(pos, end)));
    }

    let truncated = if end - offset < header.frame_len {
        " (truncated)"
    } else {
        ""
    };
    let label = match vbr {
        Some(kind) => format!("Frame {number}: {kind} header{truncated}"),
        None => format!("Frame {number}: {}{truncated}", header.summary()),
    };
    (
        Block::node(label, span(offset, end), children).expanded_if(vbr.is_some()),
        vbr,
    )
}

/// The 4-byte frame header. Only `detailed` headers get a per-field
/// breakdown, since long files have many thousands of frames.
fn header_block(offset: usize, header: &FrameHeader, detailed: bool) -> Block {
    let label = format!("Header: 0x{:08X}", header.raw);
    if !detailed {
        return Block::leaf(label, span(offset, offset + 4));
    }

    let raw = header.raw;
    let byte1 = span(offset + 1, offset + 2);
    let byte2 = span(offset + 2, offset + 3);
    let byte3 = span(offset + 3, offset + 4);
    Block::node(
        label,
        span(offset, offset + 4),
        vec![
            Block::leaf("Frame sync: 0x7FF", span(offset, offset + 2)),
            Block::leaf(format!("Version: {}", header.version.name()), byte1),
            Block::leaf(format!("Layer: {}", header.layer_name()), byte1),
            Block::leaf(
                format!(
                    "Protection: {}",
                    if header.crc { "CRC present" } else { "none" }
                ),
                byte1,
            ),
            Block::leaf(
                format!(
                    "Bitrate: {} kbps (index {})",
                    header.bitrate,
                    (raw >> 12) & 0xF
                ),
                byte2,
            ),
            Block::leaf(format!("Sample rate: {} Hz", header.sample_rate), byte2),
            Block::leaf(format!("Padding: {}", yes_no(header.padding)), byte2),
            Block::leaf(format!("Private bit: {}", (raw >> 8) & 1), byte2),
            Block::leaf(
                format!("Channel mode: {}", channel_mode_name(header.channel_mode)),
                byte3,
            ),
            Block::leaf(
                format!("Mode extension: {}", mode_extension_name(header)),
                byte3,
            ),
            Block::leaf(format!("Copyright: {}", yes_no((raw >> 3) & 1 == 1)), byte3),
            Block::leaf(format!("Original: {}", yes_no((raw >> 2) & 1 == 1)), byte3),
            Block::leaf(format!("Emphasis: {}", emphasis_name(raw & 3)), byte3),
        ],
    )
    .expanded()
}

// ---------------------------------------------------------------------------
// Xing / Info / LAME / VBRI headers
// ---------------------------------------------------------------------------

fn xing_block(
    data: &[u8],
    start: usize,
    frame_start: usize,
    frame_end: usize,
) -> Option<(Block, usize, &'static str)> {
    let kind = match data.get(start..start + 4)? {
        b"Xing" => "Xing",
        b"Info" => "Info",
        _ => return None,
    };
    if start + 8 > frame_end {
        return None;
    }
    let flags = read_u32_be(data, start + 4)?;

    let mut children = vec![
        Block::leaf(format!("ID: {kind}"), span(start, start + 4)),
        Block::leaf(
            format!(
                "Flags: 0x{flags:08X}{}",
                flag_names(
                    flags,
                    &[(1, "frames"), (2, "bytes"), (4, "TOC"), (8, "quality")]
                )
            ),
            span(start + 4, start + 8),
        ),
    ];
    let mut pos = start + 8;
    let fields: [(u32, usize, &str); 4] = [
        (1, 4, "Frames"),
        (2, 4, "Bytes"),
        (4, 100, "TOC"),
        (8, 4, "Quality"),
    ];
    for (bit, len, name) in fields {
        if flags & bit == 0 || pos + len > frame_end {
            continue;
        }
        let label = if len == 4 {
            format!("{name}: {}", read_u32_be(data, pos)?)
        } else {
            format!("{name} (seek table, {len} entries)")
        };
        children.push(Block::leaf(label, span(pos, pos + len)));
        pos += len;
    }

    if let Some(lame) = lame_block(data, pos, frame_start, frame_end) {
        pos = lame.range.end as usize;
        children.push(lame);
    }

    let label = if kind == "Xing" {
        "Xing VBR header"
    } else {
        "Info header"
    };
    Some((
        Block::node(label, span(start, pos), children).expanded(),
        pos,
        kind,
    ))
}

fn vbr_method_name(method: u8) -> &'static str {
    match method {
        0 => "unknown",
        1 => "CBR",
        2 => "ABR",
        3 => "VBR (old/rh)",
        4 => "VBR (mtrh)",
        5 => "VBR (rh)",
        6 => "VBR (mt)",
        8 => "CBR (2-pass)",
        9 => "ABR (2-pass)",
        _ => "reserved",
    }
}

fn replay_gain_label(name: &str, value: u16) -> String {
    let kind = value >> 13;
    if kind == 0 {
        return format!("{name}: not set");
    }
    let originator = match (value >> 10) & 7 {
        0 => "unspecified",
        1 => "artist",
        2 => "user",
        3 => "automatic",
        4 => "RMS average",
        _ => "reserved",
    };
    let sign = if value & 0x200 != 0 { "-" } else { "+" };
    let db = (value & 0x1FF) as f32 / 10.0;
    format!("{name}: {sign}{db:.1} dB (set by {originator})")
}

fn lame_preset_name(preset: u16) -> String {
    match preset {
        0 => "none".to_string(),
        8..=320 => format!("ABR {preset}"),
        410..=500 if preset.is_multiple_of(10) => format!("V{}", (500 - preset) / 10),
        1000 => "r3mix".to_string(),
        1001 => "standard".to_string(),
        1002 => "extreme".to_string(),
        1003 => "insane".to_string(),
        1004 => "standard/fast".to_string(),
        1005 => "extreme/fast".to_string(),
        1006 => "medium".to_string(),
        1007 => "medium/fast".to_string(),
        _ => preset.to_string(),
    }
}

/// The 36-byte LAME extension that encoders in the LAME family (including
/// FFmpeg's Lavf/Lavc) append to the Xing/Info header.
fn lame_block(data: &[u8], start: usize, frame_start: usize, frame_end: usize) -> Option<Block> {
    const ENCODERS: [&[u8]; 5] = [b"LAME", b"Lavf", b"Lavc", b"L3.99", b"GOGO"];
    if start + 36 > frame_end {
        return None;
    }
    let tag = data.get(start..start + 36)?;
    if !ENCODERS.iter().any(|e| tag.starts_with(e)) {
        return None;
    }
    let at = |from: usize, to: usize| span(start + from, start + to);

    let peak = f32::from_be_bytes(tag[11..15].try_into().ok()?);
    let encoding_flags = (tag[19] >> 4) as u32;
    let delay = ((tag[21] as u16) << 4) | (tag[22] as u16 >> 4);
    let padding = (((tag[22] & 0x0F) as u16) << 8) | tag[23] as u16;
    let misc = tag[24];
    let stereo_mode = match (misc >> 2) & 7 {
        0 => "mono",
        1 => "stereo",
        2 => "dual channel",
        3 => "joint stereo",
        4 => "forced",
        5 => "auto",
        6 => "intensity",
        _ => "undefined",
    };
    let source_rate = match misc >> 6 {
        0 => "32 kHz or below",
        1 => "44.1 kHz",
        2 => "48 kHz",
        _ => "above 48 kHz",
    };
    let surround_preset = u16::from_be_bytes([tag[26], tag[27]]);
    let surround = match (surround_preset >> 11) & 7 {
        0 => "none",
        1 => "DPL",
        2 => "DPL2",
        3 => "Ambisonic",
        _ => "reserved",
    };
    let stored_crc = u16::from_be_bytes([tag[34], tag[35]]);
    let computed_crc = crc16_arc(&data[frame_start..start + 34]);

    let children = vec![
        Block::leaf(
            format!("Encoder: {}", display(&latin1(&tag[..9]))),
            at(0, 9),
        ),
        Block::leaf(format!("Tag revision: {}", tag[9] >> 4), at(9, 10)),
        Block::leaf(
            format!("VBR method: {}", vbr_method_name(tag[9] & 0x0F)),
            at(9, 10),
        ),
        Block::leaf(
            format!("Lowpass filter: {} Hz", tag[10] as u32 * 100),
            at(10, 11),
        ),
        Block::leaf(
            if peak == 0.0 {
                "Peak signal amplitude: unknown".to_string()
            } else {
                format!("Peak signal amplitude: {peak:.6}")
            },
            at(11, 15),
        ),
        Block::leaf(
            replay_gain_label("Track gain", u16::from_be_bytes([tag[15], tag[16]])),
            at(15, 17),
        ),
        Block::leaf(
            replay_gain_label("Album gain", u16::from_be_bytes([tag[17], tag[18]])),
            at(17, 19),
        ),
        Block::leaf(
            format!(
                "Encoding flags: 0x{encoding_flags:X}{}",
                flag_names(
                    encoding_flags,
                    &[
                        (1, "nspsytune"),
                        (2, "nssafejoint"),
                        (4, "nogap next"),
                        (8, "nogap previous")
                    ]
                )
            ),
            at(19, 20),
        ),
        Block::leaf(format!("ATH type: {}", tag[19] & 0x0F), at(19, 20)),
        Block::leaf(format!("Bitrate: {} kbps", tag[20]), at(20, 21)),
        Block::leaf(format!("Encoder delay: {delay} samples"), at(21, 23)),
        Block::leaf(format!("Encoder padding: {padding} samples"), at(22, 24)),
        Block::leaf(
            format!(
                "Misc: noise shaping {}, {stereo_mode}, unwise settings {}, source {source_rate}",
                misc & 3,
                yes_no(misc & 0x20 != 0)
            ),
            at(24, 25),
        ),
        Block::leaf(
            format!("MP3 gain: {:+.1} dB", tag[25] as i8 as f32 * 1.5),
            at(25, 26),
        ),
        Block::leaf(
            format!(
                "Surround: {surround}, preset: {}",
                lame_preset_name(surround_preset & 0x7FF)
            ),
            at(26, 28),
        ),
        Block::leaf(
            format!(
                "Music length: {} bytes",
                u32::from_be_bytes(tag[28..32].try_into().ok()?)
            ),
            at(28, 32),
        ),
        Block::leaf(
            format!(
                "Music CRC: 0x{:04X}",
                u16::from_be_bytes([tag[32], tag[33]])
            ),
            at(32, 34),
        ),
        Block::leaf(crc_label("Tag CRC", stored_crc, computed_crc), at(34, 36)),
    ];

    Some(Block::node("LAME extension", at(0, 36), children).expanded())
}

/// Fraunhofer's VBRI header, always 32 bytes after the side info of an
/// MPEG-1 frame (i.e. 36 bytes into the frame).
fn vbri_block(data: &[u8], start: usize, frame_end: usize) -> Option<(Block, usize)> {
    if data.get(start..start + 4)? != b"VBRI" || start + 26 > frame_end {
        return None;
    }
    let u16_at = |off: usize| read_u16_be(data, start + off).unwrap_or(0);
    let u32_at = |off: usize| read_u32_be(data, start + off).unwrap_or(0);
    let entries = u16_at(18) as usize;
    let entry_size = u16_at(22) as usize;
    let toc_end = (start + 26 + entries * entry_size).min(frame_end);

    let mut children = vec![
        Block::leaf("ID: VBRI", span(start, start + 4)),
        Block::leaf(
            format!("Version: {}", u16_at(4)),
            span(start + 4, start + 6),
        ),
        Block::leaf(format!("Delay: {}", u16_at(6)), span(start + 6, start + 8)),
        Block::leaf(
            format!("Quality: {}", u16_at(8)),
            span(start + 8, start + 10),
        ),
        Block::leaf(
            format!("Bytes: {}", u32_at(10)),
            span(start + 10, start + 14),
        ),
        Block::leaf(
            format!("Frames: {}", u32_at(14)),
            span(start + 14, start + 18),
        ),
        Block::leaf(
            format!("TOC entries: {entries}"),
            span(start + 18, start + 20),
        ),
        Block::leaf(
            format!("TOC scale factor: {}", u16_at(20)),
            span(start + 20, start + 22),
        ),
        Block::leaf(
            format!("TOC entry size: {entry_size} bytes"),
            span(start + 22, start + 24),
        ),
        Block::leaf(
            format!("Frames per TOC entry: {}", u16_at(24)),
            span(start + 24, start + 26),
        ),
    ];
    if toc_end > start + 26 {
        children.push(Block::leaf("TOC (seek table)", span(start + 26, toc_end)));
    }

    Some((
        Block::node("VBRI header", span(start, toc_end), children).expanded(),
        toc_end,
    ))
}

// ---------------------------------------------------------------------------
// ID3v2
// ---------------------------------------------------------------------------

struct Id3v2Header {
    major: u8,
    revision: u8,
    flags: u8,
    size: usize,
}

fn parse_id3v2_header(data: &[u8], offset: usize) -> Option<Id3v2Header> {
    let h = data.get(offset..offset + 10)?;
    if &h[..3] != ID3V2_MAGIC || !(2..=4).contains(&h[3]) || h[4] == 0xFF {
        return None;
    }
    Some(Id3v2Header {
        major: h[3],
        revision: h[4],
        flags: h[5],
        size: read_synchsafe(h, 6)? as usize,
    })
}

/// Tag-wide properties needed while parsing frames.
#[derive(Clone, Copy)]
struct TagContext {
    major: u8,
    unsync: bool,
}

/// A run of tag bytes, possibly with unsynchronisation undone. Because
/// resynchronising drops bytes, `offsets` records where each byte came from
/// in the file so blocks still point at the right raw bytes.
struct Mapped<'a> {
    bytes: Cow<'a, [u8]>,
    offsets: Option<Vec<usize>>,
    base: usize,
}

impl<'a> Mapped<'a> {
    fn plain(data: &'a [u8], start: usize, end: usize) -> Self {
        Self {
            bytes: Cow::Borrowed(&data[start..end]),
            offsets: None,
            base: start,
        }
    }

    /// Undoes ID3v2 unsynchronisation (0xFF 0x00 -> 0xFF). `file_offset`
    /// maps an index into `src` to its offset in the file.
    fn resync(src: &[u8], file_offset: impl Fn(usize) -> usize) -> Mapped<'static> {
        let mut bytes = Vec::with_capacity(src.len());
        let mut offsets = Vec::with_capacity(src.len());
        for (i, &b) in src.iter().enumerate() {
            if b == 0 && i > 0 && src[i - 1] == 0xFF {
                continue;
            }
            bytes.push(b);
            offsets.push(file_offset(i));
        }
        Mapped {
            bytes: Cow::Owned(bytes),
            offsets: Some(offsets),
            base: file_offset(0),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn file_offset(&self, index: usize) -> usize {
        match &self.offsets {
            None => self.base + index,
            Some(offsets) => match offsets.get(index) {
                Some(&o) => o,
                None => offsets.last().map_or(self.base, |&o| o + 1),
            },
        }
    }

    fn range(&self, start: usize, end: usize) -> ByteRange {
        if end <= start {
            let at = self.file_offset(start);
            span(at, at)
        } else {
            span(self.file_offset(start), self.file_offset(end - 1) + 1)
        }
    }
}

fn id3v2_block(data: &[u8], offset: usize, header: &Id3v2Header) -> Block {
    let major = header.major;
    let flags = header.flags;
    let has_footer = major == 4 && flags & 0x10 != 0;
    let body_start = offset + 10;
    let body_end = (body_start + header.size).min(data.len());
    let tag_end = (body_end + if has_footer { 10 } else { 0 }).min(data.len());

    let flag_list: &[(u32, &str)] = match major {
        2 => &[(0x80, "unsynchronisation"), (0x40, "compression")],
        3 => &[
            (0x80, "unsynchronisation"),
            (0x40, "extended header"),
            (0x20, "experimental"),
        ],
        _ => &[
            (0x80, "unsynchronisation"),
            (0x40, "extended header"),
            (0x20, "experimental"),
            (0x10, "footer"),
        ],
    };
    let mut children = vec![Block::node(
        "Header",
        span(offset, body_start),
        vec![
            Block::leaf("File identifier: ID3", span(offset, offset + 3)),
            Block::leaf(
                format!("Version: 2.{major}.{}", header.revision),
                span(offset + 3, offset + 5),
            ),
            Block::leaf(
                format!(
                    "Flags: 0x{flags:02X}{}",
                    flag_names(flags as u32, flag_list)
                ),
                span(offset + 5, offset + 6),
            ),
            Block::leaf(
                format!("Size: {} (synchsafe)", header.size),
                span(offset + 6, offset + 10),
            ),
        ],
    )];

    let unsync = flags & 0x80 != 0;
    // Before v2.4, unsynchronisation applies to the whole tag body and frame
    // sizes describe the resynchronised data. In v2.4 it's per frame.
    let body = if unsync && major < 4 {
        Mapped::resync(&data[body_start..body_end], |i| body_start + i)
    } else {
        Mapped::plain(data, body_start, body_end)
    };
    let ctx = TagContext { major, unsync };

    let mut pos = 0;
    if major == 2 && flags & 0x40 != 0 {
        children.push(Block::leaf(
            "Compressed tag data",
            body.range(0, body.len()),
        ));
        pos = body.len();
    } else if major >= 3
        && flags & 0x40 != 0
        && let Some((block, len)) = extended_header_block(&body, major)
    {
        children.push(block);
        pos = len;
    }
    children.extend(id3v2_frames(&body, pos, body.len(), ctx));

    if has_footer && tag_end >= body_end + 10 {
        children.push(Block::leaf("Footer", span(body_end, tag_end)));
    }

    Block::node(
        format!("ID3v2.{major} tag"),
        span(offset, tag_end),
        children,
    )
    .expanded()
}

fn extended_header_block(body: &Mapped, major: u8) -> Option<(Block, usize)> {
    let b = &body.bytes;
    // v2.3's size excludes the size field itself; v2.4's is synchsafe and
    // includes it.
    let len = if major == 3 {
        read_u32_be(b, 0)? as usize + 4
    } else {
        read_synchsafe(b, 0)? as usize
    };
    let len = len.clamp(4, body.len());

    let mut children = vec![Block::leaf(format!("Size: {len}"), body.range(0, 4))];
    if major == 3 && len >= 10 {
        let flags = read_u16_be(b, 4)?;
        children.push(Block::leaf(
            format!(
                "Flags: 0x{flags:04X}{}",
                flag_names(flags as u32, &[(0x8000, "CRC present")])
            ),
            body.range(4, 6),
        ));
        children.push(Block::leaf(
            format!("Padding size: {}", read_u32_be(b, 6)?),
            body.range(6, 10),
        ));
        if flags & 0x8000 != 0 && len >= 14 {
            children.push(Block::leaf(
                format!("CRC: 0x{:08X}", read_u32_be(b, 10)?),
                body.range(10, 14),
            ));
        }
    } else if major == 4 && len >= 6 {
        children.push(Block::leaf(
            format!("Flag bytes: {}", b[4]),
            body.range(4, 5),
        ));
        let flags = b[5] as u32;
        children.push(Block::leaf(
            format!(
                "Flags: 0x{flags:02X}{}",
                flag_names(
                    flags,
                    &[
                        (0x40, "tag is an update"),
                        (0x20, "CRC present"),
                        (0x10, "restrictions")
                    ]
                )
            ),
            body.range(5, 6),
        ));
        if len > 6 {
            children.push(Block::leaf("Flag data", body.range(6, len)));
        }
    }

    Some((
        Block::node("Extended header", body.range(0, len), children),
        len,
    ))
}

fn valid_frame_id(id: &[u8]) -> bool {
    id.iter()
        .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// v2.4 frame sizes should be synchsafe, but some writers (notably older
/// iTunes) stored plain integers. Pick whichever lands on a plausible next
/// frame.
fn v24_frame_size(b: &[u8], pos: usize, end: usize) -> usize {
    let plain = read_u32_be(b, pos + 4).unwrap_or(0) as usize;
    let Some(synchsafe) = read_synchsafe(b, pos + 4).map(|s| s as usize) else {
        return plain;
    };
    if synchsafe == plain {
        return synchsafe;
    }
    let lands_well = |size: usize| {
        let next = pos + 10 + size;
        next == end
            || (next < end && b[next] == 0)
            || (next + 4 <= end && valid_frame_id(&b[next..next + 4]))
    };
    if !lands_well(synchsafe) && lands_well(plain) {
        plain
    } else {
        synchsafe
    }
}

fn id3v2_frames(body: &Mapped, start: usize, end: usize, ctx: TagContext) -> Vec<Block> {
    let header_len = if ctx.major == 2 { 6 } else { 10 };
    let id_len = if ctx.major == 2 { 3 } else { 4 };
    let b = &body.bytes;

    let mut blocks = Vec::new();
    let mut pos = start;
    while pos < end {
        if b[pos] == 0 {
            blocks.push(Block::leaf(
                format!("Padding ({} bytes)", end - pos),
                body.range(pos, end),
            ));
            break;
        }
        if pos + header_len > end || !valid_frame_id(&b[pos..pos + id_len]) {
            blocks.push(Block::leaf(
                format!("Unrecognized data ({} bytes)", end - pos),
                body.range(pos, end),
            ));
            break;
        }
        let size = match ctx.major {
            2 => read_u24_be(b, pos + 3).unwrap_or(0) as usize,
            3 => read_u32_be(b, pos + 4).unwrap_or(0) as usize,
            _ => v24_frame_size(b, pos, end),
        };
        let frame_end = (pos + header_len).saturating_add(size).min(end);
        blocks.push(id3v2_frame(body, pos, frame_end, size, ctx));
        pos = frame_end;
    }
    blocks
}

fn id3v2_frame(body: &Mapped, pos: usize, end: usize, size: usize, ctx: TagContext) -> Block {
    let b = &body.bytes;
    let id_len = if ctx.major == 2 { 3 } else { 4 };
    let id = latin1(&b[pos..pos + id_len]);
    let size_end = pos + id_len * 2;

    let mut children = vec![
        Block::leaf(format!("Frame ID: {id}"), body.range(pos, pos + id_len)),
        Block::leaf(format!("Size: {size}"), body.range(pos + id_len, size_end)),
    ];

    let mut content_start = size_end;
    let mut decodable = true;
    let mut frame_unsync = false;
    if ctx.major >= 3 {
        let flags = read_u16_be(b, size_end).unwrap_or(0);
        let names: &[(u32, &str)] = if ctx.major == 3 {
            &[
                (0x8000, "discard on tag change"),
                (0x4000, "discard on file change"),
                (0x2000, "read only"),
                (0x0080, "compressed"),
                (0x0040, "encrypted"),
                (0x0020, "grouped"),
            ]
        } else {
            &[
                (0x4000, "discard on tag change"),
                (0x2000, "discard on file change"),
                (0x1000, "read only"),
                (0x0040, "grouped"),
                (0x0008, "compressed"),
                (0x0004, "encrypted"),
                (0x0002, "unsynchronised"),
                (0x0001, "data length indicator"),
            ]
        };
        children.push(Block::leaf(
            format!("Flags: 0x{flags:04X}{}", flag_names(flags as u32, names)),
            body.range(size_end, size_end + 2),
        ));
        content_start += 2;

        // Optional fields that sit between the header and the frame content,
        // in the order the spec lists them.
        let (compressed, encrypted, grouped, data_length) = if ctx.major == 3 {
            (
                flags & 0x0080 != 0,
                flags & 0x0040 != 0,
                flags & 0x0020 != 0,
                false,
            )
        } else {
            (
                flags & 0x0008 != 0,
                flags & 0x0004 != 0,
                flags & 0x0040 != 0,
                flags & 0x0001 != 0,
            )
        };
        let extras: &[(bool, &str, usize)] = if ctx.major == 3 {
            &[
                (compressed, "Decompressed size", 4),
                (encrypted, "Encryption method", 1),
                (grouped, "Group ID", 1),
            ]
        } else {
            &[
                (grouped, "Group ID", 1),
                (encrypted, "Encryption method", 1),
                (data_length, "Data length", 4),
            ]
        };
        for &(present, name, len) in extras {
            if !present || content_start + len > end {
                continue;
            }
            let value = match (len, ctx.major) {
                (1, _) => b[content_start] as u32,
                (_, 3) => read_u32_be(b, content_start).unwrap_or(0),
                _ => read_synchsafe(b, content_start).unwrap_or(0),
            };
            children.push(Block::leaf(
                format!("{name}: {value}"),
                body.range(content_start, content_start + len),
            ));
            content_start += len;
        }
        frame_unsync = ctx.major == 4 && (flags & 0x0002 != 0 || ctx.unsync);
        decodable = !compressed && !encrypted;
    }
    let content_start = content_start.min(end);

    let summary = if !decodable {
        if end > content_start {
            children.push(Block::leaf(
                "Frame data (compressed/encrypted)",
                body.range(content_start, end),
            ));
        }
        None
    } else if frame_unsync {
        let content = Mapped::resync(&b[content_start..end], |i| {
            body.file_offset(content_start + i)
        });
        let (fields, summary) = frame_fields(&id, &content, 0, content.len(), ctx);
        children.extend(fields);
        summary
    } else {
        let (fields, summary) = frame_fields(&id, body, content_start, end, ctx);
        children.extend(fields);
        summary
    };

    let mut label = match frame_name(&id) {
        Some(name) => format!("Frame {id} ({name})"),
        None => format!("Frame {id}"),
    };
    if let Some(summary) = summary.filter(|s| !s.is_empty()) {
        label.push_str(": ");
        label.push_str(&display(&summary));
    }
    Block::node(label, body.range(pos, end), children)
}

fn encoding_name(encoding: u8) -> &'static str {
    match encoding {
        0 => "ISO-8859-1",
        1 => "UTF-16",
        2 => "UTF-16BE",
        3 => "UTF-8",
        _ => "unknown",
    }
}

/// Finds the end of a null-terminated string in `bytes`. Returns the
/// string's length and the number of bytes consumed, including the
/// terminator (which is two bytes for UTF-16).
fn find_terminator(bytes: &[u8], encoding: u8) -> (usize, usize) {
    if encoding == 1 || encoding == 2 {
        (0..bytes.len() / 2)
            .map(|i| i * 2)
            .find(|&i| bytes[i] == 0 && bytes[i + 1] == 0)
            .map_or((bytes.len(), bytes.len()), |i| (i, i + 2))
    } else {
        bytes
            .iter()
            .position(|&c| c == 0)
            .map_or((bytes.len(), bytes.len()), |i| (i, i + 1))
    }
}

fn decode_text(encoding: u8, bytes: &[u8]) -> String {
    match encoding {
        1 | 2 => {
            let (big_endian, body) = match bytes {
                [0xFE, 0xFF, rest @ ..] => (true, rest),
                [0xFF, 0xFE, rest @ ..] => (false, rest),
                _ => (encoding == 2, bytes),
            };
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| {
                    if big_endian {
                        u16::from_be_bytes(c)
                    } else {
                        u16::from_le_bytes(c)
                    }
                })
                .collect();
            String::from_utf16_lossy(&units)
        }
        3 => String::from_utf8_lossy(bytes).into_owned(),
        _ => latin1(bytes),
    }
}

/// Walks the fields of a frame's content, emitting a leaf per field.
struct Cursor<'m, 'a> {
    m: &'m Mapped<'a>,
    pos: usize,
    end: usize,
    blocks: Vec<Block>,
}

impl<'m, 'a> Cursor<'m, 'a> {
    fn new(m: &'m Mapped<'a>, start: usize, end: usize) -> Self {
        Self {
            m,
            pos: start,
            end,
            blocks: Vec::new(),
        }
    }

    fn remaining(&self) -> &'m [u8] {
        let bytes: &'m [u8] = &self.m.bytes;
        &bytes[self.pos..self.end]
    }

    fn leaf(&mut self, label: String, len: usize) {
        let len = len.min(self.end - self.pos);
        if len > 0 {
            self.blocks
                .push(Block::leaf(label, self.m.range(self.pos, self.pos + len)));
            self.pos += len;
        }
    }

    fn byte(&mut self, label: impl FnOnce(u8) -> String) -> Option<u8> {
        let value = *self.remaining().first()?;
        self.leaf(label(value), 1);
        Some(value)
    }

    fn u32(&mut self, label: impl FnOnce(u32) -> String) -> Option<u32> {
        let value = read_u32_be(self.remaining(), 0)?;
        self.leaf(label(value), 4);
        Some(value)
    }

    fn encoding(&mut self) -> u8 {
        self.byte(|e| format!("Text encoding: {}", encoding_name(e)))
            .unwrap_or(0)
    }

    fn fixed_latin1(&mut self, name: &str, len: usize) -> String {
        let rest = self.remaining();
        let text = latin1(&rest[..len.min(rest.len())]);
        self.leaf(format!("{name}: {}", display(&text)), len);
        text
    }

    fn terminated(&mut self, name: &str, encoding: u8) -> String {
        let rest = self.remaining();
        let (text_len, consumed) = find_terminator(rest, encoding);
        let text = decode_text(encoding, &rest[..text_len]);
        self.leaf(format!("{name}: {}", display(&text)), consumed);
        text
    }

    /// Decodes the rest of the content as text. v2.4 allows several
    /// null-separated values, which are joined with " / ".
    fn text_rest(&mut self, name: &str, encoding: u8) -> String {
        let rest = self.remaining();
        let mut values = Vec::new();
        let mut at = 0;
        while at < rest.len() {
            let (text_len, consumed) = find_terminator(&rest[at..], encoding);
            values.push(decode_text(encoding, &rest[at..at + text_len]));
            at += consumed;
        }
        while values.last().is_some_and(|v| v.is_empty()) {
            values.pop();
        }
        let text = values.join(" / ");
        self.leaf(format!("{name}: {}", display(&text)), rest.len());
        text
    }

    fn data(&mut self, name: &str) -> usize {
        let len = self.end - self.pos;
        self.leaf(format!("{name} ({len} bytes)"), len);
        len
    }
}

fn picture_type_name(value: u8) -> &'static str {
    match value {
        0 => "Other",
        1 => "32x32 file icon",
        2 => "Other file icon",
        3 => "Front cover",
        4 => "Back cover",
        5 => "Leaflet page",
        6 => "Media",
        7 => "Lead artist",
        8 => "Artist",
        9 => "Conductor",
        10 => "Band",
        11 => "Composer",
        12 => "Lyricist",
        13 => "Recording location",
        14 => "During recording",
        15 => "During performance",
        16 => "Video screen capture",
        17 => "A bright coloured fish",
        18 => "Illustration",
        19 => "Band logotype",
        20 => "Publisher logotype",
        _ => "unknown",
    }
}

/// Expands ID3v1 genre references in TCON, e.g. "(17)" or "17" -> "Rock".
fn expand_genre(text: &str) -> String {
    let lookup = |n: &str| n.parse::<usize>().ok().and_then(|i| GENRES.get(i).copied());
    if let Some(name) = lookup(text) {
        return format!("{name} ({text})");
    }
    if let Some((reference, refinement)) =
        text.strip_prefix('(').and_then(|rest| rest.split_once(')'))
    {
        let name = match reference {
            "RX" => Some("Remix"),
            "CR" => Some("Cover"),
            n => lookup(n),
        };
        if let Some(name) = name {
            return if refinement.is_empty() {
                format!("{name} ({reference})")
            } else {
                format!("{refinement} ({name})")
            };
        }
    }
    text.to_string()
}

/// Parses a frame's content. Returns the field blocks and a short value
/// summary for the frame's label.
fn frame_fields(
    id: &str,
    m: &Mapped,
    start: usize,
    end: usize,
    ctx: TagContext,
) -> (Vec<Block>, Option<String>) {
    let mut c = Cursor::new(m, start, end);
    let summary = match id {
        "TXXX" | "TXX" => {
            let encoding = c.encoding();
            let description = c.terminated("Description", encoding);
            let value = c.text_rest("Value", encoding);
            Some(format!("{description}: {value}"))
        }
        "TCON" | "TCO" => {
            let encoding = c.encoding();
            let text = c.text_rest("Text", encoding);
            Some(
                text.split(" / ")
                    .map(expand_genre)
                    .collect::<Vec<_>>()
                    .join(" / "),
            )
        }
        _ if id.starts_with('T') => {
            let encoding = c.encoding();
            Some(c.text_rest("Text", encoding))
        }
        "WXXX" | "WXX" => {
            let encoding = c.encoding();
            let description = c.terminated("Description", encoding);
            let url = c.text_rest("URL", 0);
            Some(if description.is_empty() {
                url
            } else {
                format!("{description}: {url}")
            })
        }
        _ if id.starts_with('W') => Some(c.text_rest("URL", 0)),
        "COMM" | "COM" | "USLT" | "ULT" => {
            let encoding = c.encoding();
            c.fixed_latin1("Language", 3);
            let description = c.terminated("Description", encoding);
            let text = c.text_rest("Text", encoding);
            Some(if description.is_empty() {
                text
            } else {
                format!("{description}: {text}")
            })
        }
        "APIC" | "PIC" => {
            let encoding = c.encoding();
            let format = if id == "PIC" {
                c.fixed_latin1("Image format", 3)
            } else {
                c.terminated("MIME type", 0)
            };
            let picture_type = c
                .byte(|t| format!("Picture type: {} ({t})", picture_type_name(t)))
                .unwrap_or(0);
            c.terminated("Description", encoding);
            let len = c.data("Picture data");
            Some(format!(
                "{format}, {}, {len} bytes",
                picture_type_name(picture_type)
            ))
        }
        "GEOB" | "GEO" => {
            let encoding = c.encoding();
            let mime = c.terminated("MIME type", 0);
            let filename = c.terminated("Filename", encoding);
            let description = c.terminated("Description", encoding);
            let len = c.data("Object data");
            let name = if filename.is_empty() {
                description
            } else {
                filename
            };
            Some(if mime.is_empty() {
                format!("{name} ({len} bytes)")
            } else {
                format!("{name} ({mime}, {len} bytes)")
            })
        }
        "PRIV" => {
            let owner = c.terminated("Owner", 0);
            c.data("Private data");
            Some(owner)
        }
        "UFID" | "UFI" => {
            let owner = c.terminated("Owner", 0);
            let identifier = c.remaining();
            let printable = identifier
                .iter()
                .all(|b| b.is_ascii_graphic() || *b == b' ');
            if printable {
                c.fixed_latin1("Identifier", identifier.len());
            } else {
                c.data("Identifier");
            }
            Some(owner)
        }
        "POPM" | "POP" => {
            let email = c.terminated("Email", 0);
            let rating = c.byte(|r| format!("Rating: {r}/255")).unwrap_or(0);
            if !c.remaining().is_empty() {
                let count = c
                    .remaining()
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | b as u64);
                c.leaf(format!("Play count: {count}"), c.end - c.pos);
            }
            Some(format!("{email}, rating {rating}/255"))
        }
        "PCNT" | "CNT" => {
            let count = c
                .remaining()
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | b as u64);
            c.leaf(format!("Play count: {count}"), c.end - c.pos);
            Some(count.to_string())
        }
        "CHAP" => {
            let element = c.terminated("Element ID", 0);
            let start_ms = c.u32(|v| format!("Start time: {v} ms"));
            let end_ms = c.u32(|v| format!("End time: {v} ms"));
            c.u32(|v| format!("Start offset: 0x{v:08X}"));
            c.u32(|v| format!("End offset: 0x{v:08X}"));
            let (pos, end) = (c.pos, c.end);
            c.blocks.extend(id3v2_frames(m, pos, end, ctx));
            c.pos = end;
            Some(match (start_ms, end_ms) {
                (Some(s), Some(e)) => format!(
                    "{element} ({}-{})",
                    format_duration(s as f64 / 1000.0),
                    format_duration(e as f64 / 1000.0)
                ),
                _ => element,
            })
        }
        "CTOC" => {
            let element = c.terminated("Element ID", 0);
            c.byte(|f| {
                format!(
                    "Flags: 0x{f:02X}{}",
                    flag_names(f as u32, &[(2, "top level"), (1, "ordered")])
                )
            });
            let count = c.byte(|n| format!("Entry count: {n}")).unwrap_or(0);
            for i in 0..count {
                c.terminated(&format!("Child element {}", i + 1), 0);
            }
            let (pos, end) = (c.pos, c.end);
            c.blocks.extend(id3v2_frames(m, pos, end, ctx));
            c.pos = end;
            Some(format!("{element}, {count} entries"))
        }
        _ => {
            c.data("Frame data");
            None
        }
    };
    if c.pos < c.end {
        c.data("Unparsed data");
    }
    (c.blocks, summary)
}

fn frame_name(id: &str) -> Option<&'static str> {
    Some(match id {
        "AENC" | "CRA" => "Audio encryption",
        "APIC" | "PIC" => "Attached picture",
        "ASPI" => "Audio seek point index",
        "CHAP" => "Chapter",
        "COMM" | "COM" => "Comment",
        "COMR" => "Commercial",
        "CTOC" => "Table of contents",
        "ENCR" => "Encryption method registration",
        "EQU2" | "EQUA" | "EQU" => "Equalisation",
        "ETCO" | "ETC" => "Event timing codes",
        "GEOB" | "GEO" => "General encapsulated object",
        "GRID" => "Group identification registration",
        "GRP1" => "Grouping",
        "IPLS" | "IPL" => "Involved people",
        "LINK" | "LNK" => "Linked information",
        "MCDI" | "MCI" => "Music CD identifier",
        "MLLT" | "MLL" => "MPEG location lookup table",
        "MVIN" => "Movement number",
        "MVNM" => "Movement name",
        "OWNE" => "Ownership",
        "PCNT" | "CNT" => "Play counter",
        "POPM" | "POP" => "Popularimeter",
        "POSS" => "Position synchronisation",
        "PRIV" => "Private",
        "RBUF" | "BUF" => "Recommended buffer size",
        "RVA2" | "RVAD" | "RVA" => "Relative volume adjustment",
        "RVRB" | "REV" => "Reverb",
        "SEEK" => "Seek",
        "SIGN" => "Signature",
        "SYLT" | "SLT" => "Synchronised lyrics",
        "SYTC" | "STC" => "Synchronised tempo codes",
        "TALB" | "TAL" => "Album",
        "TBPM" | "TBP" => "BPM",
        "TCMP" | "TCP" => "Compilation",
        "TCOM" | "TCM" => "Composer",
        "TCON" | "TCO" => "Genre",
        "TCOP" | "TCR" => "Copyright",
        "TDAT" | "TDA" => "Date",
        "TDEN" => "Encoding time",
        "TDLY" | "TDY" => "Playlist delay",
        "TDOR" => "Original release time",
        "TDRC" => "Recording time",
        "TDRL" => "Release time",
        "TDTG" => "Tagging time",
        "TENC" | "TEN" => "Encoded by",
        "TEXT" | "TXT" => "Lyricist",
        "TFLT" | "TFT" => "File type",
        "TIME" | "TIM" => "Time",
        "TIPL" => "Involved people",
        "TIT1" | "TT1" => "Content group",
        "TIT2" | "TT2" => "Title",
        "TIT3" | "TT3" => "Subtitle",
        "TKEY" | "TKE" => "Initial key",
        "TLAN" | "TLA" => "Language",
        "TLEN" | "TLE" => "Length (ms)",
        "TMCL" => "Musician credits",
        "TMED" | "TMT" => "Media type",
        "TMOO" => "Mood",
        "TOAL" | "TOT" => "Original album",
        "TOFN" | "TOF" => "Original filename",
        "TOLY" | "TOL" => "Original lyricist",
        "TOPE" | "TOA" => "Original artist",
        "TORY" | "TOR" => "Original release year",
        "TOWN" => "File owner",
        "TPE1" | "TP1" => "Artist",
        "TPE2" | "TP2" => "Album artist",
        "TPE3" | "TP3" => "Conductor",
        "TPE4" | "TP4" => "Remixed by",
        "TPOS" | "TPA" => "Disc number",
        "TPRO" => "Produced notice",
        "TPUB" | "TPB" => "Publisher",
        "TRCK" | "TRK" => "Track number",
        "TRDA" | "TRD" => "Recording dates",
        "TRSN" => "Internet radio station name",
        "TRSO" => "Internet radio station owner",
        "TSIZ" | "TSI" => "Size",
        "TSO2" | "TS2" => "Album artist sort order",
        "TSOA" | "TSA" => "Album sort order",
        "TSOC" | "TSC" => "Composer sort order",
        "TSOP" | "TSP" => "Artist sort order",
        "TSOT" | "TST" => "Title sort order",
        "TSRC" | "TRC" => "ISRC",
        "TSSE" | "TSS" => "Encoder settings",
        "TSST" => "Set subtitle",
        "TXXX" | "TXX" => "User-defined text",
        "TYER" | "TYE" => "Year",
        "UFID" | "UFI" => "Unique file identifier",
        "USER" => "Terms of use",
        "USLT" | "ULT" => "Unsynchronised lyrics",
        "WCOM" | "WCM" => "Commercial information",
        "WCOP" | "WCP" => "Copyright information",
        "WFED" => "Podcast feed",
        "WOAF" | "WAF" => "Official audio file webpage",
        "WOAR" | "WAR" => "Official artist webpage",
        "WOAS" | "WAS" => "Official audio source webpage",
        "WORS" => "Official radio station homepage",
        "WPAY" => "Payment",
        "WPUB" | "WPB" => "Publisher webpage",
        "WXXX" | "WXX" => "User-defined URL",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Trailing tags: ID3v1, Enhanced TAG, APEv2, Lyrics3, appended ID3v2
// ---------------------------------------------------------------------------

/// Peels tags off the end of the file, which can appear in any order (most
/// commonly APEv2, then Lyrics3, then ID3v1). Returns the tags in file order
/// and where the audio before them ends. Nothing before `min` is considered.
fn trailing_tags(data: &[u8], min: usize) -> (Vec<Block>, usize) {
    let mut blocks = Vec::new();
    let mut end = data.len();

    loop {
        if end >= min + ID3V1_LEN && data[end - ID3V1_LEN..].starts_with(ID3V1_MAGIC) {
            let start = end - ID3V1_LEN;
            blocks.push(id3v1_block(data, start));
            end = start;
            if end >= min + ID3V1_ENHANCED_LEN
                && data[end - ID3V1_ENHANCED_LEN..].starts_with(ID3V1_ENHANCED_MAGIC)
            {
                let start = end - ID3V1_ENHANCED_LEN;
                blocks.push(enhanced_tag_block(data, start));
                end = start;
            }
        } else if let Some(start) = ape_tag_start(data, min, end) {
            blocks.push(ape_block(data, start, end));
            end = start;
        } else if let Some(start) = lyrics3v2_start(data, min, end) {
            blocks.push(lyrics3v2_block(data, start, end));
            end = start;
        } else if let Some(start) = lyrics3v1_start(data, min, end) {
            blocks.push(Block::node(
                "Lyrics3 v1 tag",
                span(start, end),
                vec![
                    Block::leaf("Begin: LYRICSBEGIN", span(start, start + 11)),
                    Block::leaf(
                        format!("Lyrics: {}", display(&latin1(&data[start + 11..end - 9]))),
                        span(start + 11, end - 9),
                    ),
                    Block::leaf("End: LYRICSEND", span(end - 9, end)),
                ],
            ));
            end = start;
        } else if let Some((start, header)) = appended_id3v2(data, min, end) {
            blocks.push(id3v2_block(data, start, &header));
            end = start;
        } else {
            break;
        }
    }

    blocks.reverse();
    (blocks, end)
}

fn id3v1_text(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    display(latin1(&bytes[..len]).trim_end())
}

fn id3v1_block(data: &[u8], start: usize) -> Block {
    let tag = &data[start..start + ID3V1_LEN];
    let at = |from: usize, to: usize| span(start + from, start + to);
    // ID3v1.1 steals the last two comment bytes for a zero and a track number.
    let v11 = tag[125] == 0 && tag[126] != 0;
    let genre = tag[127];
    let genre_name = GENRES.get(genre as usize).copied().unwrap_or("unknown");

    let mut children = vec![
        Block::leaf("Identifier: TAG", at(0, 3)),
        Block::leaf(format!("Title: {}", id3v1_text(&tag[3..33])), at(3, 33)),
        Block::leaf(format!("Artist: {}", id3v1_text(&tag[33..63])), at(33, 63)),
        Block::leaf(format!("Album: {}", id3v1_text(&tag[63..93])), at(63, 93)),
        Block::leaf(format!("Year: {}", id3v1_text(&tag[93..97])), at(93, 97)),
    ];
    if v11 {
        children.push(Block::leaf(
            format!("Comment: {}", id3v1_text(&tag[97..125])),
            at(97, 125),
        ));
        children.push(Block::leaf("Zero byte", at(125, 126)));
        children.push(Block::leaf(format!("Track: {}", tag[126]), at(126, 127)));
    } else {
        children.push(Block::leaf(
            format!("Comment: {}", id3v1_text(&tag[97..127])),
            at(97, 127),
        ));
    }
    children.push(Block::leaf(
        format!("Genre: {genre_name} ({genre})"),
        at(127, 128),
    ));

    let label = if v11 { "ID3v1.1 tag" } else { "ID3v1 tag" };
    Block::node(label, at(0, ID3V1_LEN), children).expanded()
}

fn enhanced_tag_block(data: &[u8], start: usize) -> Block {
    let tag = &data[start..start + ID3V1_ENHANCED_LEN];
    let at = |from: usize, to: usize| span(start + from, start + to);
    let speed = match tag[184] {
        0 => "unset",
        1 => "slow",
        2 => "medium",
        3 => "fast",
        4 => "hardcore",
        _ => "unknown",
    };
    Block::node(
        "Enhanced ID3v1 tag (TAG+)",
        at(0, ID3V1_ENHANCED_LEN),
        vec![
            Block::leaf("Identifier: TAG+", at(0, 4)),
            Block::leaf(format!("Title: {}", id3v1_text(&tag[4..64])), at(4, 64)),
            Block::leaf(
                format!("Artist: {}", id3v1_text(&tag[64..124])),
                at(64, 124),
            ),
            Block::leaf(
                format!("Album: {}", id3v1_text(&tag[124..184])),
                at(124, 184),
            ),
            Block::leaf(format!("Speed: {speed}"), at(184, 185)),
            Block::leaf(
                format!("Genre: {}", id3v1_text(&tag[185..215])),
                at(185, 215),
            ),
            Block::leaf(
                format!("Start time: {}", id3v1_text(&tag[215..221])),
                at(215, 221),
            ),
            Block::leaf(
                format!("End time: {}", id3v1_text(&tag[221..227])),
                at(221, 227),
            ),
        ],
    )
}

/// An APEv2 tag ends with a 32-byte footer; its size covers the items and
/// footer, plus a matching header when flag bit 31 is set.
fn ape_tag_start(data: &[u8], min: usize, end: usize) -> Option<usize> {
    if end < min + APE_FOOTER_LEN {
        return None;
    }
    let footer = end - APE_FOOTER_LEN;
    if !data[footer..].starts_with(APE_MAGIC) {
        return None;
    }
    let size = read_u32_le(data, footer + 12)? as usize;
    let flags = read_u32_le(data, footer + 20)?;
    let header_len = if flags & 0x8000_0000 != 0 {
        APE_FOOTER_LEN
    } else {
        0
    };
    let start = end.checked_sub(size.checked_add(header_len)?)?;
    (size >= APE_FOOTER_LEN && start >= min).then_some(start)
}

fn ape_header_block(data: &[u8], offset: usize, name: &str) -> Block {
    let version = read_u32_le(data, offset + 8).unwrap_or(0);
    let flags = read_u32_le(data, offset + 20).unwrap_or(0);
    Block::node(
        name,
        span(offset, offset + APE_FOOTER_LEN),
        vec![
            Block::leaf("Preamble: APETAGEX", span(offset, offset + 8)),
            Block::leaf(
                format!("Version: {}.{:03}", version / 1000, version % 1000),
                span(offset + 8, offset + 12),
            ),
            Block::leaf(
                format!("Tag size: {}", read_u32_le(data, offset + 12).unwrap_or(0)),
                span(offset + 12, offset + 16),
            ),
            Block::leaf(
                format!(
                    "Item count: {}",
                    read_u32_le(data, offset + 16).unwrap_or(0)
                ),
                span(offset + 16, offset + 20),
            ),
            Block::leaf(
                format!(
                    "Flags: 0x{flags:08X}{}",
                    flag_names(
                        flags,
                        &[
                            (0x8000_0000, "has header"),
                            (0x4000_0000, "no footer"),
                            (0x2000_0000, "is header"),
                            (0x1, "read only"),
                        ]
                    )
                ),
                span(offset + 20, offset + 24),
            ),
            Block::leaf("Reserved", span(offset + 24, offset + 32)),
        ],
    )
}

fn ape_block(data: &[u8], start: usize, end: usize) -> Block {
    let footer = end - APE_FOOTER_LEN;
    let mut children = Vec::new();
    let mut pos = start;
    if data[start..].starts_with(APE_MAGIC) && start + APE_FOOTER_LEN <= footer {
        children.push(ape_header_block(data, start, "Header"));
        pos += APE_FOOTER_LEN;
    }

    let count = read_u32_le(data, footer + 16).unwrap_or(0);
    for _ in 0..count {
        let Some((item, next)) = ape_item(data, pos, footer) else {
            break;
        };
        children.push(item);
        pos = next;
    }
    if pos < footer {
        children.push(Block::leaf("Unrecognized data", span(pos, footer)));
    }
    children.push(ape_header_block(data, footer, "Footer"));

    let version = read_u32_le(data, footer + 8).unwrap_or(0);
    let label = if version >= 2000 {
        "APEv2 tag"
    } else {
        "APEv1 tag"
    };
    Block::node(label, span(start, end), children).expanded()
}

fn ape_item(data: &[u8], pos: usize, end: usize) -> Option<(Block, usize)> {
    let value_len = read_u32_le(data, pos)? as usize;
    let flags = read_u32_le(data, pos + 4)?;
    let key_start = pos + 8;
    let key_len = data.get(key_start..end)?.iter().position(|&b| b == 0)?;
    let key = latin1(&data[key_start..key_start + key_len]);
    let value_start = key_start + key_len + 1;
    let value_end = value_start.checked_add(value_len)?;
    if value_end > end {
        return None;
    }
    let value = &data[value_start..value_end];

    let (kind, summary) = match (flags >> 1) & 3 {
        0 => (
            "UTF-8 text",
            String::from_utf8_lossy(value)
                .split('\0')
                .collect::<Vec<_>>()
                .join(" / "),
        ),
        1 => ("binary", format!("{value_len} bytes")),
        2 => (
            "external locator",
            String::from_utf8_lossy(value).into_owned(),
        ),
        _ => ("reserved", format!("{value_len} bytes")),
    };
    let block = Block::node(
        format!("Item {key}: {}", display(&summary)),
        span(pos, value_end),
        vec![
            Block::leaf(format!("Value size: {value_len}"), span(pos, pos + 4)),
            Block::leaf(
                format!(
                    "Flags: 0x{flags:08X} ({kind}{})",
                    if flags & 1 != 0 { ", read only" } else { "" }
                ),
                span(pos + 4, pos + 8),
            ),
            Block::leaf(format!("Key: {key}"), span(key_start, value_start)),
            Block::leaf("Value", span(value_start, value_end)),
        ],
    );
    Some((block, value_end))
}

/// Lyrics3 v2 ends with a 6-digit size (counting from LYRICSBEGIN) and
/// "LYRICS200".
fn lyrics3v2_start(data: &[u8], min: usize, end: usize) -> Option<usize> {
    if end < min + 15 || !data[..end].ends_with(LYRICS3V2_END) {
        return None;
    }
    let digits = std::str::from_utf8(&data[end - 15..end - 9]).ok()?;
    let size: usize = digits.parse().ok()?;
    let start = (end - 15).checked_sub(size)?;
    (start >= min && data[start..].starts_with(LYRICS3_BEGIN)).then_some(start)
}

fn lyrics3v2_block(data: &[u8], start: usize, end: usize) -> Block {
    let fields_end = end - 15;
    let mut children = vec![Block::leaf("Begin: LYRICSBEGIN", span(start, start + 11))];
    let mut pos = start + 11;
    while pos + 8 <= fields_end {
        let id = latin1(&data[pos..pos + 3]);
        let Some(len) = std::str::from_utf8(&data[pos + 3..pos + 8])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            break;
        };
        let value_end = (pos + 8 + len).min(fields_end);
        let name = match id.as_str() {
            "IND" => "Indications",
            "LYR" => "Lyrics",
            "INF" => "Information",
            "AUT" => "Author",
            "EAL" => "Album",
            "EAR" => "Artist",
            "ETT" => "Title",
            "IMG" => "Image links",
            _ => "Unknown field",
        };
        children.push(Block::node(
            format!(
                "Field {id} ({name}): {}",
                display(&latin1(&data[pos + 8..value_end]))
            ),
            span(pos, value_end),
            vec![
                Block::leaf(format!("Field ID: {id}"), span(pos, pos + 3)),
                Block::leaf(format!("Size: {len}"), span(pos + 3, pos + 8)),
                Block::leaf("Value", span(pos + 8, value_end)),
            ],
        ));
        pos = value_end;
    }
    if pos < fields_end {
        children.push(Block::leaf("Unrecognized data", span(pos, fields_end)));
    }
    children.push(Block::leaf(
        format!("Size: {}", latin1(&data[fields_end..end - 9])),
        span(fields_end, end - 9),
    ));
    children.push(Block::leaf("End: LYRICS200", span(end - 9, end)));
    Block::node("Lyrics3 v2 tag", span(start, end), children).expanded()
}

fn lyrics3v1_start(data: &[u8], min: usize, end: usize) -> Option<usize> {
    if end < min + 20 || !data[..end].ends_with(LYRICS3V1_END) {
        return None;
    }
    let search_from = end.saturating_sub(LYRICS3V1_MAX_LEN + 20).max(min);
    data[search_from..end - 9]
        .windows(LYRICS3_BEGIN.len())
        .rposition(|w| w == LYRICS3_BEGIN)
        .map(|i| search_from + i)
}

/// ID3v2.4 tags may be appended to the file, ending with a "3DI" footer.
fn appended_id3v2(data: &[u8], min: usize, end: usize) -> Option<(usize, Id3v2Header)> {
    if end < min + 20 || !data[end - 10..].starts_with(ID3V2_FOOTER_MAGIC) {
        return None;
    }
    let size = read_synchsafe(data, end - 4)? as usize;
    let start = end.checked_sub(size + 20)?;
    if start < min {
        return None;
    }
    parse_id3v2_header(data, start).map(|h| (start, h))
}

/// ID3v1 genres, including the Winamp extensions.
#[rustfmt::skip]
const GENRES: [&str; 192] = [
    "Blues", "Classic Rock", "Country", "Dance", "Disco", "Funk", "Grunge", "Hip-Hop",
    "Jazz", "Metal", "New Age", "Oldies", "Other", "Pop", "R&B", "Rap", "Reggae", "Rock",
    "Techno", "Industrial", "Alternative", "Ska", "Death Metal", "Pranks", "Soundtrack",
    "Euro-Techno", "Ambient", "Trip-Hop", "Vocal", "Jazz+Funk", "Fusion", "Trance",
    "Classical", "Instrumental", "Acid", "House", "Game", "Sound Clip", "Gospel", "Noise",
    "Alternative Rock", "Bass", "Soul", "Punk", "Space", "Meditative", "Instrumental Pop",
    "Instrumental Rock", "Ethnic", "Gothic", "Darkwave", "Techno-Industrial", "Electronic",
    "Pop-Folk", "Eurodance", "Dream", "Southern Rock", "Comedy", "Cult", "Gangsta",
    "Top 40", "Christian Rap", "Pop/Funk", "Jungle", "Native American", "Cabaret",
    "New Wave", "Psychedelic", "Rave", "Showtunes", "Trailer", "Lo-Fi", "Tribal",
    "Acid Punk", "Acid Jazz", "Polka", "Retro", "Musical", "Rock & Roll", "Hard Rock",
    "Folk", "Folk-Rock", "National Folk", "Swing", "Fast Fusion", "Bebop", "Latin",
    "Revival", "Celtic", "Bluegrass", "Avantgarde", "Gothic Rock", "Progressive Rock",
    "Psychedelic Rock", "Symphonic Rock", "Slow Rock", "Big Band", "Chorus",
    "Easy Listening", "Acoustic", "Humour", "Speech", "Chanson", "Opera", "Chamber Music",
    "Sonata", "Symphony", "Booty Bass", "Primus", "Porn Groove", "Satire", "Slow Jam",
    "Club", "Tango", "Samba", "Folklore", "Ballad", "Power Ballad", "Rhythmic Soul",
    "Freestyle", "Duet", "Punk Rock", "Drum Solo", "A Cappella", "Euro-House", "Dance Hall",
    "Goa", "Drum & Bass", "Club-House", "Hardcore Techno", "Terror", "Indie", "BritPop",
    "Afro-Punk", "Polsk Punk", "Beat", "Christian Gangsta Rap", "Heavy Metal",
    "Black Metal", "Crossover", "Contemporary Christian", "Christian Rock", "Merengue",
    "Salsa", "Thrash Metal", "Anime", "JPop", "Synthpop", "Abstract", "Art Rock", "Baroque",
    "Bhangra", "Big Beat", "Breakbeat", "Chillout", "Downtempo", "Dub", "EBM", "Eclectic",
    "Electro", "Electroclash", "Emo", "Experimental", "Garage", "Global", "IDM", "Illbient",
    "Industro-Goth", "Jam Band", "Krautrock", "Leftfield", "Lounge", "Math Rock",
    "New Romantic", "Nu-Breakz", "Post-Punk", "Post-Rock", "Psytrance", "Shoegaze",
    "Space Rock", "Trop Rock", "World Music", "Neoclassical", "Audiobook", "Audio Theatre",
    "Neue Deutsche Welle", "Podcast", "Indie Rock", "G-Funk", "Dubstep", "Garage Rock",
    "Psybient",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// MPEG-1 Layer III, 128 kbps, 44.1 kHz, joint stereo (MS), no CRC: 417 bytes.
    const HEADER_128K: u32 = 0xFFFB_9064;
    /// Same, with the padding bit set: 418 bytes.
    const HEADER_128K_PADDED: u32 = 0xFFFB_9264;

    fn frame(header: u32) -> Vec<u8> {
        let len = FrameHeader::parse(&header.to_be_bytes(), 0)
            .unwrap()
            .frame_len;
        let mut bytes = header.to_be_bytes().to_vec();
        bytes.resize(len, 0x55);
        bytes
    }

    fn frames(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|i| {
                frame(if i % 2 == 0 {
                    HEADER_128K
                } else {
                    HEADER_128K_PADDED
                })
            })
            .collect()
    }

    fn synchsafe(n: usize) -> [u8; 4] {
        [
            (n >> 21) as u8 & 0x7F,
            (n >> 14) as u8 & 0x7F,
            (n >> 7) as u8 & 0x7F,
            n as u8 & 0x7F,
        ]
    }

    fn id3_frame(major: u8, id: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = id.to_vec();
        if major == 4 {
            bytes.extend_from_slice(&synchsafe(payload.len()));
        } else {
            bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn id3_tag(major: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![b'I', b'D', b'3', major, 0, flags];
        bytes.extend_from_slice(&synchsafe(body.len()));
        bytes.extend_from_slice(body);
        bytes
    }

    fn find<'a>(blocks: &'a [Block], prefix: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label.starts_with(prefix))
            .unwrap_or_else(|| {
                panic!(
                    "block {prefix:?} not found; have {:?}",
                    blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
                )
            })
    }

    fn has(block: &Block, label: &str) -> bool {
        block.children.iter().any(|b| b.label == label)
    }

    #[test]
    fn matches_id3_tag_or_consecutive_frames() {
        assert!(Mp3Dissector.matches(&id3_tag(3, 0, &[0; 16])));
        assert!(Mp3Dissector.matches(&frames(3)));
        assert!(Mp3Dissector.matches(&frame(HEADER_128K)));
    }

    #[test]
    fn does_not_match_non_mp3_data() {
        assert!(!Mp3Dissector.matches(b""));
        assert!(!Mp3Dissector.matches(b"not an mp3 file"));
        assert!(!Mp3Dissector.matches(b"ID3\x09\x00\x00\x00\x00\x00\x00"));
        // A lone sync word followed by something that isn't a frame.
        let mut data = frame(HEADER_128K);
        data.extend_from_slice(&[0u8; 64]);
        assert!(!Mp3Dissector.matches(&data));
    }

    #[test]
    fn computes_frame_lengths() {
        let len = |raw: u32| FrameHeader::parse(&raw.to_be_bytes(), 0).unwrap().frame_len;
        assert_eq!(len(HEADER_128K), 417);
        assert_eq!(len(HEADER_128K_PADDED), 418);
        assert_eq!(len(0xFFF3_48C4), 144); // MPEG-2 Layer III, 32 kbps, 16 kHz
        assert_eq!(len(0xFFFD_A004), 626); // MPEG-1 Layer II, 192 kbps, 44.1 kHz
        assert_eq!(len(0xFFFF_9004), 312); // MPEG-1 Layer I, 288 kbps, 44.1 kHz
        assert!(FrameHeader::parse(&0xFFFB_0064u32.to_be_bytes(), 0).is_none()); // free format
        assert!(FrameHeader::parse(&0xFFF9_9064u32.to_be_bytes(), 0).is_none()); // reserved layer
    }

    #[test]
    fn dissects_frames_and_header_fields() {
        let data = frames(4);
        let blocks = Mp3Dissector.dissect(&data);
        assert_eq!(blocks.len(), 1);

        let audio = &blocks[0];
        assert!(
            audio
                .label
                .starts_with("Audio: 4 frames, MPEG-1 Layer III, 44100 Hz")
        );
        assert!(audio.label.contains("(CBR)"));
        assert_eq!(audio.children.len(), 4);

        let first = &audio.children[0];
        assert_eq!(
            first.label,
            "Frame 1: MPEG-1 Layer III, 128 kbps, 44100 Hz, Joint stereo"
        );
        assert_eq!(first.range, ByteRange::new(0, 417));
        let header = find(&first.children, "Header: 0xFFFB9064");
        assert!(has(header, "Bitrate: 128 kbps (index 9)"));
        assert!(has(
            header,
            "Mode extension: 2 (intensity stereo off, MS stereo on)"
        ));
        assert!(has(first, "Side information (main_data_begin: 170)")); // 0x5555 >> 7
        assert_eq!(
            find(&first.children, "Audio data").range,
            ByteRange::new(36, 417)
        );

        // Later frames only get a summary header leaf.
        let second = &audio.children[1];
        assert_eq!(second.range, ByteRange::new(417, 835));
        assert!(!find(&second.children, "Header").expandable);
    }

    #[test]
    fn verifies_layer3_crc() {
        let mut data = frame(0xFFFA_9064); // protected
        data.extend(frames(2));
        let crc = crc16_mpeg(data[2..4].iter().chain(&data[6..38]));
        data[4..6].copy_from_slice(&crc.to_be_bytes());

        let blocks = Mp3Dissector.dissect(&data);
        let first = &blocks[0].children[0];
        assert!(has(first, &format!("CRC: 0x{crc:04X} (valid)")));
        assert_eq!(
            find(&first.children, "Side information").range,
            ByteRange::new(6, 38)
        );

        data[10] ^= 0xFF;
        let blocks = Mp3Dissector.dissect(&data);
        assert!(
            find(&blocks[0].children[0].children, "CRC")
                .label
                .contains("invalid")
        );
    }

    #[test]
    fn parses_xing_and_lame_headers() {
        let mut info = frame(HEADER_128K);
        let xing = 36;
        info[4..xing].fill(0);
        info[xing..xing + 4].copy_from_slice(b"Info");
        info[xing + 4..xing + 8].copy_from_slice(&0x0Fu32.to_be_bytes());
        info[xing + 8..xing + 12].copy_from_slice(&3u32.to_be_bytes());
        info[xing + 12..xing + 16].copy_from_slice(&1253u32.to_be_bytes());
        let lame = xing + 120;
        info[lame..lame + 9].copy_from_slice(b"LAME3.100");
        info[lame + 9] = 0x01; // revision 0, CBR
        info[lame + 21..lame + 24].copy_from_slice(&[0x24, 0x02, 0xF4]); // delay 576, padding 756
        let crc = crc16_arc(&info[..lame + 34]);
        info[lame + 34..lame + 36].copy_from_slice(&crc.to_be_bytes());

        let mut data = info;
        data.extend(frames(3));
        let blocks = Mp3Dissector.dissect(&data);
        let audio = &blocks[0];
        assert!(audio.label.starts_with("Audio: 3 frames"));
        assert!(audio.label.contains("(CBR, Info header)"));

        let first = &audio.children[0];
        assert_eq!(first.label, "Frame 1: Info header");
        let header = find(&first.children, "Info header");
        assert!(has(header, "Frames: 3"));
        assert!(has(header, "Bytes: 1253"));
        assert!(has(header, "TOC (seek table, 100 entries)"));
        let lame = find(&header.children, "LAME extension");
        assert_eq!(lame.range, ByteRange::new(156, 192));
        assert!(has(lame, "Encoder: LAME3.100"));
        assert!(has(lame, "VBR method: CBR"));
        assert!(has(lame, "Encoder delay: 576 samples"));
        assert!(has(lame, "Encoder padding: 756 samples"));
        assert!(has(lame, &format!("Tag CRC: 0x{crc:04X} (valid)")));
        assert_eq!(
            find(&first.children, "Padding").range,
            ByteRange::new(192, 417)
        );
    }

    #[test]
    fn parses_vbri_header() {
        let mut vbri = frame(HEADER_128K);
        vbri[36..40].copy_from_slice(b"VBRI");
        vbri[50..54].copy_from_slice(&3u32.to_be_bytes()); // frames
        vbri[54..56].copy_from_slice(&2u16.to_be_bytes()); // TOC entries
        vbri[58..60].copy_from_slice(&2u16.to_be_bytes()); // entry size
        let mut data = vbri;
        data.extend(frames(3));

        let blocks = Mp3Dissector.dissect(&data);
        let first = &blocks[0].children[0];
        assert_eq!(first.label, "Frame 1: VBRI header");
        let header = find(&first.children, "VBRI header");
        assert!(has(header, "Frames: 3"));
        assert_eq!(
            find(&header.children, "TOC (seek").range,
            ByteRange::new(62, 66)
        );
    }

    #[test]
    fn parses_id3v23_frames() {
        let mut body = Vec::new();
        body.extend(id3_frame(3, b"TIT2", b"\x00Song"));
        // UTF-16 with a little-endian BOM.
        body.extend(id3_frame(
            3,
            b"TPE1",
            &[1, 0xFF, 0xFE, b'A', 0, b'r', 0, b't', 0],
        ));
        body.extend(id3_frame(3, b"TCON", b"\x00(17)"));
        body.extend(id3_frame(3, b"COMM", b"\x00engdesc\x00Hello"));
        body.extend(id3_frame(3, b"APIC", b"\x00image/png\x00\x03\x00PNGDATA"));
        body.extend(id3_frame(3, b"TXXX", b"\x00Key\x00Value"));
        body.extend(id3_frame(3, b"XYZW", b"opaque"));
        body.extend([0u8; 20]);
        let mut data = id3_tag(3, 0, &body);
        let tag_len = data.len() as u64;
        data.extend(frames(2));

        let blocks = Mp3Dissector.dissect(&data);
        let tag = find(&blocks, "ID3v2.3 tag");
        assert_eq!(tag.range, ByteRange::new(0, tag_len));
        assert!(has(find(&tag.children, "Header"), "Version: 2.3.0"));

        let title = find(&tag.children, "Frame TIT2");
        assert_eq!(title.label, "Frame TIT2 (Title): Song");
        assert_eq!(title.range, ByteRange::new(10, 25));
        assert!(has(title, "Text encoding: ISO-8859-1"));
        assert_eq!(
            find(&title.children, "Text: ").range,
            ByteRange::new(21, 25)
        );

        assert_eq!(
            find(&tag.children, "Frame TPE1").label,
            "Frame TPE1 (Artist): Art"
        );
        assert_eq!(
            find(&tag.children, "Frame TCON").label,
            "Frame TCON (Genre): Rock (17)"
        );
        let comment = find(&tag.children, "Frame COMM");
        assert_eq!(comment.label, "Frame COMM (Comment): desc: Hello");
        assert!(has(comment, "Language: eng"));

        let picture = find(&tag.children, "Frame APIC");
        assert_eq!(
            picture.label,
            "Frame APIC (Attached picture): image/png, Front cover, 7 bytes"
        );
        assert!(has(picture, "Picture type: Front cover (3)"));
        assert!(has(picture, "Picture data (7 bytes)"));

        assert_eq!(
            find(&tag.children, "Frame TXXX").label,
            "Frame TXXX (User-defined text): Key: Value"
        );
        assert!(has(
            find(&tag.children, "Frame XYZW"),
            "Frame data (6 bytes)"
        ));
        assert_eq!(find(&tag.children, "Padding").label, "Padding (20 bytes)");

        assert!(find(&blocks, "Audio").label.starts_with("Audio: 2 frames"));
    }

    #[test]
    fn parses_id3v24_synchsafe_and_multi_value_frames() {
        let long_title = vec![b'x'; 200]; // size needs more than 7 bits
        let mut payload = vec![3u8];
        payload.extend(&long_title);
        let mut body = id3_frame(4, b"TIT2", &payload);
        body.extend(id3_frame(4, b"TPE1", b"\x03One\x00Two"));
        let data = id3_tag(4, 0, &body);

        let blocks = Mp3Dissector.dissect(&data);
        let tag = find(&blocks, "ID3v2.4 tag");
        let title = find(&tag.children, "Frame TIT2");
        assert!(has(title, "Size: 201"));
        assert_eq!(title.range, ByteRange::new(10, 10 + 10 + 201));
        assert!(title.label.ends_with('…'));
        assert_eq!(
            find(&tag.children, "Frame TPE1").label,
            "Frame TPE1 (Artist): One / Two"
        );
    }

    #[test]
    fn falls_back_to_plain_sizes_in_buggy_v24_tags() {
        // Some writers store plain big-endian sizes in v2.4 tags.
        let mut payload = vec![0u8];
        payload.extend([b'y'; 199]);
        let mut body = b"TIT2".to_vec();
        body.extend((payload.len() as u32).to_be_bytes());
        body.extend([0, 0]);
        body.extend(&payload);
        body.extend(id3_frame(4, b"TALB", b"\x00Album"));
        let data = id3_tag(4, 0, &body);

        let blocks = Mp3Dissector.dissect(&data);
        let tag = find(&blocks, "ID3v2.4 tag");
        assert_eq!(
            find(&tag.children, "Frame TIT2").range,
            ByteRange::new(10, 220)
        );
        assert_eq!(
            find(&tag.children, "Frame TALB").label,
            "Frame TALB (Album): Album"
        );
    }

    #[test]
    fn undoes_tag_level_unsynchronisation() {
        // PRIV data 0xFF 0xE0 must be stored as 0xFF 0x00 0xE0.
        let mut body = id3_frame(3, b"PRIV", b"me\x00\xFF\xE0");
        body.insert(body.len() - 1, 0);
        body.extend(id3_frame(3, b"TIT2", b"\x00After"));
        let data = id3_tag(3, 0x80, &body);

        let blocks = Mp3Dissector.dissect(&data);
        let tag = find(&blocks, "ID3v2.3 tag");
        assert!(has(
            find(&tag.children, "Header"),
            "Flags: 0x80 (unsynchronisation)"
        ));
        let private = find(&tag.children, "Frame PRIV");
        // 10 header bytes + 5 data bytes, plus the stuffed zero.
        assert_eq!(private.range, ByteRange::new(10, 26));
        assert_eq!(
            find(&private.children, "Private data").range,
            ByteRange::new(23, 26)
        );
        assert_eq!(
            find(&tag.children, "Frame TIT2").label,
            "Frame TIT2 (Title): After"
        );
    }

    #[test]
    fn parses_chapter_sub_frames() {
        let mut chap = b"ch1\x00".to_vec();
        chap.extend(1000u32.to_be_bytes());
        chap.extend(61500u32.to_be_bytes());
        chap.extend([0xFF; 8]);
        chap.extend(id3_frame(4, b"TIT2", b"\x03Intro"));
        let data = id3_tag(4, 0, &id3_frame(4, b"CHAP", &chap));

        let blocks = Mp3Dissector.dissect(&data);
        let chapter = find(&find(&blocks, "ID3v2.4 tag").children, "Frame CHAP");
        assert_eq!(
            chapter.label,
            "Frame CHAP (Chapter): ch1 (0:01.000-1:01.500)"
        );
        assert!(has(chapter, "End time: 61500 ms"));
        assert_eq!(
            find(&chapter.children, "Frame TIT2").label,
            "Frame TIT2 (Title): Intro"
        );
    }

    fn id3v1(track: u8, genre: u8) -> Vec<u8> {
        let field = |text: &[u8], len: usize| {
            let mut bytes = text.to_vec();
            bytes.resize(len, 0);
            bytes
        };
        let mut tag = b"TAG".to_vec();
        tag.extend(field(b"Title", 30));
        tag.extend(field(b"Artist", 30));
        tag.extend(field(b"Album", 30));
        tag.extend(b"2001");
        tag.extend(field(b"Comment", 28));
        tag.extend([0, track, genre]);
        tag
    }

    fn ape_tag(items: &[(&str, &str)]) -> Vec<u8> {
        let mut item_bytes = Vec::new();
        for (key, value) in items {
            item_bytes.extend((value.len() as u32).to_le_bytes());
            item_bytes.extend(0u32.to_le_bytes());
            item_bytes.extend(key.as_bytes());
            item_bytes.push(0);
            item_bytes.extend(value.as_bytes());
        }
        let header = |flags: u32| {
            let mut bytes = b"APETAGEX".to_vec();
            bytes.extend(2000u32.to_le_bytes());
            bytes.extend((item_bytes.len() as u32 + 32).to_le_bytes());
            bytes.extend((items.len() as u32).to_le_bytes());
            bytes.extend(flags.to_le_bytes());
            bytes.extend([0; 8]);
            bytes
        };
        let mut tag = header(0xA000_0000);
        tag.extend(&item_bytes);
        tag.extend(header(0x8000_0000));
        tag
    }

    fn lyrics3v2(lyrics: &str) -> Vec<u8> {
        let mut tag = b"LYRICSBEGIN".to_vec();
        tag.extend(b"IND00002".iter().chain(b"10"));
        tag.extend(format!("LYR{:05}{lyrics}", lyrics.len()).as_bytes());
        tag.extend(format!("{:06}LYRICS200", tag.len()).as_bytes());
        tag
    }

    #[test]
    fn parses_trailing_tags() {
        let mut data = frames(3);
        let audio_end = data.len() as u64;
        data.extend(ape_tag(&[("Title", "APE Title"), ("Artist", "APE Artist")]));
        let lyrics_start = data.len() as u64;
        data.extend(lyrics3v2("la la la"));
        let v1_start = data.len() as u64;
        data.extend(id3v1(7, 17));

        let blocks = Mp3Dissector.dissect(&data);
        let labels: Vec<&str> = blocks.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels[1..], ["APEv2 tag", "Lyrics3 v2 tag", "ID3v1.1 tag"]);
        assert_eq!(blocks[0].range, ByteRange::new(0, audio_end));

        let ape = &blocks[1];
        assert_eq!(ape.range, ByteRange::new(audio_end, lyrics_start));
        assert!(has(ape, "Item Title: APE Title"));
        assert!(has(ape, "Item Artist: APE Artist"));
        assert!(find(&ape.children, "Header").range.start == audio_end);

        let lyrics = &blocks[2];
        assert!(has(lyrics, "Field LYR (Lyrics): la la la"));

        let v1 = &blocks[3];
        assert_eq!(v1.range, ByteRange::new(v1_start, v1_start + 128));
        assert!(has(v1, "Title: Title"));
        assert!(has(v1, "Track: 7"));
        assert!(has(v1, "Genre: Rock (17)"));
    }

    #[test]
    fn parses_plain_id3v1() {
        let mut data = frames(2);
        let mut tag = id3v1(0, 255);
        tag[125] = b'!'; // comment uses all 30 bytes, so no track number
        data.extend(tag);

        let blocks = Mp3Dissector.dissect(&data);
        let v1 = find(&blocks, "ID3v1 tag");
        assert!(!v1.children.iter().any(|b| b.label.starts_with("Track")));
        assert!(has(v1, "Genre: unknown (255)"));
    }

    #[test]
    fn resyncs_after_junk() {
        let mut data = frames(3);
        let junk_start = data.len() as u64;
        // Includes a bogus sync word that isn't followed by a real frame.
        data.extend(b"\x00\x00junk\xFF\xFB\x90\x64junk");
        let junk_end = data.len() as u64;
        data.extend(frames(3));

        let blocks = Mp3Dissector.dissect(&data);
        let audio = &blocks[0];
        assert!(audio.label.starts_with("Audio: 6 frames"));
        let junk = find(&audio.children, "Unrecognized data");
        assert_eq!(junk.range, ByteRange::new(junk_start, junk_end));
        assert!(has(
            audio,
            "Frame 4: MPEG-1 Layer III, 128 kbps, 44100 Hz, Joint stereo"
        ));
    }

    #[test]
    fn marks_truncated_last_frame() {
        let mut data = frames(3);
        data.truncate(data.len() - 100);

        let blocks = Mp3Dissector.dissect(&data);
        let last = blocks[0].children.last().unwrap();
        assert!(last.label.ends_with("(truncated)"));
        assert_eq!(last.range.end, data.len() as u64);
    }

    #[test]
    fn handles_truncated_id3v2_tag() {
        let mut data = id3_tag(3, 0, &id3_frame(3, b"TIT2", b"\x00Song"));
        data.truncate(18);
        let blocks = Mp3Dissector.dissect(&data);
        let tag = find(&blocks, "ID3v2.3 tag");
        assert_eq!(tag.range, ByteRange::new(0, 18));
    }

    #[test]
    fn identify_reports_mp3() {
        assert_eq!(super::super::identify(&frames(3)), "MP3");
        assert_eq!(super::super::identify(&id3_tag(4, 0, &[0; 8])), "MP3");
    }
}
