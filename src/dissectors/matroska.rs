use super::{Block, ByteRange, Dissector};

const EBML_MAGIC: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3];

const ID_EBML: u32 = 0x1A45_DFA3;
const ID_DOC_TYPE: u32 = 0x4282;
const ID_SEGMENT: u32 = 0x1853_8067;
const ID_CLUSTER: u32 = 0x1F43_B675;
const ID_SIMPLE_BLOCK: u32 = 0xA3;
const ID_BLOCK: u32 = 0xA1;
const ID_TRACK_TYPE: u32 = 0x83;

/// Maximum nesting depth of master elements that are parsed into children.
const MAX_DEPTH: usize = 16;
/// Maximum number of elements shown under a single parent.
const MAX_CHILDREN: usize = 256;
/// Maximum number of elements shown in the whole tree.
const MAX_ELEMENTS: usize = 4096;
/// Longest string value shown in a label, in characters.
const MAX_STRING_CHARS: usize = 64;

/// Level-1 elements (children of Segment). In an unknown-sized element other
/// than Segment, one of these marks the start of the next sibling.
const LEVEL1_IDS: &[u32] = &[
    0x114D_9B74, // SeekHead
    0x1549_A966, // Info
    0x1654_AE6B, // Tracks
    ID_CLUSTER,
    0x1C53_BB6B, // Cues
    0x1941_A469, // Attachments
    0x1043_A770, // Chapters
    0x1254_C367, // Tags
];

pub struct MatroskaDissector;

impl Dissector for MatroskaDissector {
    fn name(&self) -> &'static str {
        "Matroska"
    }

    fn matches(&self, data: &[u8]) -> bool {
        matches!(doc_type(data).as_deref(), Some("matroska") | Some("webm"))
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut ctx = Context {
            data,
            budget: MAX_ELEMENTS,
        };
        ctx.elements(0, data.len(), None, 0).0
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Master,
    Uint,
    Int,
    Float,
    String,
    Utf8,
    Date,
    Binary,
}

fn element_info(id: u32) -> Option<(&'static str, Kind)> {
    use Kind::*;
    let info = match id {
        // EBML header
        ID_EBML => ("EBML", Master),
        0x4286 => ("EBMLVersion", Uint),
        0x42F7 => ("EBMLReadVersion", Uint),
        0x42F2 => ("EBMLMaxIDLength", Uint),
        0x42F3 => ("EBMLMaxSizeLength", Uint),
        ID_DOC_TYPE => ("DocType", String),
        0x4287 => ("DocTypeVersion", Uint),
        0x4285 => ("DocTypeReadVersion", Uint),
        0x4281 => ("DocTypeExtension", Master),
        0x4283 => ("DocTypeExtensionName", String),
        0x4284 => ("DocTypeExtensionVersion", Uint),
        // Global
        0xEC => ("Void", Binary),
        0xBF => ("CRC-32", Binary),
        // Segment
        ID_SEGMENT => ("Segment", Master),
        // Meta seek
        0x114D_9B74 => ("SeekHead", Master),
        0x4DBB => ("Seek", Master),
        0x53AB => ("SeekID", Binary),
        0x53AC => ("SeekPosition", Uint),
        // Segment info
        0x1549_A966 => ("Info", Master),
        0x73A4 => ("SegmentUUID", Binary),
        0x7384 => ("SegmentFilename", Utf8),
        0x3C_B923 => ("PrevUUID", Binary),
        0x3C_83AB => ("PrevFilename", Utf8),
        0x3E_B923 => ("NextUUID", Binary),
        0x3E_83BB => ("NextFilename", Utf8),
        0x4444 => ("SegmentFamily", Binary),
        0x6924 => ("ChapterTranslate", Master),
        0x2A_D7B1 => ("TimestampScale", Uint),
        0x4489 => ("Duration", Float),
        0x4461 => ("DateUTC", Date),
        0x7BA9 => ("Title", Utf8),
        0x4D80 => ("MuxingApp", Utf8),
        0x5741 => ("WritingApp", Utf8),
        // Cluster
        ID_CLUSTER => ("Cluster", Master),
        0xE7 => ("Timestamp", Uint),
        0xA7 => ("Position", Uint),
        0xAB => ("PrevSize", Uint),
        ID_SIMPLE_BLOCK => ("SimpleBlock", Binary),
        0xA0 => ("BlockGroup", Master),
        ID_BLOCK => ("Block", Binary),
        0x75A1 => ("BlockAdditions", Master),
        0xA6 => ("BlockMore", Master),
        0xEE => ("BlockAddID", Uint),
        0xA5 => ("BlockAdditional", Binary),
        0x9B => ("BlockDuration", Uint),
        0xFA => ("ReferencePriority", Uint),
        0xFB => ("ReferenceBlock", Int),
        0xA4 => ("CodecState", Binary),
        0x75A2 => ("DiscardPadding", Int),
        // Tracks
        0x1654_AE6B => ("Tracks", Master),
        0xAE => ("TrackEntry", Master),
        0xD7 => ("TrackNumber", Uint),
        0x73C5 => ("TrackUID", Uint),
        ID_TRACK_TYPE => ("TrackType", Uint),
        0xB9 => ("FlagEnabled", Uint),
        0x88 => ("FlagDefault", Uint),
        0x55AA => ("FlagForced", Uint),
        0x9C => ("FlagLacing", Uint),
        0x23_E383 => ("DefaultDuration", Uint),
        0x23_4E7A => ("DefaultDecodedFieldDuration", Uint),
        0x55EE => ("MaxBlockAdditionID", Uint),
        0x536E => ("Name", Utf8),
        0x22_B59C => ("Language", String),
        0x22_B59D => ("LanguageBCP47", String),
        0x86 => ("CodecID", String),
        0x63A2 => ("CodecPrivate", Binary),
        0x25_8688 => ("CodecName", Utf8),
        0x56AA => ("CodecDelay", Uint),
        0x56BB => ("SeekPreRoll", Uint),
        0xE0 => ("Video", Master),
        0x9A => ("FlagInterlaced", Uint),
        0x53B8 => ("StereoMode", Uint),
        0xB0 => ("PixelWidth", Uint),
        0xBA => ("PixelHeight", Uint),
        0x54AA => ("PixelCropBottom", Uint),
        0x54BB => ("PixelCropTop", Uint),
        0x54CC => ("PixelCropLeft", Uint),
        0x54DD => ("PixelCropRight", Uint),
        0x54B0 => ("DisplayWidth", Uint),
        0x54BA => ("DisplayHeight", Uint),
        0x54B2 => ("DisplayUnit", Uint),
        0x55B0 => ("Colour", Master),
        0x55B1 => ("MatrixCoefficients", Uint),
        0x55B2 => ("BitsPerChannel", Uint),
        0x55B9 => ("Range", Uint),
        0x55BA => ("TransferCharacteristics", Uint),
        0x55BB => ("Primaries", Uint),
        0xE1 => ("Audio", Master),
        0xB5 => ("SamplingFrequency", Float),
        0x78B5 => ("OutputSamplingFrequency", Float),
        0x9F => ("Channels", Uint),
        0x6264 => ("BitDepth", Uint),
        0x6D80 => ("ContentEncodings", Master),
        0x6240 => ("ContentEncoding", Master),
        0x5031 => ("ContentEncodingOrder", Uint),
        0x5032 => ("ContentEncodingScope", Uint),
        0x5033 => ("ContentEncodingType", Uint),
        0x5034 => ("ContentCompression", Master),
        0x4254 => ("ContentCompAlgo", Uint),
        0x4255 => ("ContentCompSettings", Binary),
        0x5035 => ("ContentEncryption", Master),
        // Cues
        0x1C53_BB6B => ("Cues", Master),
        0xBB => ("CuePoint", Master),
        0xB3 => ("CueTime", Uint),
        0xB7 => ("CueTrackPositions", Master),
        0xF7 => ("CueTrack", Uint),
        0xF1 => ("CueClusterPosition", Uint),
        0xF0 => ("CueRelativePosition", Uint),
        0xB2 => ("CueDuration", Uint),
        0x5378 => ("CueBlockNumber", Uint),
        // Attachments
        0x1941_A469 => ("Attachments", Master),
        0x61A7 => ("AttachedFile", Master),
        0x467E => ("FileDescription", Utf8),
        0x466E => ("FileName", Utf8),
        0x4660 => ("FileMediaType", String),
        0x465C => ("FileData", Binary),
        0x46AE => ("FileUID", Uint),
        // Chapters
        0x1043_A770 => ("Chapters", Master),
        0x45B9 => ("EditionEntry", Master),
        0x45BC => ("EditionUID", Uint),
        0x45BD => ("EditionFlagHidden", Uint),
        0x45DB => ("EditionFlagDefault", Uint),
        0x45DD => ("EditionFlagOrdered", Uint),
        0xB6 => ("ChapterAtom", Master),
        0x73C4 => ("ChapterUID", Uint),
        0x5654 => ("ChapterStringUID", Utf8),
        0x91 => ("ChapterTimeStart", Uint),
        0x92 => ("ChapterTimeEnd", Uint),
        0x98 => ("ChapterFlagHidden", Uint),
        0x4598 => ("ChapterFlagEnabled", Uint),
        0x80 => ("ChapterDisplay", Master),
        0x85 => ("ChapString", Utf8),
        0x437C => ("ChapLanguage", String),
        0x437D => ("ChapLanguageBCP47", String),
        0x437E => ("ChapCountry", String),
        // Tags
        0x1254_C367 => ("Tags", Master),
        0x7373 => ("Tag", Master),
        0x63C0 => ("Targets", Master),
        0x68CA => ("TargetTypeValue", Uint),
        0x63CA => ("TargetType", String),
        0x63C5 => ("TagTrackUID", Uint),
        0x63C9 => ("TagEditionUID", Uint),
        0x63C4 => ("TagChapterUID", Uint),
        0x63C6 => ("TagAttachmentUID", Uint),
        0x67C8 => ("SimpleTag", Master),
        0x45A3 => ("TagName", Utf8),
        0x447A => ("TagLanguage", String),
        0x447B => ("TagLanguageBCP47", String),
        0x4484 => ("TagDefault", Uint),
        0x4487 => ("TagString", Utf8),
        0x4485 => ("TagBinary", Binary),
        _ => return None,
    };
    Some(info)
}

fn track_type_name(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "video",
        2 => "audio",
        3 => "complex",
        0x10 => "logo",
        0x11 => "subtitle",
        0x12 => "buttons",
        0x20 => "control",
        0x21 => "metadata",
        _ => return None,
    })
}

/// Reads an EBML variable-length integer. Returns the raw value with the
/// length marker bit kept, the value with the marker stripped, and the
/// length in bytes.
fn read_vint(data: &[u8], off: usize) -> Option<(u64, u64, usize)> {
    let first = *data.get(off)?;
    if first == 0 {
        return None; // Lengths above 8 bytes are not supported.
    }
    let len = first.leading_zeros() as usize + 1;
    let bytes = data.get(off..off.checked_add(len)?)?;
    let raw = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let marker = 1u64 << (7 * len);
    Some((raw, raw & (marker - 1), len))
}

/// Reads an element ID (1 to 4 bytes, marker bits kept).
fn read_id(data: &[u8], off: usize) -> Option<(u32, usize)> {
    let (raw, _, len) = read_vint(data, off)?;
    if len > 4 {
        return None;
    }
    Some((raw as u32, len))
}

/// Reads an element data size. `None` in the first slot means "unknown size"
/// (all value bits set).
fn read_size(data: &[u8], off: usize) -> Option<(Option<u64>, usize)> {
    let (_, value, len) = read_vint(data, off)?;
    let all_ones = (1u64 << (7 * len)) - 1;
    Some(((value != all_ones).then_some(value), len))
}

struct Header {
    id: u32,
    id_len: usize,
    size: Option<u64>,
    size_len: usize,
}

impl Header {
    fn data_start(&self, pos: usize) -> usize {
        pos + self.id_len + self.size_len
    }
}

fn read_header(data: &[u8], pos: usize) -> Option<Header> {
    let (id, id_len) = read_id(data, pos)?;
    let (size, size_len) = read_size(data, pos + id_len)?;
    Some(Header {
        id,
        id_len,
        size,
        size_len,
    })
}

/// Whether element `id` cannot be a child of an unknown-sized element
/// `parent`, and therefore ends it.
fn ends_unknown_sized(parent: u32, id: u32) -> bool {
    if id == ID_EBML || id == ID_SEGMENT {
        return true;
    }
    parent != ID_SEGMENT && LEVEL1_IDS.contains(&id)
}

/// Returns the DocType string from an EBML header at offset 0.
fn doc_type(data: &[u8]) -> Option<String> {
    if !data.starts_with(EBML_MAGIC) {
        return None;
    }
    let header = read_header(data, 0)?;
    let start = header.data_start(0);
    let end = start.checked_add(usize::try_from(header.size?).ok()?)?;
    let end = end.min(data.len());
    let mut pos = start;
    while pos < end {
        let child = read_header(data, pos)?;
        let child_start = child.data_start(pos);
        let child_end = child_start.checked_add(usize::try_from(child.size?).ok()?)?;
        if child.id == ID_DOC_TYPE {
            return Some(decode_string(data.get(child_start..child_end)?));
        }
        pos = child_end;
    }
    None
}

fn decode_string(bytes: &[u8]) -> String {
    let trimmed = match bytes.iter().position(|&b| b == 0) {
        Some(nul) => &bytes[..nul],
        None => bytes,
    };
    let text = String::from_utf8_lossy(trimmed);
    if text.chars().count() > MAX_STRING_CHARS {
        let mut short: String = text.chars().take(MAX_STRING_CHARS).collect();
        short.push('…');
        short
    } else {
        text.into_owned()
    }
}

fn decode_uint(bytes: &[u8]) -> Option<u64> {
    (bytes.len() <= 8).then(|| bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

fn decode_int(bytes: &[u8]) -> Option<i64> {
    let raw = decode_uint(bytes)?;
    if bytes.is_empty() {
        return Some(0);
    }
    let shift = 64 - 8 * bytes.len() as u32;
    Some(((raw << shift) as i64) >> shift)
}

fn decode_float(bytes: &[u8]) -> Option<f64> {
    match bytes.len() {
        0 => Some(0.0),
        4 => Some(f64::from(f32::from_be_bytes(bytes.try_into().ok()?))),
        8 => Some(f64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

/// Formats a Matroska date (nanoseconds since 2001-01-01T00:00:00 UTC).
fn format_date(nanos: i64) -> String {
    const DAYS_1970_TO_2001: i64 = 11_323;
    let secs = nanos.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400) + DAYS_1970_TO_2001;
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Converts days since 1970-01-01 to a (year, month, day) civil date.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn format_value(id: u32, kind: Kind, bytes: &[u8]) -> Option<String> {
    Some(match kind {
        Kind::Uint => {
            let value = decode_uint(bytes)?;
            match (id, track_type_name(value)) {
                (ID_TRACK_TYPE, Some(name)) => format!("{value} ({name})"),
                _ => value.to_string(),
            }
        }
        Kind::Int => decode_int(bytes)?.to_string(),
        Kind::Float => decode_float(bytes)?.to_string(),
        Kind::Date => format_date(decode_int(bytes)?),
        Kind::String | Kind::Utf8 => decode_string(bytes),
        Kind::Master | Kind::Binary => return None,
    })
}

/// Breaks a SimpleBlock or Block payload into its header fields and frame
/// data, and returns a short summary for the element label.
fn block_fields(
    data: &[u8],
    start: usize,
    end: usize,
    simple: bool,
) -> Option<(Vec<Block>, String)> {
    let (_, track, track_len) = read_vint(data, start)?;
    let timecode_off = start + track_len;
    let flags_off = timecode_off + 2;
    let frames_off = flags_off + 1;
    if frames_off > end {
        return None;
    }
    let timecode = i16::from_be_bytes([data[timecode_off], data[timecode_off + 1]]);
    let flags = data[flags_off];
    let lacing = match (flags >> 1) & 3 {
        0 => "none",
        1 => "Xiph",
        2 => "fixed-size",
        _ => "EBML",
    };
    let keyframe = simple && flags & 0x80 != 0;
    let mut flag_names = vec![format!("lacing {lacing}")];
    if keyframe {
        flag_names.insert(0, "keyframe".to_string());
    }
    if flags & 0x08 != 0 {
        flag_names.push("invisible".to_string());
    }
    if simple && flags & 0x01 != 0 {
        flag_names.push("discardable".to_string());
    }
    let r = |s: usize, e: usize| ByteRange::new(s as u64, e as u64);
    let fields = vec![
        Block::leaf(format!("Track number: {track}"), r(start, timecode_off)),
        Block::leaf(format!("Timecode: {timecode}"), r(timecode_off, flags_off)),
        Block::leaf(
            format!("Flags: 0x{flags:02X} ({})", flag_names.join(", ")),
            r(flags_off, frames_off),
        ),
        Block::leaf(
            format!("Frame data ({} bytes)", end - frames_off),
            r(frames_off, end),
        ),
    ];
    let summary = format!(
        "track {track}, timecode {timecode}{}",
        if keyframe { ", keyframe" } else { "" }
    );
    Some((fields, summary))
}

struct Context<'a> {
    data: &'a [u8],
    /// Number of elements that may still be shown in the tree.
    budget: usize,
}

impl Context<'_> {
    /// Parses the elements in `start..end`. `unknown_parent` is the ID of the
    /// enclosing element if it has unknown size, in which case parsing stops
    /// at the first element that cannot be its child. Returns the blocks and
    /// the offset where parsing stopped.
    fn elements(
        &mut self,
        start: usize,
        end: usize,
        unknown_parent: Option<u32>,
        depth: usize,
    ) -> (Vec<Block>, usize) {
        let mut blocks = Vec::new();
        let mut pos = start;
        while pos < end {
            let Some(header) = read_header(self.data, pos) else {
                blocks.push(Block::leaf(
                    "Unparseable data",
                    ByteRange::new(pos as u64, end as u64),
                ));
                return (blocks, end);
            };
            if unknown_parent.is_some_and(|parent| ends_unknown_sized(parent, header.id)) {
                break;
            }
            if blocks.len() >= MAX_CHILDREN || self.budget == 0 {
                let (count, stop) = skip_elements(self.data, pos, end, unknown_parent, depth);
                blocks.push(Block::leaf(
                    format!("({count} more not shown)"),
                    ByteRange::new(pos as u64, stop as u64),
                ));
                return (blocks, stop);
            }
            self.budget -= 1;
            let block = self.element(pos, end, &header, depth);
            pos = block.range.end as usize;
            blocks.push(block);
        }
        (blocks, pos.min(end))
    }

    fn element(&mut self, pos: usize, parent_end: usize, header: &Header, depth: usize) -> Block {
        let data_start = header.data_start(pos).min(parent_end);
        let info = element_info(header.id);
        let name = info.map_or("Unknown", |(name, _)| name);
        let kind = info.map_or(Kind::Binary, |(_, kind)| kind);
        let r = |s: usize, e: usize| ByteRange::new(s as u64, e as u64);

        let id_end = pos + header.id_len;
        let mut children = vec![
            Block::leaf(
                format!(
                    "ID: 0x{:0width$X} ({name})",
                    header.id,
                    width = header.id_len * 2
                ),
                r(pos, id_end),
            ),
            Block::leaf(
                match header.size {
                    Some(size) => format!("Size: {size}"),
                    None => "Size: unknown".to_string(),
                },
                r(id_end, data_start),
            ),
        ];

        // Where the element's data ends according to its size field.
        let declared_end = header
            .size
            .and_then(|size| usize::try_from(size).ok())
            .and_then(|size| data_start.checked_add(size));
        let truncated = declared_end.is_some_and(|e| e > parent_end);
        let mut end = declared_end.map_or(parent_end, |e| e.min(parent_end));

        let mut label;
        let mut expand = false;
        if kind == Kind::Master && depth < MAX_DEPTH {
            let unknown_parent = header.size.is_none().then_some(header.id);
            let (elements, stop) = self.elements(data_start, end, unknown_parent, depth + 1);
            if header.size.is_none() {
                end = stop;
            }
            label = name.to_string();
            if header.id == ID_EBML {
                let doc_type = elements
                    .iter()
                    .find_map(|b| b.label.strip_prefix("DocType: "));
                if let Some(doc_type) = doc_type {
                    label = format!("EBML header (DocType: {doc_type})");
                }
            }
            children.extend(elements);
            expand = depth == 0 || matches!(header.id, 0x1549_A966 | 0x1654_AE6B);
        } else if kind == Kind::Master {
            children.push(Block::leaf(
                "Data (nesting too deep to parse)",
                r(data_start, end),
            ));
            label = name.to_string();
        } else if kind == Kind::Binary {
            let len = end - data_start;
            let block_info = match header.id {
                ID_SIMPLE_BLOCK => block_fields(self.data, data_start, end, true),
                ID_BLOCK => block_fields(self.data, data_start, end, false),
                _ => None,
            };
            label = match block_info {
                Some((fields, summary)) => {
                    children.extend(fields);
                    format!("{name}: {summary} ({len} bytes)")
                }
                None => {
                    children.push(Block::leaf(
                        format!("Data ({len} bytes)"),
                        r(data_start, end),
                    ));
                    format!("{name} ({len} bytes)")
                }
            };
            if info.is_none() {
                label = format!(
                    "Unknown element 0x{:0width$X} ({len} bytes)",
                    header.id,
                    width = header.id_len * 2
                );
            }
        } else {
            let bytes = &self.data[data_start..end];
            label = match (truncated, format_value(header.id, kind, bytes)) {
                (false, Some(value)) => format!("{name}: {value}"),
                (true, _) => format!("{name}: (truncated)"),
                (false, None) => format!("{name}: (invalid {}-byte value)", bytes.len()),
            };
            children.push(Block::leaf(
                label.replacen(name, "Value", 1),
                r(data_start, end),
            ));
        }
        if truncated {
            label.push_str(" (truncated)");
        }
        Block::node(label, r(pos, end), children).expanded_if(expand)
    }
}

/// Counts the elements in `start..end` without building blocks, using the
/// same stopping rules as `Context::elements`. Returns the count and the
/// offset where counting stopped.
fn skip_elements(
    data: &[u8],
    start: usize,
    end: usize,
    unknown_parent: Option<u32>,
    depth: usize,
) -> (usize, usize) {
    let mut count = 0;
    let mut pos = start;
    while pos < end {
        let Some(header) = read_header(data, pos) else {
            return (count, end);
        };
        if unknown_parent.is_some_and(|parent| ends_unknown_sized(parent, header.id)) {
            break;
        }
        count += 1;
        let data_start = header.data_start(pos).min(end);
        pos = match header.size.and_then(|s| usize::try_from(s).ok()) {
            Some(size) => data_start.saturating_add(size).min(end),
            None => {
                let is_master = element_info(header.id).is_some_and(|(_, k)| k == Kind::Master);
                if is_master && depth < MAX_DEPTH {
                    skip_elements(data, data_start, end, Some(header.id), depth + 1).1
                } else {
                    end
                }
            }
        };
    }
    (count, pos.min(end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes an element with a minimal-length size field.
    fn element(id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = id_bytes(id);
        let len = payload.len() as u64;
        let size_len = (1..=8).find(|&n| len < (1u64 << (7 * n)) - 1).unwrap();
        let marked = len | (1u64 << (7 * size_len));
        out.extend_from_slice(&marked.to_be_bytes()[8 - size_len..]);
        out.extend_from_slice(payload);
        out
    }

    fn unknown_size_element(id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = id_bytes(id);
        out.push(0xFF);
        out.extend_from_slice(payload);
        out
    }

    fn id_bytes(id: u32) -> Vec<u8> {
        let bytes = id.to_be_bytes();
        let skip = bytes.iter().position(|&b| b != 0).unwrap();
        bytes[skip..].to_vec()
    }

    fn ebml_header(doc_type: &str) -> Vec<u8> {
        let mut body = element(0x4286, &[1]);
        body.extend(element(ID_DOC_TYPE, doc_type.as_bytes()));
        body.extend(element(0x4287, &[4]));
        element(ID_EBML, &body)
    }

    /// Builds a minimal file: EBML header, then a Segment holding Info,
    /// Tracks and the given clusters.
    fn build_matroska(doc_type: &str, clusters: &[Vec<u8>], unknown_segment: bool) -> Vec<u8> {
        let mut data = ebml_header(doc_type);
        let mut info = element(0x2A_D7B1, &[0x0F, 0x42, 0x40]);
        info.extend(element(0x4489, &1500.0f32.to_be_bytes()));
        info.extend(element(0x4461, &0i64.to_be_bytes()));
        let mut segment = element(0x1549_A966, &info);
        let mut track = element(0xD7, &[1]);
        track.extend(element(ID_TRACK_TYPE, &[1]));
        track.extend(element(0x86, b"V_VP9"));
        segment.extend(element(0x1654_AE6B, &element(0xAE, &track)));
        for cluster in clusters {
            segment.extend_from_slice(cluster);
        }
        if unknown_segment {
            data.extend(unknown_size_element(ID_SEGMENT, &segment));
        } else {
            data.extend(element(ID_SEGMENT, &segment));
        }
        data
    }

    fn simple_block(track: u8, timecode: i16, flags: u8, frame: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x80 | track];
        payload.extend_from_slice(&timecode.to_be_bytes());
        payload.push(flags);
        payload.extend_from_slice(frame);
        element(ID_SIMPLE_BLOCK, &payload)
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
    fn matches_matroska_and_webm() {
        assert!(MatroskaDissector.matches(&build_matroska("matroska", &[], false)));
        assert!(MatroskaDissector.matches(&build_matroska("webm", &[], false)));
        // Only the EBML header is needed.
        assert!(MatroskaDissector.matches(&ebml_header("webm")));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!MatroskaDissector.matches(b""));
        assert!(!MatroskaDissector.matches(b"not a matroska file"));
        assert!(!MatroskaDissector.matches(EBML_MAGIC));
        // Truncated EBML header.
        let header = ebml_header("matroska");
        assert!(!MatroskaDissector.matches(&header[..header.len() - 6]));
        // Other EBML document types are not claimed.
        assert!(!MatroskaDissector.matches(&ebml_header("dvd-ebml")));
        // EBML header with an unknown size.
        let mut unknown = vec![0x1A, 0x45, 0xDF, 0xA3, 0xFF];
        unknown.extend(element(ID_DOC_TYPE, b"webm"));
        assert!(!MatroskaDissector.matches(&unknown));
    }

    #[test]
    fn vint_parsing() {
        assert_eq!(read_vint(&[0x81], 0), Some((0x81, 1, 1)));
        assert_eq!(read_vint(&[0x40, 0x02], 0), Some((0x4002, 2, 2)));
        assert_eq!(read_vint(&[0x00], 0), None);
        assert_eq!(read_vint(&[0x40], 0), None);
        assert_eq!(read_size(&[0xFF], 0), Some((None, 1)));
        assert_eq!(
            read_size(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0),
            Some((None, 8))
        );
        assert_eq!(read_size(&[0x7F, 0xFF], 0), Some((None, 2)));
        assert_eq!(read_size(&[0x7F, 0xFE], 0), Some((Some(0x3FFE), 2)));
    }

    #[test]
    fn value_decoding() {
        assert_eq!(decode_int(&[0xFF, 0xFE]), Some(-2));
        assert_eq!(decode_int(&[]), Some(0));
        assert_eq!(decode_uint(&[0; 9]), None);
        assert_eq!(decode_float(&[0; 3]), None);
        assert_eq!(format_date(0), "2001-01-01 00:00:00 UTC");
        assert_eq!(format_date(-1), "2000-12-31 23:59:59 UTC");
        assert_eq!(
            format_date(745_632_000 * 1_000_000_000 + 3_723_000_000_000),
            "2024-08-18 01:02:03 UTC"
        );
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = build_matroska(
            "webm",
            &[element(ID_CLUSTER, &simple_block(1, 0, 0x80, &[1; 8]))],
            false,
        );
        let full = MatroskaDissector.dissect(&data);
        assert_eq!(full.len(), 2);
        for len in 0..data.len() {
            let blocks = MatroskaDissector.dissect(&data[..len]);
            assert!(blocks.len() <= 2);
            for block in &blocks {
                assert!(block.range.end as usize <= len);
            }
        }
        assert!(MatroskaDissector.dissect(&[]).is_empty());
    }

    #[test]
    fn dissect_parses_header_and_segment() {
        let mut cluster = element(0xE7, &[0]);
        cluster.extend(simple_block(1, -3, 0x80, &[0xAA; 10]));
        let cluster = element(ID_CLUSTER, &cluster);
        let data = build_matroska("webm", &[cluster], false);
        let blocks = MatroskaDissector.dissect(&data);
        assert_eq!(blocks.len(), 2);

        let header = find_block(&blocks, "EBML header (DocType: webm)");
        let header_len = ebml_header("webm").len() as u64;
        assert_eq!(header.range, ByteRange::new(0, header_len));
        assert!(header.default_expanded);
        assert_eq!(header.children[0].label, "ID: 0x1A45DFA3 (EBML)");
        assert_eq!(header.children[0].range, ByteRange::new(0, 4));
        assert_eq!(
            header.children[1].label,
            format!("Size: {}", header_len - 5)
        );
        assert_eq!(header.children[1].range, ByteRange::new(4, 5));
        find_block(&header.children, "EBMLVersion: 1");
        let doc_type = find_block(&header.children, "DocType: webm");
        // ID 42 82 at offset 9, size at 11, value "webm" at 12..16.
        assert_eq!(doc_type.range, ByteRange::new(9, 16));
        assert_eq!(doc_type.children[2].label, "Value: webm");
        assert_eq!(doc_type.children[2].range, ByteRange::new(12, 16));

        let segment = find_block(&blocks, "Segment");
        assert_eq!(segment.range, ByteRange::new(header_len, data.len() as u64));

        let info = find_block(&segment.children, "Info");
        find_block(&info.children, "TimestampScale: 1000000");
        find_block(&info.children, "Duration: 1500");
        find_block(&info.children, "DateUTC: 2001-01-01 00:00:00 UTC");

        let tracks = find_block(&segment.children, "Tracks");
        let entry = find_block(&tracks.children, "TrackEntry");
        find_block(&entry.children, "TrackNumber: 1");
        find_block(&entry.children, "TrackType: 1 (video)");
        find_block(&entry.children, "CodecID: V_VP9");

        let cluster = find_block(&segment.children, "Cluster");
        assert!(!cluster.default_expanded);
        find_block(&cluster.children, "Timestamp: 0");
        let block = find_block(
            &cluster.children,
            "SimpleBlock: track 1, timecode -3, keyframe (14 bytes)",
        );
        let start = block.range.start;
        assert_eq!(block.range.end, data.len() as u64);
        find_block(&block.children, "Track number: 1");
        find_block(&block.children, "Timecode: -3");
        find_block(&block.children, "Flags: 0x80 (keyframe, lacing none)");
        let frame = find_block(&block.children, "Frame data (10 bytes)");
        assert_eq!(
            frame.range,
            ByteRange::new(start + 2 + 4, data.len() as u64)
        );
    }

    #[test]
    fn unknown_sizes_end_at_next_sibling() {
        let cluster_a = unknown_size_element(ID_CLUSTER, &simple_block(1, 0, 0x80, &[1; 4]));
        let cluster_b = unknown_size_element(ID_CLUSTER, &simple_block(1, 5, 0x00, &[2; 4]));
        let data = build_matroska("matroska", &[cluster_a.clone(), cluster_b.clone()], true);
        let blocks = MatroskaDissector.dissect(&data);
        let segment = find_block(&blocks, "Segment");
        assert_eq!(segment.children[1].label, "Size: unknown");
        assert_eq!(segment.range.end, data.len() as u64);

        let clusters: Vec<_> = segment
            .children
            .iter()
            .filter(|b| b.label == "Cluster")
            .collect();
        assert_eq!(clusters.len(), 2);
        let b_start = data.len() - cluster_b.len();
        assert_eq!(
            clusters[0].range,
            ByteRange::new((b_start - cluster_a.len()) as u64, b_start as u64)
        );
        assert_eq!(
            clusters[1].range,
            ByteRange::new(b_start as u64, data.len() as u64)
        );
        assert_eq!(clusters[0].children.len(), 3);
        assert_eq!(clusters[1].children.len(), 3);
    }

    #[test]
    fn element_count_is_capped() {
        let clusters: Vec<Vec<u8>> = (0..MAX_CHILDREN + 10)
            .map(|i| element(ID_CLUSTER, &element(0xE7, &[i as u8])))
            .collect();
        let data = build_matroska("webm", &clusters, false);
        let blocks = MatroskaDissector.dissect(&data);
        let segment = find_block(&blocks, "Segment");
        // ID, size, Info, Tracks and clusters up to the cap.
        assert_eq!(segment.children.len(), 2 + MAX_CHILDREN + 1);
        let more = find_block(&segment.children, "(12 more not shown)");
        assert_eq!(more.range.end, data.len() as u64);
    }

    #[test]
    fn unknown_elements_and_bad_data() {
        let mut body = element(0x4286, &[1]);
        body.extend(element(ID_DOC_TYPE, b"webm"));
        body.extend(element(0x4DFF, &[1, 2, 3]));
        let mut data = element(ID_EBML, &body);
        data.extend_from_slice(&[0x00, 0x01]);
        let blocks = MatroskaDissector.dissect(&data);
        find_block(&blocks[0].children, "Unknown element 0x4DFF (3 bytes)");
        let bad = find_block(&blocks, "Unparseable data");
        assert_eq!(bad.range.end, data.len() as u64);
    }

    #[test]
    fn identify_reports_matroska() {
        assert_eq!(
            super::super::identify(&build_matroska("webm", &[], false)),
            "Matroska"
        );
        assert_eq!(
            super::super::identify(&build_matroska("matroska", &[], false)),
            "Matroska"
        );
        assert_eq!(super::super::identify(&ebml_header("other")), "Data");
    }
}
