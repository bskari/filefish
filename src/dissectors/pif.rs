//! Microsoft Program Information File (.pif).
//!
//! Layout reference: Sergey Merzlikin, "The PIF file format in various Windows
//! versions" (2000), cross-checked against Wine's `programs/winevdm`. The format
//! was never officially documented, so fields nobody has identified are shown
//! as "Unknown".

use std::collections::HashSet;

use super::{Block, ByteRange, Dissector};

/// The basic (Windows 1.x/2.x, TopView) section always sits at offset 0.
const BASIC_LEN: usize = 0x171;
/// Heading of the basic section; it starts the extension chain.
const PIFEX_MAGIC: &[u8] = b"MICROSOFT PIFEX\0";
/// 16-byte name, next-heading offset, data offset, data length.
const HEADING_LEN: usize = 0x16;
const LAST_HEADING: u16 = 0xFFFF;
/// Real files have at most eight sections; this bounds hostile chains.
const MAX_SECTIONS: usize = 64;
const MAX_TEXT_LINES: usize = 4096;
/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct PifDissector;

impl Dissector for PifDissector {
    fn name(&self) -> &'static str {
        "PIF"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= BASIC_LEN + HEADING_LEN
            && data.get(BASIC_LEN..BASIC_LEN + PIFEX_MAGIC.len()) == Some(PIFEX_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < BASIC_LEN {
            return blocks;
        }
        blocks.push(
            Block::node(
                "Basic section",
                span(0, BASIC_LEN),
                fields_block(data, 0, BASIC_LEN, BASIC_FIELDS),
            )
            .expanded(),
        );

        let mut covered_end = BASIC_LEN;
        let mut visited = HashSet::new();
        let mut offset = BASIC_LEN;
        let mut sections = Vec::new();
        while sections.len() < MAX_SECTIONS && visited.insert(offset) {
            let Some(heading) = Heading::parse(data, offset) else {
                break;
            };
            covered_end = covered_end.max(offset + HEADING_LEN);
            let data_block = section_data_block(data, &heading);
            if let Some(block) = &data_block {
                covered_end = covered_end.max(block.range.end as usize);
            }
            sections.push(heading.block());
            sections.extend(data_block);
            if heading.next == LAST_HEADING {
                break;
            }
            offset = heading.next as usize;
        }
        // Headings and data may live anywhere in the file, so they are listed
        // at the top level rather than nested under a single range.
        blocks.extend(sections);

        if covered_end < data.len() {
            blocks.push(Block::leaf(
                format!("Trailing data ({} bytes)", data.len() - covered_end),
                span(covered_end, data.len()),
            ));
        }
        blocks
    }
}

struct Heading {
    offset: usize,
    name: String,
    next: u16,
    data_offset: u16,
    data_len: u16,
}

impl Heading {
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        let raw = data.get(offset..offset.checked_add(HEADING_LEN)?)?;
        Some(Self {
            offset,
            name: c_string(&raw[..16]),
            next: u16::from_le_bytes([raw[16], raw[17]]),
            data_offset: u16::from_le_bytes([raw[18], raw[19]]),
            data_len: u16::from_le_bytes([raw[20], raw[21]]),
        })
    }

    fn block(&self) -> Block {
        let o = self.offset;
        let next = if self.next == LAST_HEADING {
            "Next heading: 0xFFFF (last)".to_string()
        } else {
            format!("Next heading: 0x{:04X}", self.next)
        };
        Block::node(
            format!("Section heading: {}", display(&self.name)),
            span(o, o + HEADING_LEN),
            vec![
                Block::leaf(format!("Name: {}", display(&self.name)), span(o, o + 16)),
                Block::leaf(next, span(o + 16, o + 18)),
                Block::leaf(
                    format!("Data offset: 0x{:04X}", self.data_offset),
                    span(o + 18, o + 20),
                ),
                Block::leaf(
                    format!("Data length: {} (0x{:X})", self.data_len, self.data_len),
                    span(o + 20, o + 22),
                ),
            ],
        )
    }
}

fn section_data_block(data: &[u8], heading: &Heading) -> Option<Block> {
    let start = heading.data_offset as usize;
    let end = (start + heading.data_len as usize).min(data.len());
    if heading.data_len == 0 || start >= end {
        return None;
    }
    // The basic section's heading points back at offset 0, already shown.
    if heading.name == "MICROSOFT PIFEX" && start == 0 {
        return None;
    }
    let fields = match heading.name.as_str() {
        "WINDOWS 386 3.0" => Some(W386_FIELDS),
        "WINDOWS 286 3.0" => Some(W286_FIELDS),
        "WINDOWS VMM 4.0" => Some(VMM_FIELDS),
        "WINDOWS NT  3.1" => Some(NT31_FIELDS),
        "WINDOWS NT  4.0" => Some(NT40_FIELDS),
        _ => None,
    };
    let children = match (fields, heading.name.as_str()) {
        (Some(fields), _) => fields_block(data, start, end, fields),
        (None, "CONFIG  SYS 4.0" | "AUTOEXECBAT 4.0") => text_lines(data, start, end),
        _ => Vec::new(),
    };
    let label = format!("Section data: {}", display(&heading.name));
    Some(if children.is_empty() {
        Block::leaf(label, span(start, end))
    } else {
        Block::node(label, span(start, end), children)
    })
}

fn text_lines(data: &[u8], start: usize, end: usize) -> Vec<Block> {
    let mut lines = Vec::new();
    let mut line_start = start;
    while line_start < end && lines.len() < MAX_TEXT_LINES {
        let line_end = data[line_start..end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(end, |p| line_start + p + 1);
        let text = latin1(&data[line_start..line_end]);
        let text = text.trim_end_matches(['\r', '\n', '\0']);
        lines.push(Block::leaf(
            format!("Line: \"{}\"", display(text)),
            span(line_start, line_end),
        ));
        line_start = line_end;
    }
    lines
}

#[derive(Clone, Copy)]
enum Kind {
    U8,
    Hex8,
    U16,
    Hex16,
    /// Memory size in KB; 0xFFFF means "all available" / "auto".
    Kb16,
    Flags16(&'static [(u32, &'static str)]),
    Flags32(&'static [(u32, &'static str)]),
    /// NUL-terminated (or space-padded) 8-bit string of the given length.
    Str(usize),
    /// NUL-terminated UTF-16LE string of the given byte length.
    Utf16(usize),
    /// Bytes nobody has identified.
    Unknown(usize),
}

impl Kind {
    fn len(self) -> usize {
        match self {
            Kind::U8 | Kind::Hex8 => 1,
            Kind::U16 | Kind::Hex16 | Kind::Kb16 | Kind::Flags16(_) => 2,
            Kind::Flags32(_) => 4,
            Kind::Str(n) | Kind::Utf16(n) | Kind::Unknown(n) => n,
        }
    }
}

struct Field {
    offset: usize,
    name: &'static str,
    kind: Kind,
}

const fn f(offset: usize, name: &'static str, kind: Kind) -> Field {
    Field { offset, name, kind }
}

/// Decodes `fields` relative to `base`, stopping at the first field that does
/// not fit before `end` (a truncated file or short section).
fn fields_block(data: &[u8], base: usize, end: usize, fields: &[Field]) -> Vec<Block> {
    let mut blocks = Vec::new();
    for field in fields {
        let start = base + field.offset;
        let stop = start + field.kind.len();
        let Some(bytes) = data.get(start..stop).filter(|_| stop <= end) else {
            break;
        };
        blocks.push(Block::leaf(field_label(field, bytes), span(start, stop)));
    }
    blocks
}

fn field_label(field: &Field, bytes: &[u8]) -> String {
    let name = field.name;
    let u16_value = || u16::from_le_bytes([bytes[0], bytes[1]]);
    match field.kind {
        Kind::U8 => format!("{name}: {}", bytes[0]),
        Kind::Hex8 => format!("{name}: 0x{:02X}", bytes[0]),
        Kind::U16 => format!("{name}: {}", u16_value()),
        Kind::Hex16 => format!("{name}: 0x{:04X}", u16_value()),
        Kind::Kb16 => match u16_value() {
            0xFFFF => format!("{name}: all available / auto (0xFFFF)"),
            kb => format!("{name}: {kb} KB"),
        },
        Kind::Flags16(names) => {
            let value = u16_value() as u32;
            format!("{name}: 0x{value:04X} ({})", flag_names(value, names))
        }
        Kind::Flags32(names) => {
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{name}: 0x{value:08X} ({})", flag_names(value, names))
        }
        Kind::Str(_) => {
            let text = c_string(bytes);
            format!("{name}: \"{}\"", display(text.trim_end_matches(' ')))
        }
        Kind::Utf16(_) => format!("{name}: \"{}\"", display(&utf16_string(bytes))),
        Kind::Unknown(n) => format!("{name} ({n} bytes)"),
    }
}

fn flag_names(value: u32, names: &[(u32, &str)]) -> String {
    let mut parts = Vec::new();
    let mut known = 0;
    for &(mask, label) in names {
        known |= mask;
        if value & mask == mask {
            parts.push(label.to_string());
        }
    }
    let unknown = value & !known;
    if unknown != 0 {
        parts.push(format!("unknown bits 0x{unknown:X}"));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

const BASIC_FLAGS: &[(u32, &str)] = &[
    (0x0001, "Directly modify memory"),
    (0x0002, "Graphics/multiple text"),
    (0x0004, "Prevent program switch"),
    (0x0008, "No screen exchange"),
    (0x0010, "Close window on exit"),
    (0x0040, "Direct COM1 access"),
    (0x0080, "Direct COM2 access"),
];

const BASIC_FLAGS2: &[(u32, &str)] = &[
    (0x0010, "Direct keyboard access"),
    (0x0020, "Use coprocessor"),
    (0x0040, "Stop in background"),
    (0x0080, "Directly modify screen"),
    (0x2000, "Exchange interrupt vectors"),
    (0x4000, "Parameters on command line"),
];

const BASIC_FIELDS: &[Field] = &[
    f(0x00, "Reserved", Kind::Hex8),
    f(0x01, "Checksum", Kind::Hex8),
    f(0x02, "Window title", Kind::Str(30)),
    f(0x20, "Max conventional memory", Kind::Kb16),
    f(0x22, "Min conventional memory", Kind::Kb16),
    f(0x24, "Program filename", Kind::Str(63)),
    f(0x63, "Flags", Kind::Flags16(BASIC_FLAGS)),
    f(0x65, "Working directory", Kind::Str(64)),
    f(0xA5, "Parameters", Kind::Str(64)),
    f(0xE5, "Video mode", Kind::Hex8),
    f(0xE6, "Text video pages", Kind::U8),
    f(0xE7, "First used interrupt", Kind::Hex8),
    f(0xE8, "Last used interrupt", Kind::Hex8),
    f(0xE9, "Screen rows", Kind::U8),
    f(0xEA, "Screen columns", Kind::U8),
    f(0xEB, "Window X position", Kind::U8),
    f(0xEC, "Window Y position", Kind::U8),
    f(0xED, "Last text video page / flags", Kind::Hex16),
    f(0xEF, "Unknown (unused by Windows)", Kind::Unknown(128)),
    f(0x16F, "Flags 2", Kind::Flags16(BASIC_FLAGS2)),
];

const W386_OPTIONS: &[(u32, &str)] = &[
    (0x0000_0001, "Allow close when active"),
    (0x0000_0002, "Background"),
    (0x0000_0004, "Exclusive"),
    (0x0000_0008, "Full screen"),
    (0x0000_0020, "Reserve Alt+Tab"),
    (0x0000_0040, "Reserve Alt+Esc"),
    (0x0000_0080, "Reserve Alt+Space"),
    (0x0000_0100, "Reserve Alt+Enter"),
    (0x0000_0200, "Reserve Alt+PrtSc"),
    (0x0000_0400, "Reserve PrtSc"),
    (0x0000_0800, "Reserve Ctrl+Esc"),
    (0x0000_1000, "Detect idle time"),
    (0x0000_2000, "No HMA"),
    (0x0000_4000, "Use shortcut key"),
    (0x0000_8000, "EMS locked"),
    (0x0001_0000, "XMS locked"),
    (0x0002_0000, "Fast paste"),
    (0x0004_0000, "Lock application memory"),
    (0x0008_0000, "Memory protection"),
    (0x0010_0000, "Start minimized"),
    (0x0020_0000, "Start maximized"),
    (0x0080_0000, "MS-DOS mode"),
    (0x0100_0000, "Prevent Windows detection"),
    (0x0400_0000, "Don't suggest MS-DOS mode"),
    (0x1000_0000, "Don't warn before MS-DOS mode"),
];

const W386_VIDEO: &[(u32, &str)] = &[
    (0x0001, "Emulate video ROM"),
    (0x0002, "No port monitoring: text"),
    (0x0004, "No port monitoring: low graphics"),
    (0x0008, "No port monitoring: high graphics"),
    (0x0010, "Video memory: text"),
    (0x0020, "Video memory: low graphics"),
    (0x0040, "Video memory: high graphics"),
    (0x0080, "Retain video memory"),
];

const HOTKEY_MODIFIERS: &[(u32, &str)] = &[(0x0003, "Shift"), (0x0004, "Ctrl"), (0x0008, "Alt")];

const W386_FIELDS: &[Field] = &[
    f(0x00, "Max conventional memory", Kind::Kb16),
    f(0x02, "Min conventional memory", Kind::Kb16),
    f(0x04, "Foreground priority", Kind::U16),
    f(0x06, "Background priority", Kind::U16),
    f(0x08, "Max EMS memory", Kind::Kb16),
    f(0x0A, "Min EMS memory", Kind::Kb16),
    f(0x0C, "Max XMS memory", Kind::Kb16),
    f(0x0E, "Min XMS memory", Kind::Kb16),
    f(0x10, "Options", Kind::Flags32(W386_OPTIONS)),
    f(0x14, "Video", Kind::Flags16(W386_VIDEO)),
    f(0x16, "Unknown", Kind::Unknown(2)),
    f(0x18, "Shortcut key scan code", Kind::Hex16),
    f(
        0x1A,
        "Shortcut key modifiers",
        Kind::Flags16(HOTKEY_MODIFIERS),
    ),
    f(0x1C, "Shortcut key in use (0x000F = yes)", Kind::Hex16),
    f(
        0x1E,
        "Shortcut key flags",
        Kind::Flags16(&[(0x0001, "Extended scan code")]),
    ),
    f(0x20, "Unknown", Kind::Unknown(8)),
    f(0x28, "Parameters", Kind::Str(64)),
];

const W286_FLAGS: &[(u32, &str)] = &[
    (0x0001, "Reserve Alt+Tab"),
    (0x0002, "Reserve Alt+Esc"),
    (0x0004, "Reserve Alt+PrtSc"),
    (0x0008, "Reserve PrtSc"),
    (0x0010, "Reserve Ctrl+Esc"),
    (0x0020, "No screen save"),
    (0x4000, "Direct COM3 access"),
    (0x8000, "Direct COM4 access"),
];

const W286_FIELDS: &[Field] = &[
    f(0x00, "Max XMS memory", Kind::Kb16),
    f(0x02, "Min XMS memory", Kind::Kb16),
    f(0x04, "Flags", Kind::Flags16(W286_FLAGS)),
];

const VMM_FLAGS: &[(u32, &str)] = &[
    (0x0002, "Run in background"),
    (0x0010, "Don't warn on exit"),
    (0x0020, "Disallow screen saver"),
];

const VMM_VIDEO: &[(u32, &str)] = &[
    (0x0001, "Emulate video ROM"),
    (0x0080, "No dynamic video memory"),
    (0x0100, "Full screen"),
];

const VMM_KEYS: &[(u32, &str)] = &[
    (0x0001, "Fast paste"),
    (0x0020, "Reserve Alt+Tab"),
    (0x0040, "Reserve Alt+Esc"),
    (0x0080, "Reserve Alt+Space"),
    (0x0100, "Reserve Alt+Enter"),
    (0x0200, "Reserve Alt+PrtSc"),
    (0x0400, "Reserve PrtSc"),
    (0x0800, "Reserve Ctrl+Esc"),
];

const VMM_MOUSE: &[(u32, &str)] = &[(0x0001, "QuickEdit off"), (0x0002, "Exclusive mouse")];

const VMM_FONT: &[(u32, &str)] = &[
    (0x0004, "Raster fonts available"),
    (0x0008, "TrueType fonts available"),
    (0x0010, "Auto font size"),
    (0x0400, "Current font is raster"),
    (0x0800, "Current font is TrueType"),
];

const VMM_FIELDS: &[Field] = &[
    f(0x000, "Unknown", Kind::Unknown(88)),
    f(0x058, "Icon file", Kind::Str(80)),
    f(0x0A8, "Icon index", Kind::U16),
    f(0x0AA, "Flags", Kind::Flags16(VMM_FLAGS)),
    f(0x0AC, "Unknown", Kind::Unknown(10)),
    f(0x0B6, "Idle sensitivity (0 = high priority)", Kind::U16),
    f(0x0B8, "Video", Kind::Flags16(VMM_VIDEO)),
    f(0x0BA, "Unknown", Kind::Unknown(8)),
    f(0x0C2, "Window text lines (0 = auto)", Kind::U16),
    f(0x0C4, "Keyboard", Kind::Flags16(VMM_KEYS)),
    f(0x0C6, "Unknown", Kind::Unknown(16)),
    f(0x0D6, "Mouse", Kind::Flags16(VMM_MOUSE)),
    f(0x0D8, "Unknown", Kind::Unknown(6)),
    f(0x0DE, "Font", Kind::Flags16(VMM_FONT)),
    f(0x0E0, "Unknown", Kind::Unknown(2)),
    f(0x0E2, "Raster font width", Kind::U16),
    f(0x0E4, "Raster font height", Kind::U16),
    f(0x0E6, "Font width", Kind::U16),
    f(0x0E8, "Font height", Kind::U16),
    f(0x0EA, "Raster font name", Kind::Str(32)),
    f(0x10A, "TrueType font name", Kind::Str(32)),
    f(0x12A, "Unknown", Kind::Unknown(2)),
    f(
        0x12C,
        "Window flags",
        Kind::Flags16(&[(0x0002, "Show toolbar")]),
    ),
    f(
        0x12E,
        "Restore flags",
        Kind::Flags16(&[(0x0001, "Don't restore settings at startup")]),
    ),
    f(0x130, "Screen columns", Kind::U16),
    f(0x132, "Screen rows", Kind::U16),
    f(0x134, "Client area width", Kind::U16),
    f(0x136, "Client area height", Kind::U16),
    f(0x138, "Window width", Kind::U16),
    f(0x13A, "Window height", Kind::U16),
    f(0x13C, "Unknown", Kind::Unknown(2)),
    f(0x13E, "Last state flags", Kind::Hex16),
    f(0x140, "Last show state", Kind::Hex16),
    f(0x142, "Unknown", Kind::Unknown(4)),
    f(0x146, "Maximized right", Kind::U16),
    f(0x148, "Maximized bottom", Kind::U16),
    f(0x14A, "Window left", Kind::U16),
    f(0x14C, "Window top", Kind::U16),
    f(0x14E, "Normal right", Kind::U16),
    f(0x150, "Normal bottom", Kind::U16),
    f(0x152, "Unknown", Kind::Unknown(4)),
    f(0x156, "Batch file", Kind::Str(80)),
    f(0x1A6, "Environment memory", Kind::Kb16),
    f(0x1A8, "DPMI memory", Kind::Kb16),
    f(0x1AA, "Unknown", Kind::Unknown(2)),
];

const NT31_FIELDS: &[Field] = &[
    f(
        0x00,
        "Flags",
        Kind::Flags16(&[(0x0010, "Compatible timer emulation")]),
    ),
    f(0x02, "Unknown", Kind::Unknown(10)),
    f(0x0C, "CONFIG.SYS replacement", Kind::Str(64)),
    f(0x4C, "AUTOEXEC.BAT replacement", Kind::Str(64)),
    f(0x8C, "Unknown", Kind::Unknown(2)),
];

const NT40_FIELDS: &[Field] = &[
    f(0x000, "Unknown", Kind::Unknown(4)),
    f(0x004, "Command line (Unicode)", Kind::Utf16(256)),
    f(0x104, "Command line", Kind::Str(128)),
    f(0x184, "Unknown", Kind::Unknown(240)),
    f(0x274, "PIF filename (Unicode)", Kind::Utf16(160)),
    f(0x314, "PIF filename", Kind::Str(80)),
    f(0x364, "Window title (Unicode)", Kind::Utf16(60)),
    f(0x3A0, "Window title", Kind::Str(30)),
    f(0x3BE, "Icon file (Unicode)", Kind::Utf16(160)),
    f(0x45E, "Icon file", Kind::Str(80)),
    f(0x4AE, "Working directory (Unicode)", Kind::Utf16(128)),
    f(0x52E, "Working directory", Kind::Str(64)),
    f(0x56E, "Unknown", Kind::Unknown(286)),
];

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    latin1(&bytes[..end])
}

fn utf16_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn display(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    if cleaned.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = cleaned.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(text: &[u8], len: usize, pad: u8) -> Vec<u8> {
        let mut out = text.to_vec();
        out.resize(len, pad);
        out
    }

    fn build_basic() -> Vec<u8> {
        let mut data = vec![0u8; BASIC_LEN];
        data[1] = 0x78;
        data[0x02..0x20].copy_from_slice(&padded(b"Test Program", 30, b' '));
        data[0x20..0x22].copy_from_slice(&640u16.to_le_bytes());
        data[0x22..0x24].copy_from_slice(&128u16.to_le_bytes());
        data[0x24..0x63].copy_from_slice(&padded(b"C:\\GAME\\GAME.EXE", 63, 0));
        data[0x63] = 0x10;
        data[0x65..0xA5].copy_from_slice(&padded(b"C:\\GAME", 64, 0));
        data[0xA5..0xE5].copy_from_slice(&padded(b"/fast", 64, 0));
        data[0xE6] = 1;
        data[0xE8] = 0xFF;
        data[0xE9] = 25;
        data[0xEA] = 80;
        data[0xED] = 7;
        data[0x16F..0x171].copy_from_slice(&0x20E0u16.to_le_bytes());
        data
    }

    /// Builds a PIF with the PIFEX heading followed by `sections`, each heading
    /// immediately followed by its data, as Windows writes them.
    fn build_pif(sections: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let mut data = build_basic();
        let mut all: Vec<(&[u8], Vec<u8>)> = vec![(b"MICROSOFT PIFEX", Vec::new())];
        all.extend(sections.iter().cloned());
        for (i, (name, body)) in all.iter().enumerate() {
            let heading_start = data.len();
            let (data_offset, data_len) = if i == 0 {
                (0, BASIC_LEN)
            } else {
                (heading_start + HEADING_LEN, body.len())
            };
            let next = if i + 1 == all.len() {
                LAST_HEADING as usize
            } else {
                heading_start + HEADING_LEN + body.len()
            };
            data.extend(padded(name, 16, 0));
            data.extend((next as u16).to_le_bytes());
            data.extend((data_offset as u16).to_le_bytes());
            data.extend((data_len as u16).to_le_bytes());
            data.extend(body);
        }
        data
    }

    fn build_386() -> Vec<u8> {
        let mut body = vec![0u8; 0x68];
        for (i, v) in [640u16, 0, 100, 50, 1024, 0, 0xFFFF, 0].iter().enumerate() {
            body[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        body[0x10..0x14].copy_from_slice(&0x0002_1008u32.to_le_bytes());
        body[0x14..0x16].copy_from_slice(&0x0011u16.to_le_bytes());
        body[0x28..0x2C].copy_from_slice(b"-x 1");
        body
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
    fn matches_pif() {
        assert!(PifDissector.matches(&build_pif(&[])));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!PifDissector.matches(b""));
        assert!(!PifDissector.matches(b"MZ\x90\x00 not a pif"));
        assert!(!PifDissector.matches(&vec![0u8; 0x200]));
        // Basic section only (Windows 1.x/2.x era): too weak to identify.
        assert!(!PifDissector.matches(&build_basic()));
        // Magic present but heading truncated.
        let data = build_pif(&[]);
        assert!(!PifDissector.matches(&data[..BASIC_LEN + 16]));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = build_pif(&[(b"WINDOWS 386 3.0", build_386())]);
        for len in [
            0,
            1,
            0x30,
            BASIC_LEN - 1,
            BASIC_LEN,
            BASIC_LEN + 10,
            0x190,
            0x1C0,
        ] {
            let blocks = PifDissector.dissect(&data[..len]);
            assert!(blocks.len() <= PifDissector.dissect(&data).len());
        }
        assert!(PifDissector.dissect(&data[..0x30]).is_empty());
    }

    #[test]
    fn dissect_basic_section() {
        let data = build_pif(&[]);
        let blocks = PifDissector.dissect(&data);
        let basic = find_block(&blocks, "Basic section");
        assert_eq!(basic.range, ByteRange::new(0, 0x171));
        let title = find_block(&basic.children, "Window title: \"Test Program\"");
        assert_eq!(title.range, ByteRange::new(2, 0x20));
        find_block(&basic.children, "Max conventional memory: 640 KB");
        find_block(&basic.children, "Program filename: \"C:\\GAME\\GAME.EXE\"");
        let flags = find_block(&basic.children, "Flags: 0x0010 (Close window on exit)");
        assert_eq!(flags.range, ByteRange::new(0x63, 0x65));
        let dir = find_block(&basic.children, "Working directory: \"C:\\GAME\"");
        assert_eq!(dir.range, ByteRange::new(0x65, 0xA5));
        find_block(&basic.children, "Parameters: \"/fast\"");
        find_block(&basic.children, "Screen rows: 25");
        find_block(
            &basic.children,
            "Flags 2: 0x20E0 (Use coprocessor, Stop in background, Directly modify screen, \
             Exchange interrupt vectors)",
        );

        let heading = find_block(&blocks, "Section heading: MICROSOFT PIFEX");
        assert_eq!(heading.range, ByteRange::new(0x171, 0x187));
        find_block(&heading.children, "Next heading: 0xFFFF (last)");
        find_block(&heading.children, "Data length: 369 (0x171)");
        assert!(!blocks.iter().any(|b| b.label.starts_with("Section data")));
    }

    #[test]
    fn dissect_extension_sections() {
        let autoexec = b"@ECHO OFF\r\nSET BLASTER=A220\r\n".to_vec();
        let data = build_pif(&[
            (b"WINDOWS 386 3.0", build_386()),
            (b"WINDOWS 286 3.0", vec![0x00, 0x04, 0, 0, 0x21, 0x00]),
            (b"AUTOEXECBAT 4.0", autoexec),
        ]);
        let blocks = PifDissector.dissect(&data);

        let h386 = find_block(&blocks, "Section heading: WINDOWS 386 3.0");
        assert_eq!(h386.range, ByteRange::new(0x187, 0x19D));
        let d386 = find_block(&blocks, "Section data: WINDOWS 386 3.0");
        assert_eq!(d386.range, ByteRange::new(0x19D, 0x19D + 0x68));
        find_block(&d386.children, "Foreground priority: 100");
        find_block(&d386.children, "Max EMS memory: 1024 KB");
        find_block(
            &d386.children,
            "Max XMS memory: all available / auto (0xFFFF)",
        );
        let options = find_block(
            &d386.children,
            "Options: 0x00021008 (Full screen, Detect idle time, Fast paste)",
        );
        assert_eq!(options.range, ByteRange::new(0x19D + 0x10, 0x19D + 0x14));
        find_block(
            &d386.children,
            "Video: 0x0011 (Emulate video ROM, Video memory: text)",
        );
        find_block(&d386.children, "Parameters: \"-x 1\"");

        let d286 = find_block(&blocks, "Section data: WINDOWS 286 3.0");
        find_block(&d286.children, "Max XMS memory: 1024 KB");
        find_block(
            &d286.children,
            "Flags: 0x0021 (Reserve Alt+Tab, No screen save)",
        );

        let bat = find_block(&blocks, "Section data: AUTOEXECBAT 4.0");
        let line = find_block(&bat.children, "Line: \"@ECHO OFF\"");
        assert_eq!(line.range.end - line.range.start, 11);
        find_block(&bat.children, "Line: \"SET BLASTER=A220\"");
        assert_eq!(bat.range.end as usize, data.len());
        assert!(!blocks.iter().any(|b| b.label.starts_with("Trailing")));
    }

    #[test]
    fn dissect_stops_on_cyclic_chain() {
        let mut data = build_pif(&[(b"WINDOWS 286 3.0", vec![0; 6])]);
        // Point the last heading back at the first.
        let last = BASIC_LEN + HEADING_LEN;
        data[last + 16..last + 18].copy_from_slice(&(BASIC_LEN as u16).to_le_bytes());
        let blocks = PifDissector.dissect(&data);
        let headings = blocks
            .iter()
            .filter(|b| b.label.starts_with("Section heading"))
            .count();
        assert_eq!(headings, 2);
    }

    #[test]
    fn identify_returns_pif() {
        let data = build_pif(&[(b"WINDOWS 386 3.0", build_386())]);
        assert_eq!(super::super::identify(&data), "PIF");
    }
}
