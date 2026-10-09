//! Linear Executable dissector: LE (DOS extenders such as DOS/4GW, Windows
//! VxDs) and LX (OS/2 2.x and later).
//!
//! Most table offsets in the LE/LX header are relative to the start of the
//! LE/LX header; the data pages, iterated pages, non-resident name table and
//! debug info offsets are relative to the start of the file.

use super::{Block, ByteRange, Dissector};

const DOS_MAGIC: &[u8] = b"MZ";
const E_LFANEW_OFFSET: u64 = 0x3C;
const DOS_HEADER_SIZE: u64 = 64;
/// Size of the full header including the trailing reserved / VxD fields.
const HEADER_SIZE: u64 = 0xC4;
/// Size of the part of the header that every table lookup depends on.
const CORE_HEADER_SIZE: u64 = 0xB0;
const OBJECT_ENTRY_SIZE: u64 = 24;
const RESOURCE_ENTRY_SIZE: u64 = 14;
const DIRECTIVE_ENTRY_SIZE: u64 = 8;
/// Maximum number of child blocks listed per table before summarizing.
const MAX_ENTRIES: usize = 256;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Le,
    Lx,
}

impl Kind {
    fn signature(self) -> &'static [u8] {
        match self {
            Kind::Le => b"LE",
            Kind::Lx => b"LX",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Le => "LE",
            Kind::Lx => "LX",
        }
    }
}

pub struct LeDissector;
pub struct LxDissector;

impl Dissector for LeDissector {
    fn name(&self) -> &'static str {
        "LE"
    }

    fn matches(&self, data: &[u8]) -> bool {
        header_offset(data, Kind::Le).is_some()
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        dissect_linear(data, Kind::Le)
    }
}

impl Dissector for LxDissector {
    fn name(&self) -> &'static str {
        "LX"
    }

    fn matches(&self, data: &[u8]) -> bool {
        header_offset(data, Kind::Lx).is_some()
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        dissect_linear(data, Kind::Lx)
    }
}

// ---------------------------------------------------------------------------
// Reading helpers

fn get(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn read_u8(data: &[u8], offset: u64) -> Option<u8> {
    get(data, offset, 1).map(|b| b[0])
}

fn read_u16(data: &[u8], offset: u64) -> Option<u16> {
    let bytes: [u8; 2] = get(data, offset, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: u64) -> Option<u32> {
    let bytes: [u8; 4] = get(data, offset, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Range starting at `start` of `len` bytes, clamped to the data. `None` if
/// `start` lies outside the data or the clamped range is empty.
fn clamp(data: &[u8], start: u64, len: u64) -> Option<ByteRange> {
    let size = data.len() as u64;
    if start >= size || len == 0 {
        return None;
    }
    Some(ByteRange::new(start, start.saturating_add(len).min(size)))
}

/// Reads a length-prefixed string at `offset`. Returns (name, total length
/// including the length byte).
fn read_pascal(data: &[u8], offset: u64) -> Option<(String, u64)> {
    let len = read_u8(data, offset)? as usize;
    let bytes = get(data, offset + 1, len)?;
    Some((String::from_utf8_lossy(bytes).into_owned(), len as u64 + 1))
}

// ---------------------------------------------------------------------------
// Matching

fn valid_signature(data: &[u8], offset: u64, kind: Kind) -> bool {
    get(data, offset, 4)
        .map(|b| &b[0..2] == kind.signature() && b[2] == 0 && b[3] == 0)
        .unwrap_or(false)
}

fn header_offset(data: &[u8], kind: Kind) -> Option<u64> {
    if data.starts_with(DOS_MAGIC) {
        let offset = read_u32(data, E_LFANEW_OFFSET)? as u64;
        return valid_signature(data, offset, kind).then_some(offset);
    }
    // Bare LE/LX image: the signature alone is weak, so sanity-check fields.
    if !valid_signature(data, 0, kind) || (data.len() as u64) < CORE_HEADER_SIZE {
        return None;
    }
    let format_level = read_u32(data, 0x04)?;
    let cpu = read_u16(data, 0x08)?;
    let os = read_u16(data, 0x0A)?;
    let page_size = read_u32(data, 0x28)?;
    let plausible = format_level == 0
        && cpu_name(cpu).is_some()
        && os <= 5
        && page_size.is_power_of_two()
        && (16..=0x10000).contains(&page_size);
    plausible.then_some(0)
}

// ---------------------------------------------------------------------------
// Value names

fn cpu_name(value: u16) -> Option<&'static str> {
    Some(match value {
        0x01 => "80286",
        0x02 => "80386",
        0x03 => "80486",
        0x04 => "Pentium (80586)",
        0x20 => "Intel i860 (N10)",
        0x21 => "Intel N11",
        0x40 => "MIPS Mark I (R2000/R3000)",
        0x41 => "MIPS Mark II (R6000)",
        0x42 => "MIPS Mark III (R4000)",
        _ => return None,
    })
}

fn os_name(value: u16) -> String {
    match value {
        0 => "unknown (0)".to_string(),
        1 => "OS/2".to_string(),
        2 => "Windows".to_string(),
        3 => "DOS 4.x".to_string(),
        4 => "Windows 386".to_string(),
        5 => "IBM Microkernel Personality Neutral".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn byte_order_name(value: u8) -> String {
    match value {
        0 => "little-endian (0)".to_string(),
        1 => "big-endian (1)".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn module_flags_desc(flags: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    parts.push(match flags & 0x38000 {
        0x00000 => "program",
        0x08000 => "library (DLL)",
        0x18000 => "protected memory library",
        0x20000 => "physical device driver",
        0x28000 => "virtual device driver",
        0x38000 => "Windows VxD",
        _ => "unknown module type",
    });
    if flags & 0x4 != 0 {
        parts.push("per-process library initialization");
    }
    if flags & 0x10 != 0 {
        parts.push("internal fixups removed");
    }
    if flags & 0x20 != 0 {
        parts.push("external fixups removed");
    }
    match flags & 0x300 {
        0x100 => parts.push("PM incompatible"),
        0x200 => parts.push("PM compatible"),
        0x300 => parts.push("uses PM"),
        _ => {}
    }
    if flags & 0x2000 != 0 {
        parts.push("not loadable");
    }
    if flags & 0x80000 != 0 {
        parts.push("MP unsafe");
    }
    if flags & 0x40000000 != 0 {
        parts.push("per-process library termination");
    }
    format!("{flags:#010x} ({})", parts.join(", "))
}

fn object_flags_desc(flags: u32) -> String {
    const BITS: &[(u32, &str)] = &[
        (0x0001, "readable"),
        (0x0002, "writable"),
        (0x0004, "executable"),
        (0x0008, "resource"),
        (0x0010, "discardable"),
        (0x0020, "shared"),
        (0x0040, "preload"),
        (0x0080, "invalid"),
        (0x1000, "16:16 alias"),
        (0x2000, "32-bit"),
        (0x4000, "conforming"),
        (0x8000, "I/O privilege"),
    ];
    let mut parts: Vec<&str> = BITS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    match flags & 0x700 {
        0x100 => parts.push("zero-filled"),
        0x200 => parts.push("resident"),
        0x300 => parts.push("resident & contiguous"),
        0x400 => parts.push("resident & long-lockable"),
        _ => {}
    }
    if parts.is_empty() {
        format!("{flags:#06x}")
    } else {
        format!("{flags:#06x} ({})", parts.join(", "))
    }
}

fn page_flags_name(flags: u16) -> String {
    match flags {
        0 => "legal".to_string(),
        1 => "iterated".to_string(),
        2 => "invalid".to_string(),
        3 => "zero-filled".to_string(),
        4 => "range".to_string(),
        5 => "compressed".to_string(),
        _ => format!("unknown ({flags})"),
    }
}

fn resource_type_name(value: u16) -> String {
    let name = match value {
        1 => "pointer",
        2 => "bitmap",
        3 => "menu",
        4 => "dialog",
        5 => "string table",
        6 => "font directory",
        7 => "font",
        8 => "accelerator table",
        9 => "RC data",
        10 => "message table",
        11 => "dialog include",
        12 => "virtual key table",
        13 => "key table",
        14 => "character table",
        15 => "display info",
        16 => "FKA short",
        17 => "FKA long",
        18 => "help table",
        19 => "help subtable",
        20 => "DBCS font directory",
        21 => "DBCS font",
        _ => return value.to_string(),
    };
    format!("{name} ({value})")
}

// ---------------------------------------------------------------------------
// Header

/// Fields from the LE/LX header that the table parsers need. Header-relative
/// offsets are already converted to file offsets (0 means absent).
struct Header {
    kind: Kind,
    num_pages: u32,
    page_size: u32,
    last_page_or_shift: u32,
    fixup_size: u32,
    object_table: u64,
    num_objects: u32,
    page_table: u64,
    resource_table: u64,
    num_resources: u32,
    resident_names: u64,
    entry_table: u64,
    directives: u64,
    num_directives: u32,
    fixup_page_table: u64,
    fixup_record_table: u64,
    import_modules: u64,
    num_import_modules: u32,
    import_procs: u64,
    page_checksums: u64,
    data_pages: u64,
    nonresident_names: u64,
    nonresident_length: u32,
    debug_info: u64,
    debug_length: u32,
}

impl Header {
    fn parse(data: &[u8], offset: u64, kind: Kind) -> Option<Header> {
        let u32_at = |rel: u64| read_u32(data, offset + rel);
        let rel = |field: u64| -> Option<u64> {
            let value = u32_at(field)? as u64;
            Some(if value == 0 { 0 } else { offset + value })
        };
        let abs = |field: u64| -> Option<u64> { Some(u32_at(field)? as u64) };
        // Make sure the whole core header is present.
        get(data, offset, CORE_HEADER_SIZE as usize)?;
        Some(Header {
            kind,
            num_pages: u32_at(0x14)?,
            page_size: u32_at(0x28)?,
            last_page_or_shift: u32_at(0x2C)?,
            fixup_size: u32_at(0x30)?,
            object_table: rel(0x40)?,
            num_objects: u32_at(0x44)?,
            page_table: rel(0x48)?,
            resource_table: rel(0x50)?,
            num_resources: u32_at(0x54)?,
            resident_names: rel(0x58)?,
            entry_table: rel(0x5C)?,
            directives: rel(0x60)?,
            num_directives: u32_at(0x64)?,
            fixup_page_table: rel(0x68)?,
            fixup_record_table: rel(0x6C)?,
            import_modules: rel(0x70)?,
            num_import_modules: u32_at(0x74)?,
            import_procs: rel(0x78)?,
            page_checksums: rel(0x7C)?,
            data_pages: abs(0x80)?,
            nonresident_names: abs(0x88)?,
            nonresident_length: u32_at(0x8C)?,
            debug_info: abs(0x98)?,
            debug_length: u32_at(0x9C)?,
        })
    }

    fn page_entry_size(&self) -> u64 {
        match self.kind {
            Kind::Le => 4,
            Kind::Lx => 8,
        }
    }
}

#[derive(Clone, Copy)]
enum Fmt {
    Dec,
    Hex,
    /// Offset relative to the LE/LX header.
    Rel,
    /// Offset relative to the start of the file.
    Abs,
}

fn header_block(data: &[u8], offset: u64, kind: Kind) -> Option<Block> {
    let name = kind.name();
    // The header normally runs to 0xC4, but the loader section may start
    // earlier in files with a shorter header.
    let mut header_len = HEADER_SIZE;
    if let Some(obj) = read_u32(data, offset + 0x40) {
        let obj = obj as u64;
        if (CORE_HEADER_SIZE..HEADER_SIZE).contains(&obj) {
            header_len = obj;
        }
    }
    let range = clamp(data, offset, header_len)?;
    let end = range.end;
    let mut children = Vec::new();

    let mut leaf = |rel: u64, size: u64, label: String| {
        if offset + rel + size <= end {
            children.push(Block::leaf(
                label,
                ByteRange::new(offset + rel, offset + rel + size),
            ));
        }
    };

    leaf(0, 2, format!("Signature: {name}"));
    if let Some(b) = read_u8(data, offset + 2) {
        leaf(2, 1, format!("Byte order: {}", byte_order_name(b)));
    }
    if let Some(b) = read_u8(data, offset + 3) {
        leaf(3, 1, format!("Word order: {}", byte_order_name(b)));
    }
    if let Some(v) = read_u32(data, offset + 4) {
        leaf(4, 4, format!("Format level: {v}"));
    }
    if let Some(v) = read_u16(data, offset + 8) {
        let cpu = cpu_name(v)
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown ({v:#x})"));
        leaf(8, 2, format!("CPU type: {cpu}"));
    }
    if let Some(v) = read_u16(data, offset + 0x0A) {
        leaf(0x0A, 2, format!("OS type: {}", os_name(v)));
    }

    let last_page_label = match kind {
        Kind::Le => "Last page size",
        Kind::Lx => "Page offset shift",
    };
    let u32_fields: &[(u64, &str, Fmt)] = &[
        (0x0C, "Module version", Fmt::Dec),
        (0x14, "Number of pages", Fmt::Dec),
        (0x18, "EIP object", Fmt::Dec),
        (0x1C, "EIP offset", Fmt::Hex),
        (0x20, "ESP object", Fmt::Dec),
        (0x24, "ESP offset", Fmt::Hex),
        (0x28, "Page size", Fmt::Dec),
        (0x2C, last_page_label, Fmt::Dec),
        (0x30, "Fixup section size", Fmt::Dec),
        (0x34, "Fixup section checksum", Fmt::Hex),
        (0x38, "Loader section size", Fmt::Dec),
        (0x3C, "Loader section checksum", Fmt::Hex),
        (0x40, "Object table offset", Fmt::Rel),
        (0x44, "Number of objects", Fmt::Dec),
        (0x48, "Object page table offset", Fmt::Rel),
        (0x4C, "Object iterated pages offset", Fmt::Abs),
        (0x50, "Resource table offset", Fmt::Rel),
        (0x54, "Number of resources", Fmt::Dec),
        (0x58, "Resident name table offset", Fmt::Rel),
        (0x5C, "Entry table offset", Fmt::Rel),
        (0x60, "Module directives offset", Fmt::Rel),
        (0x64, "Number of module directives", Fmt::Dec),
        (0x68, "Fixup page table offset", Fmt::Rel),
        (0x6C, "Fixup record table offset", Fmt::Rel),
        (0x70, "Import module table offset", Fmt::Rel),
        (0x74, "Number of import modules", Fmt::Dec),
        (0x78, "Import procedure table offset", Fmt::Rel),
        (0x7C, "Per-page checksum table offset", Fmt::Rel),
        (0x80, "Data pages offset", Fmt::Abs),
        (0x84, "Number of preload pages", Fmt::Dec),
        (0x88, "Non-resident name table offset", Fmt::Abs),
        (0x8C, "Non-resident name table length", Fmt::Dec),
        (0x90, "Non-resident name table checksum", Fmt::Hex),
        (0x94, "Auto data object", Fmt::Dec),
        (0x98, "Debug info offset", Fmt::Abs),
        (0x9C, "Debug info length", Fmt::Dec),
        (0xA0, "Instance pages in preload section", Fmt::Dec),
        (0xA4, "Instance pages on demand", Fmt::Dec),
        (0xA8, "Heap size", Fmt::Dec),
    ];

    let format_u32 = |rel: u64, label: &str, fmt: Fmt| -> Option<Block> {
        let v = read_u32(data, offset + rel)?;
        if offset + rel + 4 > end {
            return None;
        }
        let text = match fmt {
            Fmt::Dec => format!("{label}: {v}"),
            Fmt::Hex => format!("{label}: {v:#x}"),
            Fmt::Rel if v == 0 => format!("{label}: 0 (none)"),
            Fmt::Rel => format!("{label}: {v:#x} (file {:#x})", offset + v as u64),
            Fmt::Abs if v == 0 => format!("{label}: 0 (none)"),
            Fmt::Abs => format!("{label}: {v:#x}"),
        };
        Some(Block::leaf(
            text,
            ByteRange::new(offset + rel, offset + rel + 4),
        ))
    };

    for &(rel, label, fmt) in u32_fields {
        if rel == 0x10 {
            continue;
        }
        if let Some(block) = format_u32(rel, label, fmt) {
            children.push(block);
        }
        if rel == 0x0C {
            if let Some(flags) = read_u32(data, offset + 0x10) {
                if offset + 0x14 <= end {
                    children.push(Block::leaf(
                        format!("Module flags: {}", module_flags_desc(flags)),
                        ByteRange::new(offset + 0x10, offset + 0x14),
                    ));
                }
            }
        }
    }

    // Trailing fields differ between LX and LE (VxD) headers.
    match kind {
        Kind::Lx => {
            if let Some(block) = format_u32(0xAC, "Stack size", Fmt::Dec) {
                children.push(block);
            }
            if end > offset + 0xB0 {
                children.push(Block::leaf("Reserved", ByteRange::new(offset + 0xB0, end)));
            }
        }
        Kind::Le => {
            if end > offset + 0xAC {
                let reserved_end = end.min(offset + 0xB8);
                children.push(Block::leaf(
                    "Reserved",
                    ByteRange::new(offset + 0xAC, reserved_end),
                ));
            }
            if let Some(block) = format_u32(0xB8, "Windows resource offset", Fmt::Abs) {
                children.push(block);
            }
            if let Some(block) = format_u32(0xBC, "Windows resource length", Fmt::Dec) {
                children.push(block);
            }
            if offset + 0xC4 <= end {
                if let (Some(id), Some(ddk)) =
                    (read_u16(data, offset + 0xC0), read_u16(data, offset + 0xC2))
                {
                    children.push(Block::leaf(
                        format!("Device ID: {id:#06x}"),
                        ByteRange::new(offset + 0xC0, offset + 0xC2),
                    ));
                    children.push(Block::leaf(
                        format!("DDK version: {}.{}", ddk >> 8, ddk & 0xFF),
                        ByteRange::new(offset + 0xC2, offset + 0xC4),
                    ));
                }
            }
        }
    }

    Some(Block::node(format!("{name} header"), range, children).expanded())
}

// ---------------------------------------------------------------------------
// DOS header

fn dos_header_block(data: &[u8], kind: Kind) -> Block {
    let mut children = vec![Block::leaf("Signature: MZ", ByteRange::new(0, 2))];
    let u16_fields: &[(u64, &str)] = &[
        (0x02, "Bytes on last page"),
        (0x04, "Pages in file"),
        (0x06, "Relocations"),
        (0x08, "Header size (paragraphs)"),
        (0x0A, "Minimum extra paragraphs"),
        (0x0C, "Maximum extra paragraphs"),
        (0x0E, "Initial SS"),
        (0x10, "Initial SP"),
        (0x12, "Checksum"),
        (0x14, "Initial IP"),
        (0x16, "Initial CS"),
        (0x18, "Relocation table offset"),
        (0x1A, "Overlay number"),
    ];
    for &(off, label) in u16_fields {
        if let Some(v) = read_u16(data, off) {
            let text = if off >= 0x0E && off != 0x1A {
                format!("{label}: {v:#06x}")
            } else {
                format!("{label}: {v}")
            };
            children.push(Block::leaf(text, ByteRange::new(off, off + 2)));
        }
    }
    children.push(Block::leaf("Reserved", ByteRange::new(0x1C, 0x24)));
    if let Some(v) = read_u16(data, 0x24) {
        children.push(Block::leaf(
            format!("OEM ID: {v}"),
            ByteRange::new(0x24, 0x26),
        ));
    }
    if let Some(v) = read_u16(data, 0x26) {
        children.push(Block::leaf(
            format!("OEM info: {v}"),
            ByteRange::new(0x26, 0x28),
        ));
    }
    children.push(Block::leaf(
        "Reserved",
        ByteRange::new(0x28, E_LFANEW_OFFSET),
    ));
    let e_lfanew = read_u32(data, E_LFANEW_OFFSET).unwrap_or(0);
    children.push(Block::leaf(
        format!("{} header offset: {e_lfanew}", kind.name()),
        ByteRange::new(E_LFANEW_OFFSET, E_LFANEW_OFFSET + 4),
    ));
    Block::node("DOS header", ByteRange::new(0, DOS_HEADER_SIZE), children).expanded()
}

// ---------------------------------------------------------------------------
// Tables

/// Appends a summary leaf for entries that were not listed individually.
fn push_more(children: &mut Vec<Block>, more: usize, range: Option<ByteRange>) {
    if more > 0 {
        if let Some(range) = range {
            children.push(Block::leaf(format!("({more} more entries)"), range));
        }
    }
}

fn object_table_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.object_table == 0 || h.num_objects == 0 {
        return None;
    }
    let total = h.num_objects as u64 * OBJECT_ENTRY_SIZE;
    let range = clamp(data, h.object_table, total)?;
    let mut children = Vec::new();
    for i in 0..h.num_objects as u64 {
        let off = h.object_table + i * OBJECT_ENTRY_SIZE;
        if off + OBJECT_ENTRY_SIZE > range.end {
            break;
        }
        if children.len() >= MAX_ENTRIES {
            let more = (range.end - off) / OBJECT_ENTRY_SIZE;
            push_more(
                &mut children,
                more as usize,
                Some(ByteRange::new(off, range.end)),
            );
            break;
        }
        let field = |rel: u64| read_u32(data, off + rel).unwrap_or(0);
        let leaf =
            |rel: u64, label: String| Block::leaf(label, ByteRange::new(off + rel, off + rel + 4));
        let flags = field(8);
        children.push(Block::node(
            format!("Object {}", i + 1),
            ByteRange::new(off, off + OBJECT_ENTRY_SIZE),
            vec![
                leaf(0, format!("Virtual size: {}", field(0))),
                leaf(4, format!("Relocation base: {:#x}", field(4))),
                leaf(8, format!("Flags: {}", object_flags_desc(flags))),
                leaf(12, format!("Page table index: {}", field(12))),
                leaf(16, format!("Page count: {}", field(16))),
                leaf(20, format!("Reserved: {}", field(20))),
            ],
        ));
    }
    Some(Block::node(
        format!("Object table ({} objects)", h.num_objects),
        range,
        children,
    ))
}

/// One decoded object page table entry.
struct PageEntry {
    entry_range: ByteRange,
    /// LE: physical page number. LX: page data offset (before shifting).
    number_or_offset: u32,
    /// LX only: size of the page data.
    size: u16,
    flags: u16,
}

fn page_entries(data: &[u8], h: &Header) -> Vec<PageEntry> {
    let mut entries = Vec::new();
    if h.page_table == 0 {
        return entries;
    }
    let size = h.page_entry_size();
    for i in 0..h.num_pages as u64 {
        let off = h.page_table + i * size;
        let Some(bytes) = get(data, off, size as usize) else {
            break;
        };
        let entry = match h.kind {
            Kind::Le => PageEntry {
                entry_range: ByteRange::new(off, off + size),
                number_or_offset: (bytes[0] as u32) << 16
                    | (bytes[1] as u32) << 8
                    | bytes[2] as u32,
                size: 0,
                flags: bytes[3] as u16,
            },
            Kind::Lx => PageEntry {
                entry_range: ByteRange::new(off, off + size),
                number_or_offset: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                size: u16::from_le_bytes([bytes[4], bytes[5]]),
                flags: u16::from_le_bytes([bytes[6], bytes[7]]),
            },
        };
        entries.push(entry);
    }
    entries
}

fn page_table_block(data: &[u8], h: &Header, entries: &[PageEntry]) -> Option<Block> {
    if h.page_table == 0 || h.num_pages == 0 {
        return None;
    }
    let range = clamp(data, h.page_table, h.num_pages as u64 * h.page_entry_size())?;
    let mut children = Vec::new();
    for (i, e) in entries.iter().enumerate().take(MAX_ENTRIES) {
        let flags = page_flags_name(e.flags);
        let label = match h.kind {
            Kind::Le => format!(
                "Page {}: page number {}, {flags}",
                i + 1,
                e.number_or_offset
            ),
            Kind::Lx => format!(
                "Page {}: offset {:#x}, size {}, {flags}",
                i + 1,
                e.number_or_offset,
                e.size
            ),
        };
        children.push(Block::leaf(label, e.entry_range));
    }
    if entries.len() > MAX_ENTRIES {
        let start = entries[MAX_ENTRIES].entry_range.start;
        push_more(
            &mut children,
            entries.len() - MAX_ENTRIES,
            Some(ByteRange::new(start, range.end)),
        );
    }
    Some(Block::node(
        format!("Object page table ({} entries)", h.num_pages),
        range,
        children,
    ))
}

fn resource_table_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.resource_table == 0 || h.num_resources == 0 {
        return None;
    }
    let range = clamp(
        data,
        h.resource_table,
        h.num_resources as u64 * RESOURCE_ENTRY_SIZE,
    )?;
    let mut children = Vec::new();
    for i in 0..h.num_resources as u64 {
        let off = h.resource_table + i * RESOURCE_ENTRY_SIZE;
        if off + RESOURCE_ENTRY_SIZE > range.end {
            break;
        }
        if children.len() >= MAX_ENTRIES {
            let more = (range.end - off) / RESOURCE_ENTRY_SIZE;
            push_more(
                &mut children,
                more as usize,
                Some(ByteRange::new(off, range.end)),
            );
            break;
        }
        let type_id = read_u16(data, off).unwrap_or(0);
        let name_id = read_u16(data, off + 2).unwrap_or(0);
        let size = read_u32(data, off + 4).unwrap_or(0);
        let object = read_u16(data, off + 8).unwrap_or(0);
        let offset = read_u32(data, off + 10).unwrap_or(0);
        children.push(Block::leaf(
            format!(
                "Resource {}: type {}, name {name_id}, size {size}, object {object}, offset {offset:#x}",
                i + 1,
                resource_type_name(type_id)
            ),
            ByteRange::new(off, off + RESOURCE_ENTRY_SIZE),
        ));
    }
    Some(Block::node(
        format!("Resource table ({} entries)", h.num_resources),
        range,
        children,
    ))
}

/// Resident / non-resident name table: (length, name, ordinal) entries ending
/// with a zero length byte. The first entry is the module name (resident) or
/// module description (non-resident).
fn name_table_block(
    data: &[u8],
    start: u64,
    limit: Option<u64>,
    title: &str,
    first_label: &str,
) -> Option<Block> {
    if start == 0 || start >= data.len() as u64 {
        return None;
    }
    let limit = limit.unwrap_or(u64::MAX).min(data.len() as u64);
    let mut children = Vec::new();
    let mut off = start;
    let mut count = 0usize;
    let mut more_start = None;
    while off < limit {
        let len = read_u8(data, off)? as u64;
        if len == 0 {
            if more_start.is_none() {
                children.push(Block::leaf("End of table", ByteRange::new(off, off + 1)));
            }
            off += 1;
            break;
        }
        let entry_len = 1 + len + 2;
        if off + entry_len > limit {
            break;
        }
        if count >= MAX_ENTRIES {
            more_start.get_or_insert(off);
        } else {
            let (name, _) = read_pascal(data, off)?;
            let ordinal = read_u16(data, off + 1 + len)?;
            let label = if count == 0 {
                format!("{first_label}: {name}")
            } else {
                format!("Name: {name} (ordinal {ordinal})")
            };
            children.push(Block::leaf(label, ByteRange::new(off, off + entry_len)));
        }
        count += 1;
        off += entry_len;
    }
    if let Some(ms) = more_start {
        push_more(
            &mut children,
            count - MAX_ENTRIES,
            Some(ByteRange::new(ms, off)),
        );
    }
    if off <= start {
        return None;
    }
    let names = count.saturating_sub(1);
    Some(Block::node(
        format!("{title} ({names} names)"),
        ByteRange::new(start, off),
        children,
    ))
}

fn entry_flags_desc(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("exported".to_string());
    }
    if flags & 0x02 != 0 {
        parts.push("shared data".to_string());
    }
    let params = flags >> 3;
    if params != 0 {
        parts.push(format!("{params} parameter words"));
    }
    if parts.is_empty() {
        format!("{flags:#04x}")
    } else {
        format!("{flags:#04x} ({})", parts.join(", "))
    }
}

fn entry_table_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.entry_table == 0 || h.entry_table >= data.len() as u64 {
        return None;
    }
    let mut bundles = Vec::new();
    let mut off = h.entry_table;
    let mut ordinal: u64 = 1;
    let mut total_entries = 0u64;
    let mut bundle_count = 0usize;
    let mut skipped_bundles = 0usize;
    let mut skipped_start = None;
    loop {
        let Some(count) = read_u8(data, off) else {
            break;
        };
        if count == 0 {
            if skipped_start.is_none() {
                bundles.push(Block::leaf("End of table", ByteRange::new(off, off + 1)));
            }
            off += 1;
            break;
        }
        let Some(raw_type) = read_u8(data, off + 1) else {
            break;
        };
        let bundle_type = raw_type & 0x7F;
        let first = ordinal;
        let last = ordinal + count as u64 - 1;
        let bundle_start = off;
        let (header_len, entry_size, type_name) = match bundle_type {
            0 => (2u64, 0u64, "unused"),
            1 => (4, 3, "16-bit"),
            2 => (4, 5, "286 call gate"),
            3 => (4, 5, "32-bit"),
            4 => (4, 7, "forwarder"),
            _ => break,
        };
        let bundle_end = off + header_len + count as u64 * entry_size;
        if bundle_end > data.len() as u64 {
            break;
        }
        bundle_count += 1;
        let listing = bundles.len() < MAX_ENTRIES && skipped_start.is_none();
        if !listing {
            skipped_bundles += 1;
            skipped_start.get_or_insert(bundle_start);
        } else if bundle_type == 0 {
            bundles.push(Block::leaf(
                format!("Bundle {bundle_count}: {count} unused ordinals ({first}-{last})"),
                ByteRange::new(off, bundle_end),
            ));
        } else {
            let object = read_u16(data, off + 2).unwrap_or(0);
            let mut entries = vec![
                Block::leaf(format!("Count: {count}"), ByteRange::new(off, off + 1)),
                Block::leaf(
                    format!("Type: {type_name} ({raw_type:#04x})"),
                    ByteRange::new(off + 1, off + 2),
                ),
                Block::leaf(
                    if bundle_type == 4 {
                        "Reserved".to_string()
                    } else {
                        format!("Object: {object}")
                    },
                    ByteRange::new(off + 2, off + 4),
                ),
            ];
            for j in 0..count as u64 {
                let e = off + header_len + j * entry_size;
                let ord = first + j;
                let flags = read_u8(data, e).unwrap_or(0);
                let label = match bundle_type {
                    1 => format!(
                        "Ordinal {ord}: offset {:#06x}, flags {}",
                        read_u16(data, e + 1).unwrap_or(0),
                        entry_flags_desc(flags)
                    ),
                    2 => format!(
                        "Ordinal {ord}: offset {:#06x}, call gate {:#06x}, flags {}",
                        read_u16(data, e + 1).unwrap_or(0),
                        read_u16(data, e + 3).unwrap_or(0),
                        entry_flags_desc(flags)
                    ),
                    3 => format!(
                        "Ordinal {ord}: offset {:#x}, flags {}",
                        read_u32(data, e + 1).unwrap_or(0),
                        entry_flags_desc(flags)
                    ),
                    _ => {
                        let module = read_u16(data, e + 1).unwrap_or(0);
                        let target = read_u32(data, e + 3).unwrap_or(0);
                        if flags & 0x01 != 0 {
                            format!("Ordinal {ord}: forwarder to module {module}, ordinal {target}")
                        } else {
                            format!(
                                "Ordinal {ord}: forwarder to module {module}, name offset {target:#x}"
                            )
                        }
                    }
                };
                entries.push(Block::leaf(label, ByteRange::new(e, e + entry_size)));
            }
            bundles.push(Block::node(
                format!("Bundle {bundle_count}: {count} {type_name} entries, object {object}"),
                ByteRange::new(off, bundle_end),
                entries,
            ));
        }
        if bundle_type != 0 {
            total_entries += count as u64;
        }
        ordinal = last + 1;
        off = bundle_end;
    }
    if let Some(start) = skipped_start {
        bundles.push(Block::leaf(
            format!("({skipped_bundles} more bundles)"),
            ByteRange::new(start, off),
        ));
    }
    if off <= h.entry_table {
        return None;
    }
    Some(Block::node(
        format!("Entry table ({bundle_count} bundles, {total_entries} entries)"),
        ByteRange::new(h.entry_table, off),
        bundles,
    ))
}

fn directives_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.directives == 0 || h.num_directives == 0 {
        return None;
    }
    let range = clamp(
        data,
        h.directives,
        h.num_directives as u64 * DIRECTIVE_ENTRY_SIZE,
    )?;
    let mut children = Vec::new();
    for i in 0..h.num_directives as u64 {
        let off = h.directives + i * DIRECTIVE_ENTRY_SIZE;
        if off + DIRECTIVE_ENTRY_SIZE > range.end || children.len() >= MAX_ENTRIES {
            break;
        }
        let number = read_u16(data, off).unwrap_or(0);
        let length = read_u16(data, off + 2).unwrap_or(0);
        let data_off = read_u32(data, off + 4).unwrap_or(0);
        let kind = if number & 0x8000 != 0 {
            "resident"
        } else {
            "non-resident"
        };
        children.push(Block::leaf(
            format!(
                "Directive {}: number {number:#06x} ({kind}), length {length}, offset {data_off:#x}",
                i + 1
            ),
            ByteRange::new(off, off + DIRECTIVE_ENTRY_SIZE),
        ));
    }
    Some(Block::node(
        format!("Module directives ({} entries)", h.num_directives),
        range,
        children,
    ))
}

/// Length in bytes of the fixup record at `off`, or `None` if it is
/// malformed or runs past `end`.
fn fixup_record_len(data: &[u8], off: u64, end: u64) -> Option<u64> {
    let src = read_u8(data, off)?;
    let flags = read_u8(data, off + 1)?;
    let mut p = off + 2;
    let source_list = src & 0x20 != 0;
    let mut list_count = 0u64;
    if source_list {
        list_count = read_u8(data, p)? as u64;
        p += 1;
    } else {
        p += 2;
    }
    let object_len = if flags & 0x40 != 0 { 2 } else { 1 };
    let target32 = flags & 0x10 != 0;
    match flags & 0x03 {
        0 => {
            p += object_len;
            if src & 0x0F != 0x02 {
                p += if target32 { 4 } else { 2 };
            }
        }
        1 => {
            p += object_len;
            p += if flags & 0x80 != 0 {
                1
            } else if target32 {
                4
            } else {
                2
            };
        }
        2 => {
            p += object_len;
            p += if target32 { 4 } else { 2 };
        }
        _ => p += object_len,
    }
    if flags & 0x04 != 0 {
        p += if flags & 0x20 != 0 { 4 } else { 2 };
    }
    p += list_count * 2;
    (p <= end).then_some(p - off)
}

fn count_fixup_records(data: &[u8], start: u64, end: u64) -> u64 {
    let mut off = start;
    let mut count = 0;
    while off < end {
        match fixup_record_len(data, off, end) {
            Some(len) => {
                off += len;
                count += 1;
            }
            None => break,
        }
    }
    count
}

fn fixup_blocks(data: &[u8], h: &Header) -> Vec<Block> {
    let mut blocks = Vec::new();
    if h.fixup_page_table == 0 {
        return blocks;
    }
    let entries = h.num_pages as u64 + 1;
    let Some(range) = clamp(data, h.fixup_page_table, entries * 4) else {
        return blocks;
    };
    let offsets: Vec<u32> = (0..entries.min((range.end - range.start) / 4))
        .map_while(|i| read_u32(data, h.fixup_page_table + i * 4))
        .collect();

    let mut table_children = Vec::new();
    for (i, pair) in offsets.windows(2).enumerate().take(MAX_ENTRIES) {
        let off = h.fixup_page_table + i as u64 * 4;
        table_children.push(Block::leaf(
            format!(
                "Page {}: records at {:#x}, {} bytes",
                i + 1,
                pair[0],
                pair[1].saturating_sub(pair[0])
            ),
            ByteRange::new(off, off + 4),
        ));
    }
    if offsets.len() > MAX_ENTRIES + 1 {
        let off = h.fixup_page_table + MAX_ENTRIES as u64 * 4;
        push_more(
            &mut table_children,
            offsets.len() - 1 - MAX_ENTRIES,
            Some(ByteRange::new(off, (range.end - 4).max(off))),
        );
    }
    if let Some(&last) = offsets.last() {
        if offsets.len() as u64 == entries {
            let off = h.fixup_page_table + (entries - 1) * 4;
            table_children.push(Block::leaf(
                format!("End of fixup records: {last:#x}"),
                ByteRange::new(off, off + 4),
            ));
        }
    }
    blocks.push(Block::node(
        format!("Fixup page table ({entries} entries)"),
        range,
        table_children,
    ));

    if h.fixup_record_table == 0 || offsets.len() as u64 != entries {
        return blocks;
    }
    let base = h.fixup_record_table;
    let total_len = *offsets.last().unwrap_or(&0) as u64;
    let Some(rec_range) = clamp(data, base, total_len) else {
        return blocks;
    };
    let mut rec_children = Vec::new();
    let mut total_records = 0u64;
    let mut listed = 0usize;
    let mut more = 0usize;
    let mut more_start = None;
    // Only count non-overlapping page ranges so malformed tables stay linear.
    let mut scanned_to = base;
    for (i, pair) in offsets.windows(2).enumerate() {
        let start = base + pair[0] as u64;
        let end = (base + pair[1] as u64).min(rec_range.end);
        if start >= end || start < scanned_to {
            continue;
        }
        scanned_to = end;
        let records = count_fixup_records(data, start, end);
        total_records += records;
        if listed >= MAX_ENTRIES {
            more += 1;
            more_start.get_or_insert(start);
            continue;
        }
        listed += 1;
        rec_children.push(Block::leaf(
            format!("Page {} fixups ({records} records)", i + 1),
            ByteRange::new(start, end),
        ));
    }
    if let Some(ms) = more_start {
        rec_children.push(Block::leaf(
            format!("({more} more pages)"),
            ByteRange::new(ms, rec_range.end),
        ));
    }
    blocks.push(Block::node(
        format!("Fixup record table ({total_records} records)"),
        rec_range,
        rec_children,
    ));
    blocks
}

fn import_modules_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.import_modules == 0 || h.num_import_modules == 0 {
        return None;
    }
    let mut children = Vec::new();
    let mut off = h.import_modules;
    for i in 0..h.num_import_modules as u64 {
        let Some((name, len)) = read_pascal(data, off) else {
            break;
        };
        if children.len() < MAX_ENTRIES {
            children.push(Block::leaf(
                format!("Module {}: {name}", i + 1),
                ByteRange::new(off, off + len),
            ));
        }
        off += len;
    }
    if off <= h.import_modules {
        return None;
    }
    if (h.num_import_modules as usize) > MAX_ENTRIES {
        let start = children.last().map(|b| b.range.end).unwrap_or(off);
        push_more(
            &mut children,
            h.num_import_modules as usize - MAX_ENTRIES,
            (off > start).then(|| ByteRange::new(start, off)),
        );
    }
    Some(Block::node(
        format!(
            "Import module name table ({} modules)",
            h.num_import_modules
        ),
        ByteRange::new(h.import_modules, off),
        children,
    ))
}

fn import_procs_block(data: &[u8], h: &Header) -> Option<Block> {
    if h.import_procs == 0 || h.fixup_page_table == 0 {
        return None;
    }
    // The import procedure table is the last part of the fixup section.
    let fixup_end = (h.fixup_page_table + h.fixup_size as u64).min(data.len() as u64);
    if fixup_end <= h.import_procs {
        return None;
    }
    let mut children = Vec::new();
    let mut off = h.import_procs;
    let mut count = 0usize;
    let mut more_start = None;
    while off < fixup_end {
        let Some((name, len)) = read_pascal(data, off) else {
            break;
        };
        if off + len > fixup_end {
            break;
        }
        if children.len() >= MAX_ENTRIES {
            more_start.get_or_insert(off);
        } else {
            let rel = off - h.import_procs;
            let label = if name.is_empty() {
                format!("Name at {rel:#x}: (empty)")
            } else {
                format!("Name at {rel:#x}: {name}")
            };
            children.push(Block::leaf(label, ByteRange::new(off, off + len)));
        }
        count += 1;
        off += len;
    }
    if let Some(ms) = more_start {
        push_more(
            &mut children,
            count - MAX_ENTRIES,
            Some(ByteRange::new(ms, off)),
        );
    }
    if off <= h.import_procs {
        return None;
    }
    Some(Block::node(
        format!("Import procedure name table ({count} names)"),
        ByteRange::new(h.import_procs, off),
        children,
    ))
}

/// Returns the 1-based object number that owns 1-based page `page`.
fn page_owner(data: &[u8], h: &Header, page: u64) -> Option<u64> {
    if h.object_table == 0 {
        return None;
    }
    for i in 0..(h.num_objects as u64).min(MAX_ENTRIES as u64 * 16) {
        let off = h.object_table + i * OBJECT_ENTRY_SIZE;
        let index = read_u32(data, off + 12)? as u64;
        let count = read_u32(data, off + 16)? as u64;
        if index != 0 && page >= index && page < index + count {
            return Some(i + 1);
        }
    }
    None
}

fn data_pages_block(data: &[u8], h: &Header, entries: &[PageEntry]) -> Option<Block> {
    if h.data_pages == 0 {
        return None;
    }
    let mut children = Vec::new();
    let mut start = u64::MAX;
    let mut end = 0u64;
    let mut more = 0usize;
    let mut more_range: Option<ByteRange> = None;
    for (i, e) in entries.iter().enumerate() {
        let page = i as u64 + 1;
        let (offset, size) = match h.kind {
            Kind::Le => {
                if e.flags >= 2 || e.number_or_offset == 0 {
                    continue;
                }
                let size = if page == h.num_pages as u64 {
                    h.last_page_or_shift
                } else {
                    h.page_size
                };
                (
                    h.data_pages + (e.number_or_offset as u64 - 1) * h.page_size as u64,
                    size as u64,
                )
            }
            Kind::Lx => {
                if e.flags == 2 || e.flags == 3 || e.size == 0 {
                    continue;
                }
                let shift = h.last_page_or_shift.min(31);
                (
                    h.data_pages + ((e.number_or_offset as u64) << shift),
                    e.size as u64,
                )
            }
        };
        let Some(range) = clamp(data, offset, size) else {
            continue;
        };
        start = start.min(range.start);
        end = end.max(range.end);
        if children.len() >= MAX_ENTRIES {
            more += 1;
            more_range = Some(match more_range {
                Some(r) => ByteRange::new(r.start.min(range.start), r.end.max(range.end)),
                None => range,
            });
            continue;
        }
        let owner = page_owner(data, h, page)
            .map(|o| format!("object {o}"))
            .unwrap_or_else(|| "no object".to_string());
        children.push(Block::leaf(
            format!("Page {page} ({owner}, {})", page_flags_name(e.flags)),
            range,
        ));
    }
    if children.is_empty() {
        return None;
    }
    push_more(&mut children, more, more_range);
    let count = children.len() - usize::from(more > 0) + more;
    Some(Block::node(
        format!("Data pages ({count} pages)"),
        ByteRange::new(start, end),
        children,
    ))
}

// ---------------------------------------------------------------------------

fn dissect_linear(data: &[u8], kind: Kind) -> Vec<Block> {
    let mut blocks = Vec::new();
    let Some(offset) = header_offset(data, kind) else {
        return blocks;
    };

    if offset > 0 {
        if (data.len() as u64) < DOS_HEADER_SIZE {
            return blocks;
        }
        blocks.push(dos_header_block(data, kind));
        if offset > DOS_HEADER_SIZE {
            blocks.push(Block::leaf(
                "DOS stub program",
                ByteRange::new(DOS_HEADER_SIZE, offset),
            ));
        }
    }

    let Some(header) = header_block(data, offset, kind) else {
        return blocks;
    };
    blocks.push(header);

    let Some(h) = Header::parse(data, offset, kind) else {
        return blocks;
    };

    let pages = page_entries(data, &h);
    let mut tables: Vec<Block> = Vec::new();
    tables.extend(object_table_block(data, &h));
    tables.extend(page_table_block(data, &h, &pages));
    tables.extend(resource_table_block(data, &h));
    tables.extend(name_table_block(
        data,
        h.resident_names,
        None,
        "Resident name table",
        "Module name",
    ));
    tables.extend(entry_table_block(data, &h));
    tables.extend(directives_block(data, &h));
    if h.page_checksums != 0 {
        if let Some(range) = clamp(data, h.page_checksums, h.num_pages as u64 * 4) {
            tables.push(Block::leaf(
                format!("Per-page checksum table ({} entries)", h.num_pages),
                range,
            ));
        }
    }
    tables.extend(fixup_blocks(data, &h));
    tables.extend(import_modules_block(data, &h));
    tables.extend(import_procs_block(data, &h));
    tables.extend(data_pages_block(data, &h, &pages));
    if h.nonresident_length > 0 {
        tables.extend(name_table_block(
            data,
            h.nonresident_names,
            Some(h.nonresident_names + h.nonresident_length as u64),
            "Non-resident name table",
            "Module description",
        ));
    }
    if h.debug_info != 0 {
        if let Some(range) = clamp(data, h.debug_info, h.debug_length as u64) {
            tables.push(Block::leaf(
                format!("Debug info ({} bytes)", h.debug_length),
                range,
            ));
        }
    }
    tables.sort_by_key(|b| b.range.start);
    blocks.extend(tables);
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const LFANEW: usize = 0x80;

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    /// Offsets (file-relative) of the pieces of a built file.
    struct Layout {
        object_table: usize,
        page_table: usize,
        resource_table: usize,
        resident_names: usize,
        entry_table: usize,
        fixup_page_table: usize,
        fixup_records: usize,
        import_modules: usize,
        import_procs: usize,
        data_pages: usize,
        nonresident: usize,
        end: usize,
    }

    /// Builds a minimal MZ + LE/LX file with 2 objects of one page each.
    fn build(kind: Kind) -> (Vec<u8>, Layout) {
        let h = LFANEW;
        let page_entry = if kind == Kind::Le { 4 } else { 8 };
        let object_table = h + 0xC4;
        let page_table = object_table + 48;
        let resource_table = page_table + 2 * page_entry;
        let resident_names = resource_table + 14;
        let entry_table = resident_names + 14;
        let fixup_page_table = entry_table + 10;
        let fixup_records = fixup_page_table + 12;
        let import_modules = fixup_records + 9;
        let import_procs = import_modules + 9;
        let data_pages = import_procs + 7;
        let nonresident = data_pages + 24;
        let end = nonresident + 8;
        let mut d = vec![0u8; end];

        // DOS header and stub
        d[0..2].copy_from_slice(b"MZ");
        put_u16(&mut d, 0x02, 0x80);
        put_u16(&mut d, 0x04, 1);
        put_u16(&mut d, 0x08, 4);
        put_u32(&mut d, 0x3C, h as u32);

        // LE/LX header
        d[h..h + 2].copy_from_slice(kind.signature());
        put_u16(&mut d, h + 0x08, 2); // 80386
        put_u32(&mut d, h + 0x14, 2); // pages
        put_u32(&mut d, h + 0x18, 1);
        put_u32(&mut d, h + 0x1C, 0x10);
        put_u32(&mut d, h + 0x20, 2);
        put_u32(&mut d, h + 0x24, 8);
        put_u32(&mut d, h + 0x28, 16); // page size
        match kind {
            Kind::Le => {
                put_u16(&mut d, h + 0x0A, 4); // Windows 386
                put_u32(&mut d, h + 0x10, 0x38000);
                put_u32(&mut d, h + 0x2C, 8); // last page size
                put_u16(&mut d, h + 0xC0, 0x1234);
                put_u16(&mut d, h + 0xC2, 0x0400);
            }
            Kind::Lx => {
                put_u16(&mut d, h + 0x0A, 1); // OS/2
                put_u32(&mut d, h + 0x10, 0x8204);
                put_u32(&mut d, h + 0x2C, 4); // page offset shift
                put_u32(&mut d, h + 0xAC, 0x2000);
            }
        }
        put_u32(&mut d, h + 0x30, 37); // fixup section size
        let rel = |off: usize| (off - h) as u32;
        put_u32(&mut d, h + 0x40, rel(object_table));
        put_u32(&mut d, h + 0x44, 2);
        put_u32(&mut d, h + 0x48, rel(page_table));
        put_u32(&mut d, h + 0x50, rel(resource_table));
        put_u32(&mut d, h + 0x54, 1);
        put_u32(&mut d, h + 0x58, rel(resident_names));
        put_u32(&mut d, h + 0x5C, rel(entry_table));
        put_u32(&mut d, h + 0x68, rel(fixup_page_table));
        put_u32(&mut d, h + 0x6C, rel(fixup_records));
        put_u32(&mut d, h + 0x70, rel(import_modules));
        put_u32(&mut d, h + 0x74, 1);
        put_u32(&mut d, h + 0x78, rel(import_procs));
        put_u32(&mut d, h + 0x80, data_pages as u32);
        put_u32(&mut d, h + 0x88, nonresident as u32);
        put_u32(&mut d, h + 0x8C, 8);

        // Object table
        for (i, (vsize, base, flags, index)) in [
            (16u32, 0x10000u32, 0x2005u32, 1u32),
            (8, 0x20000, 0x2003, 2),
        ]
        .into_iter()
        .enumerate()
        {
            let o = object_table + i * 24;
            put_u32(&mut d, o, vsize);
            put_u32(&mut d, o + 4, base);
            put_u32(&mut d, o + 8, flags);
            put_u32(&mut d, o + 12, index);
            put_u32(&mut d, o + 16, 1);
        }

        // Object page table
        match kind {
            Kind::Le => {
                d[page_table..page_table + 4].copy_from_slice(&[0, 0, 1, 0]);
                d[page_table + 4..page_table + 8].copy_from_slice(&[0, 0, 2, 0]);
            }
            Kind::Lx => {
                put_u32(&mut d, page_table, 0);
                put_u16(&mut d, page_table + 4, 16);
                put_u32(&mut d, page_table + 8, 1);
                put_u16(&mut d, page_table + 12, 8);
            }
        }

        // Resource table: bitmap, name 1, 4 bytes, object 2, offset 0
        put_u16(&mut d, resource_table, 2);
        put_u16(&mut d, resource_table + 2, 1);
        put_u32(&mut d, resource_table + 4, 4);
        put_u16(&mut d, resource_table + 8, 2);

        // Resident names
        d[resident_names..resident_names + 14]
            .copy_from_slice(b"\x04TEST\x00\x00\x03FOO\x01\x00\x00");

        // Entry table: one 32-bit bundle with one exported entry
        d[entry_table..entry_table + 10].copy_from_slice(&[1, 3, 1, 0, 0x01, 0x10, 0, 0, 0, 0]);

        // Fixup page table and one 32-bit internal fixup on page 1
        put_u32(&mut d, fixup_page_table, 0);
        put_u32(&mut d, fixup_page_table + 4, 9);
        put_u32(&mut d, fixup_page_table + 8, 9);
        d[fixup_records..fixup_records + 9]
            .copy_from_slice(&[0x07, 0x10, 0x04, 0x00, 0x01, 0x20, 0, 0, 0]);

        d[import_modules..import_modules + 9].copy_from_slice(b"\x08DOSCALLS");
        d[import_procs..import_procs + 7].copy_from_slice(b"\x00\x05Hello");
        d[nonresident..nonresident + 8].copy_from_slice(b"\x04desc\x00\x00\x00");

        let layout = Layout {
            object_table,
            page_table,
            resource_table,
            resident_names,
            entry_table,
            fixup_page_table,
            fixup_records,
            import_modules,
            import_procs,
            data_pages,
            nonresident,
            end,
        };
        (d, layout)
    }

    fn r(start: usize, end: usize) -> ByteRange {
        ByteRange::new(start as u64, end as u64)
    }

    fn has_child(block: &Block, label: &str) -> bool {
        block.children.iter().any(|b| b.label == label)
    }

    #[test]
    fn matches_built_files() {
        let (lx, _) = build(Kind::Lx);
        let (le, _) = build(Kind::Le);
        assert!(LxDissector.matches(&lx));
        assert!(!LeDissector.matches(&lx));
        assert!(LeDissector.matches(&le));
        assert!(!LxDissector.matches(&le));
    }

    #[test]
    fn matches_bare_header() {
        let (lx, _) = build(Kind::Lx);
        let bare = &lx[LFANEW..];
        assert!(LxDissector.matches(bare));

        // Bare signature without a plausible header is rejected.
        let mut bad = bare.to_vec();
        put_u16(&mut bad, 0x08, 0x99); // unknown CPU
        assert!(!LxDissector.matches(&bad));
        assert!(!LxDissector.matches(b"LX\0\0"));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!LxDissector.matches(b""));
        assert!(!LeDissector.matches(b""));
        assert!(!LxDissector.matches(b"MZ"));
        assert!(!LxDissector.matches(b"not an executable"));

        // PE signature at e_lfanew
        let (mut d, _) = build(Kind::Lx);
        d[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
        assert!(!LxDissector.matches(&d));
        assert!(!LeDissector.matches(&d));

        // Big-endian byte order is rejected
        let (mut d, _) = build(Kind::Lx);
        d[LFANEW + 2] = 1;
        assert!(!LxDissector.matches(&d));

        // Truncated before the byte/word order fields
        let (d, _) = build(Kind::Le);
        assert!(!LeDissector.matches(&d[..LFANEW + 2]));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let (lx, _) = build(Kind::Lx);
        let (le, _) = build(Kind::Le);
        for data in [&lx, &le] {
            for len in 0..data.len() {
                let _ = LxDissector.dissect(&data[..len]);
                let _ = LeDissector.dissect(&data[..len]);
            }
        }
        let full = LxDissector.dissect(&lx).len();
        let truncated = LxDissector.dissect(&lx[..LFANEW + 0x40]);
        assert!(truncated.len() < full);
        assert!(LxDissector.dissect(b"MZ").is_empty());
    }

    #[test]
    fn dissect_lx_file() {
        let (d, l) = build(Kind::Lx);
        let blocks = LxDissector.dissect(&d);

        let dos = find_block(&blocks, "DOS header");
        assert_eq!(dos.range, r(0, 64));
        assert!(has_child(dos, "Signature: MZ"));
        assert!(has_child(dos, "LX header offset: 128"));
        assert_eq!(find_block(&blocks, "DOS stub program").range, r(64, LFANEW));

        let header = find_block(&blocks, "LX header");
        assert_eq!(header.range, r(LFANEW, LFANEW + 0xC4));
        for label in [
            "Signature: LX",
            "Byte order: little-endian (0)",
            "Word order: little-endian (0)",
            "Format level: 0",
            "CPU type: 80386",
            "OS type: OS/2",
            "Module flags: 0x00008204 (library (DLL), per-process library initialization, PM compatible)",
            "Number of pages: 2",
            "EIP object: 1",
            "EIP offset: 0x10",
            "Page size: 16",
            "Page offset shift: 4",
            "Object table offset: 0xc4 (file 0x144)",
            "Stack size: 8192",
        ] {
            assert!(has_child(header, label), "missing {label:?}");
        }
        assert_eq!(header.children[0].range, r(LFANEW, LFANEW + 2));

        let objects = find_block(&blocks, "Object table (2 objects)");
        assert_eq!(objects.range, r(l.object_table, l.object_table + 48));
        let obj1 = find_block(&objects.children, "Object 1");
        assert_eq!(obj1.range, r(l.object_table, l.object_table + 24));
        assert!(has_child(obj1, "Virtual size: 16"));
        assert!(has_child(obj1, "Relocation base: 0x10000"));
        assert!(has_child(
            obj1,
            "Flags: 0x2005 (readable, executable, 32-bit)"
        ));
        assert!(has_child(obj1, "Page table index: 1"));
        assert!(has_child(obj1, "Page count: 1"));

        let pages = find_block(&blocks, "Object page table (2 entries)");
        assert_eq!(pages.range, r(l.page_table, l.page_table + 16));
        assert!(has_child(pages, "Page 2: offset 0x1, size 8, legal"));

        let res = find_block(&blocks, "Resource table (1 entries)");
        assert_eq!(res.range, r(l.resource_table, l.resource_table + 14));
        assert!(has_child(
            res,
            "Resource 1: type bitmap (2), name 1, size 4, object 2, offset 0x0"
        ));

        let names = find_block(&blocks, "Resident name table (1 names)");
        assert_eq!(names.range, r(l.resident_names, l.resident_names + 14));
        let module = find_block(&names.children, "Module name: TEST");
        assert_eq!(module.range, r(l.resident_names, l.resident_names + 7));
        assert!(has_child(names, "Name: FOO (ordinal 1)"));

        let entries = find_block(&blocks, "Entry table (1 bundles, 1 entries)");
        assert_eq!(entries.range, r(l.entry_table, l.entry_table + 10));
        let bundle = find_block(&entries.children, "Bundle 1: 1 32-bit entries, object 1");
        let entry = find_block(
            &bundle.children,
            "Ordinal 1: offset 0x10, flags 0x01 (exported)",
        );
        assert_eq!(entry.range, r(l.entry_table + 4, l.entry_table + 9));

        let fpt = find_block(&blocks, "Fixup page table (3 entries)");
        assert_eq!(fpt.range, r(l.fixup_page_table, l.fixup_page_table + 12));
        assert!(has_child(fpt, "Page 1: records at 0x0, 9 bytes"));
        assert!(has_child(fpt, "End of fixup records: 0x9"));

        let frt = find_block(&blocks, "Fixup record table (1 records)");
        assert_eq!(frt.range, r(l.fixup_records, l.fixup_records + 9));
        assert!(has_child(frt, "Page 1 fixups (1 records)"));

        let imods = find_block(&blocks, "Import module name table (1 modules)");
        assert_eq!(imods.range, r(l.import_modules, l.import_modules + 9));
        assert!(has_child(imods, "Module 1: DOSCALLS"));

        let iprocs = find_block(&blocks, "Import procedure name table (2 names)");
        assert_eq!(iprocs.range, r(l.import_procs, l.import_procs + 7));
        let hello = find_block(&iprocs.children, "Name at 0x1: Hello");
        assert_eq!(hello.range, r(l.import_procs + 1, l.import_procs + 7));

        let data = find_block(&blocks, "Data pages (2 pages)");
        assert_eq!(data.range, r(l.data_pages, l.data_pages + 24));
        let p2 = find_block(&data.children, "Page 2 (object 2, legal)");
        assert_eq!(p2.range, r(l.data_pages + 16, l.data_pages + 24));

        let nonres = find_block(&blocks, "Non-resident name table (0 names)");
        assert_eq!(nonres.range, r(l.nonresident, l.end));
        assert!(has_child(nonres, "Module description: desc"));

        // Top-level blocks are ordered by offset.
        assert!(
            blocks
                .windows(2)
                .all(|w| w[0].range.start <= w[1].range.start)
        );
    }

    #[test]
    fn dissect_le_file() {
        let (d, l) = build(Kind::Le);
        let blocks = LeDissector.dissect(&d);

        let dos = find_block(&blocks, "DOS header");
        assert!(has_child(dos, "LE header offset: 128"));

        let header = find_block(&blocks, "LE header");
        for label in [
            "Signature: LE",
            "OS type: Windows 386",
            "Module flags: 0x00038000 (Windows VxD)",
            "Last page size: 8",
            "Device ID: 0x1234",
            "DDK version: 4.0",
        ] {
            assert!(has_child(header, label), "missing {label:?}");
        }

        // LE page table entries are 4 bytes.
        let pages = find_block(&blocks, "Object page table (2 entries)");
        assert_eq!(pages.range, r(l.page_table, l.page_table + 8));
        let p2 = find_block(&pages.children, "Page 2: page number 2, legal");
        assert_eq!(p2.range, r(l.page_table + 4, l.page_table + 8));

        // The last LE page uses the last page size.
        let data = find_block(&blocks, "Data pages (2 pages)");
        let p1 = find_block(&data.children, "Page 1 (object 1, legal)");
        assert_eq!(p1.range, r(l.data_pages, l.data_pages + 16));
        let p2 = find_block(&data.children, "Page 2 (object 2, legal)");
        assert_eq!(p2.range, r(l.data_pages + 16, l.data_pages + 24));
    }

    #[test]
    fn dissect_bare_lx() {
        let (d, _) = build(Kind::Lx);
        let blocks = LxDissector.dissect(&d[LFANEW..]);
        assert_eq!(blocks[0].label, "LX header");
        assert_eq!(blocks[0].range.start, 0);
        assert!(blocks.iter().all(|b| b.label != "DOS header"));
    }

    #[test]
    fn identify_reports_le_and_lx() {
        let (lx, _) = build(Kind::Lx);
        let (le, _) = build(Kind::Le);
        assert_eq!(super::super::identify(&lx), "LX");
        assert_eq!(super::super::identify(&le), "LE");
    }
}
