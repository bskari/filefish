//! Microsoft NE ("New Executable"): 16-bit Windows 3.x and OS/2 1.x
//! executables, DLLs, drivers and font files. The file starts with a DOS MZ
//! header whose e_lfanew field (u32 at 0x3C) points to the "NE" header.

use std::collections::HashMap;

use super::{Block, ByteRange, Dissector};

const DOS_MAGIC: &[u8] = b"MZ";
const NE_SIGNATURE: &[u8] = b"NE";
const DOS_HEADER_SIZE: usize = 64;
const E_LFANEW_OFFSET: usize = 0x3C;
const NE_HEADER_SIZE: usize = 0x40;

/// Maximum number of entries shown in any single list before the rest are
/// summarised as "(N more not shown)".
const MAX_ITEMS: usize = 256;

// Segment flags.
const SEG_DATA: u16 = 0x0001;
const SEG_RELOCINFO: u16 = 0x0100;

pub struct NeDissector;

impl Dissector for NeDissector {
    fn name(&self) -> &'static str {
        "NE"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < DOS_HEADER_SIZE || !data.starts_with(DOS_MAGIC) {
            return false;
        }
        match ne_header_offset(data) {
            Some(offset) => data.get(offset..offset + 2) == Some(NE_SIGNATURE),
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < DOS_HEADER_SIZE || !data.starts_with(DOS_MAGIC) {
            return blocks;
        }
        blocks.push(dos_header_block(data));

        let Some(ne) = ne_header_offset(data) else {
            return blocks;
        };
        if ne > DOS_HEADER_SIZE {
            blocks.push(Block::leaf("DOS stub", rng(DOS_HEADER_SIZE, ne)));
        }
        if data.get(ne..ne + 2) != Some(NE_SIGNATURE) {
            return blocks;
        }
        let Some(header) = NeHeader::parse(data, ne) else {
            blocks.push(Block::leaf("NE header (truncated)", rng(ne, data.len())));
            return blocks;
        };
        blocks.push(header.block());

        let module_names = module_names(data, &header);
        let entry_names = entry_names(data, &header);

        if let Some(block) = segment_table_block(data, &header) {
            blocks.push(block);
        }
        if let Some((block, resources)) = resource_table_block(data, &header) {
            blocks.push(block);
            if let Some(block) = resource_data_block(resources) {
                blocks.push(block);
            }
        }
        if let Some(block) = name_table_block(
            data,
            "Resident name table",
            "Module name",
            ne + header.resident_off as usize,
            data.len(),
        ) {
            blocks.push(block);
        }
        if let Some(block) = module_ref_table_block(data, &header, &module_names) {
            blocks.push(block);
        }
        if let Some(block) = imported_names_block(data, &header) {
            blocks.push(block);
        }
        if let Some(block) = entry_table_block(data, &header, &entry_names) {
            blocks.push(block);
        }
        if header.nonresident_off != 0 && header.nonresident_size != 0 {
            let start = header.nonresident_off as usize;
            let end = start.saturating_add(header.nonresident_size as usize);
            if let Some(block) =
                name_table_block(data, "Non-resident name table", "Description", start, end)
            {
                blocks.push(block);
            }
        }
        blocks.extend(segment_data_blocks(data, &header, &module_names));

        // Present top-level blocks in file order (the DOS header stays first).
        blocks.sort_by_key(|b| b.range.start);
        blocks
    }
}

fn rng(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Reads a length-prefixed (Pascal) string. Returns the text and the total
/// size including the length byte. A zero length byte returns `None`.
fn read_pascal(data: &[u8], offset: usize, limit: usize) -> Option<(String, usize)> {
    let len = read_u8(data, offset)? as usize;
    if len == 0 {
        return None;
    }
    let end = offset + 1 + len;
    if end > limit.min(data.len()) {
        return None;
    }
    Some((
        String::from_utf8_lossy(&data[offset + 1..end]).into_owned(),
        1 + len,
    ))
}

fn ne_header_offset(data: &[u8]) -> Option<usize> {
    let offset = read_u32(data, E_LFANEW_OFFSET)? as usize;
    if offset.checked_add(2)? > data.len() {
        return None;
    }
    Some(offset)
}

fn more_block(count: usize, start: usize, end: usize) -> Block {
    Block::leaf(
        format!("({count} more not shown)"),
        rng(start, end.max(start)),
    )
}

fn join_flags(names: &[&str]) -> String {
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join(", "))
    }
}

fn dos_header_block(data: &[u8]) -> Block {
    let u16_at = |off: usize| read_u16(data, off).unwrap_or(0);
    let e_lfanew = read_u32(data, E_LFANEW_OFFSET).unwrap_or(0);
    let field = |label: String, off: usize, len: usize| Block::leaf(label, rng(off, off + len));

    let children = vec![
        field("Signature: MZ".to_string(), 0, 2),
        field(format!("Bytes on last page: {}", u16_at(0x02)), 0x02, 2),
        field(format!("Pages in file: {}", u16_at(0x04)), 0x04, 2),
        field(format!("Relocations: {}", u16_at(0x06)), 0x06, 2),
        field(
            format!("Header size (paragraphs): {}", u16_at(0x08)),
            0x08,
            2,
        ),
        field(
            format!("Minimum extra paragraphs: {}", u16_at(0x0A)),
            0x0A,
            2,
        ),
        field(
            format!("Maximum extra paragraphs: {}", u16_at(0x0C)),
            0x0C,
            2,
        ),
        field(format!("Initial SS: {:#06x}", u16_at(0x0E)), 0x0E, 2),
        field(format!("Initial SP: {:#06x}", u16_at(0x10)), 0x10, 2),
        field(format!("Checksum: {:#06x}", u16_at(0x12)), 0x12, 2),
        field(format!("Initial IP: {:#06x}", u16_at(0x14)), 0x14, 2),
        field(format!("Initial CS: {:#06x}", u16_at(0x16)), 0x16, 2),
        field(
            format!("Relocation table offset: {:#x}", u16_at(0x18)),
            0x18,
            2,
        ),
        field(format!("Overlay number: {}", u16_at(0x1A)), 0x1A, 2),
        field("Reserved".to_string(), 0x1C, 8),
        field(format!("OEM identifier: {:#06x}", u16_at(0x24)), 0x24, 2),
        field(format!("OEM information: {:#06x}", u16_at(0x26)), 0x26, 2),
        field("Reserved".to_string(), 0x28, 20),
        field(format!("NE header offset: {e_lfanew}"), E_LFANEW_OFFSET, 4),
    ];
    Block::node("DOS header", rng(0, DOS_HEADER_SIZE), children).expanded()
}

struct NeHeader {
    ne: usize,
    linker_version: u8,
    linker_revision: u8,
    entry_off: u16,
    entry_len: u16,
    crc: u32,
    program_flags: u8,
    app_flags: u8,
    auto_data_seg: u16,
    heap_size: u16,
    stack_size: u16,
    ip: u16,
    cs: u16,
    sp: u16,
    ss: u16,
    segment_count: u16,
    module_ref_count: u16,
    nonresident_size: u16,
    segment_off: u16,
    resource_off: u16,
    resident_off: u16,
    module_ref_off: u16,
    imported_off: u16,
    nonresident_off: u32,
    movable_entries: u16,
    align_shift: u16,
    resource_segments: u16,
    target_os: u8,
    os2_flags: u8,
    fastload_off: u16,
    fastload_len: u16,
    min_code_swap: u16,
    win_version: u16,
}

impl NeHeader {
    fn parse(data: &[u8], ne: usize) -> Option<Self> {
        if data.len() < ne.checked_add(NE_HEADER_SIZE)? {
            return None;
        }
        let b = |o: usize| data[ne + o];
        let w = |o: usize| read_u16(data, ne + o).unwrap_or(0);
        Some(Self {
            ne,
            linker_version: b(0x02),
            linker_revision: b(0x03),
            entry_off: w(0x04),
            entry_len: w(0x06),
            crc: read_u32(data, ne + 0x08)?,
            program_flags: b(0x0C),
            app_flags: b(0x0D),
            auto_data_seg: w(0x0E),
            heap_size: w(0x10),
            stack_size: w(0x12),
            ip: w(0x14),
            cs: w(0x16),
            sp: w(0x18),
            ss: w(0x1A),
            segment_count: w(0x1C),
            module_ref_count: w(0x1E),
            nonresident_size: w(0x20),
            segment_off: w(0x22),
            resource_off: w(0x24),
            resident_off: w(0x26),
            module_ref_off: w(0x28),
            imported_off: w(0x2A),
            nonresident_off: read_u32(data, ne + 0x2C)?,
            movable_entries: w(0x30),
            align_shift: w(0x32),
            resource_segments: w(0x34),
            target_os: b(0x36),
            os2_flags: b(0x37),
            fastload_off: w(0x38),
            fastload_len: w(0x3A),
            min_code_swap: w(0x3C),
            win_version: w(0x3E),
        })
    }

    /// Segment alignment shift. Some documentation says 0 means the default
    /// of 9, but loaders (and Wine-generated files, which use 0 with byte
    /// offsets) apply the value literally.
    fn shift(&self) -> u32 {
        (self.align_shift as u32).min(31)
    }

    fn rel(&self, value: u16) -> String {
        format!("{value:#x} (file {:#x})", self.ne + value as usize)
    }

    fn block(&self) -> Block {
        let ne = self.ne;
        let field = |label: String, off: usize, len: usize| {
            Block::leaf(label, rng(ne + off, ne + off + len))
        };
        let shift = self.shift();
        let children = vec![
            field("Signature: NE".to_string(), 0x00, 2),
            field(
                format!(
                    "Linker version: {}.{}",
                    self.linker_version, self.linker_revision
                ),
                0x02,
                2,
            ),
            field(
                format!("Entry table offset: {}", self.rel(self.entry_off)),
                0x04,
                2,
            ),
            field(format!("Entry table length: {}", self.entry_len), 0x06, 2),
            field(format!("CRC: {:#010x}", self.crc), 0x08, 4),
            field(
                format!(
                    "Program flags: {:#04x}{}",
                    self.program_flags,
                    program_flags_desc(self.program_flags)
                ),
                0x0C,
                1,
            ),
            field(
                format!(
                    "Application flags: {:#04x}{}",
                    self.app_flags,
                    app_flags_desc(self.app_flags)
                ),
                0x0D,
                1,
            ),
            field(
                match self.auto_data_seg {
                    0 => "Auto data segment: none".to_string(),
                    n => format!("Auto data segment: {n}"),
                },
                0x0E,
                2,
            ),
            field(format!("Initial heap size: {}", self.heap_size), 0x10, 2),
            field(format!("Initial stack size: {}", self.stack_size), 0x12, 2),
            field(format!("CS:IP: {:04x}:{:04x}", self.cs, self.ip), 0x14, 4),
            field(format!("SS:SP: {:04x}:{:04x}", self.ss, self.sp), 0x18, 4),
            field(format!("Segment count: {}", self.segment_count), 0x1C, 2),
            field(
                format!("Module reference count: {}", self.module_ref_count),
                0x1E,
                2,
            ),
            field(
                format!("Non-resident name table size: {}", self.nonresident_size),
                0x20,
                2,
            ),
            field(
                format!("Segment table offset: {}", self.rel(self.segment_off)),
                0x22,
                2,
            ),
            field(
                format!("Resource table offset: {}", self.rel(self.resource_off)),
                0x24,
                2,
            ),
            field(
                format!(
                    "Resident name table offset: {}",
                    self.rel(self.resident_off)
                ),
                0x26,
                2,
            ),
            field(
                format!(
                    "Module reference table offset: {}",
                    self.rel(self.module_ref_off)
                ),
                0x28,
                2,
            ),
            field(
                format!(
                    "Imported names table offset: {}",
                    self.rel(self.imported_off)
                ),
                0x2A,
                2,
            ),
            field(
                format!(
                    "Non-resident name table offset: {:#x}",
                    self.nonresident_off
                ),
                0x2C,
                4,
            ),
            field(
                format!("Movable entry points: {}", self.movable_entries),
                0x30,
                2,
            ),
            field(
                format!(
                    "Alignment shift: {} ({} bytes)",
                    self.align_shift,
                    1u64 << shift
                ),
                0x32,
                2,
            ),
            field(
                format!("Resource segment count: {}", self.resource_segments),
                0x34,
                2,
            ),
            field(
                format!("Target OS: {}", target_os_name(self.target_os)),
                0x36,
                1,
            ),
            field(
                format!(
                    "OS/2 flags: {:#04x}{}",
                    self.os2_flags,
                    os2_flags_desc(self.os2_flags)
                ),
                0x37,
                1,
            ),
            field(
                format!(
                    "Fast-load area offset: {} (file {:#x})",
                    self.fastload_off,
                    (self.fastload_off as u64) << shift
                ),
                0x38,
                2,
            ),
            field(
                format!(
                    "Fast-load area length: {} ({} bytes)",
                    self.fastload_len,
                    (self.fastload_len as u64) << shift
                ),
                0x3A,
                2,
            ),
            field(
                format!("Minimum code swap area size: {}", self.min_code_swap),
                0x3C,
                2,
            ),
            field(
                format!(
                    "Expected Windows version: {}.{:02}",
                    self.win_version >> 8,
                    self.win_version & 0xFF
                ),
                0x3E,
                2,
            ),
        ];
        Block::node("NE header", rng(ne, ne + NE_HEADER_SIZE), children).expanded()
    }
}

fn program_flags_desc(flags: u8) -> String {
    let mut names = vec![match flags & 0x03 {
        0 => "NOAUTODATA",
        1 => "SINGLEDATA",
        2 => "MULTIPLEDATA",
        _ => "AUTODATA (invalid)",
    }];
    for (bit, name) in [
        (0x04, "GLOBALINIT"),
        (0x08, "PROTMODE"),
        (0x10, "8086"),
        (0x20, "80286"),
        (0x40, "80386"),
        (0x80, "80x87"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    join_flags(&names)
}

fn app_flags_desc(flags: u8) -> String {
    let mut names = Vec::new();
    match flags & 0x07 {
        0 => {}
        1 => names.push("NOTWINDOWCOMPAT"),
        2 => names.push("WINDOWCOMPAT"),
        3 => names.push("WINDOWAPI"),
        _ => names.push("unknown app type"),
    }
    for (bit, name) in [
        (0x08, "OS2FAMILY"),
        (0x20, "ERRORS"),
        (0x40, "NONCONFORMING"),
        (0x80, "DLL"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    join_flags(&names)
}

fn os2_flags_desc(flags: u8) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (0x01, "LONGFILENAMES"),
        (0x02, "PROTMODE2"),
        (0x04, "PROPORTIONALFONTS"),
        (0x08, "GANGLOAD"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    join_flags(&names)
}

fn target_os_name(os: u8) -> String {
    match os {
        0 => "unknown (0)".to_string(),
        1 => "OS/2".to_string(),
        2 => "Windows".to_string(),
        3 => "DOS 4".to_string(),
        4 => "Windows 386".to_string(),
        5 => "BOSS".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn segment_flags_desc(flags: u16) -> String {
    let mut names = vec![if flags & SEG_DATA != 0 {
        "DATA"
    } else {
        "CODE"
    }];
    let readonly = if flags & SEG_DATA != 0 {
        "READONLY"
    } else {
        "EXECUTEONLY"
    };
    for (bit, name) in [
        (0x0002, "LOADED"),
        (0x0004, "ALLOCATED"),
        (0x0008, "ITERATED"),
        (0x0010, "MOVEABLE"),
        (0x0020, "SHAREABLE"),
        (0x0040, "PRELOAD"),
        (0x0080, readonly),
        (SEG_RELOCINFO, "RELOCINFO"),
        (0x1000, "DISCARDABLE"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    join_flags(&names)
}

struct Segment {
    index: usize,
    file_offset: u64,
    length: u64,
    flags: u16,
}

fn segments(data: &[u8], header: &NeHeader) -> Vec<Segment> {
    let start = header.ne + header.segment_off as usize;
    let mut out = Vec::new();
    for i in 0..header.segment_count as usize {
        let off = start + i * 8;
        let (Some(sector), Some(len), Some(flags)) = (
            read_u16(data, off),
            read_u16(data, off + 2),
            read_u16(data, off + 4),
        ) else {
            break;
        };
        let length = if len == 0 && sector != 0 {
            0x10000
        } else {
            len as u64
        };
        out.push(Segment {
            index: i + 1,
            file_offset: (sector as u64) << header.shift(),
            length,
            flags,
        });
    }
    out
}

fn segment_table_block(data: &[u8], header: &NeHeader) -> Option<Block> {
    if header.segment_count == 0 {
        return None;
    }
    let start = header.ne + header.segment_off as usize;
    if start >= data.len() {
        return None;
    }
    let end = (start + header.segment_count as usize * 8).min(data.len());
    let shift = header.shift();
    let mut children = Vec::new();
    for i in 0..header.segment_count as usize {
        let off = start + i * 8;
        if off + 8 > data.len() {
            break;
        }
        if i == MAX_ITEMS {
            children.push(more_block(header.segment_count as usize - i, off, end));
            break;
        }
        let sector = read_u16(data, off)?;
        let len = read_u16(data, off + 2)?;
        let flags = read_u16(data, off + 4)?;
        let min_alloc = read_u16(data, off + 6)?;
        let length_label = if len == 0 && sector != 0 {
            "Length: 65536".to_string()
        } else {
            format!("Length: {len}")
        };
        let min_alloc_label = if min_alloc == 0 {
            "Minimum allocation: 65536".to_string()
        } else {
            format!("Minimum allocation: {min_alloc}")
        };
        let kind = if flags & SEG_DATA != 0 {
            "DATA"
        } else {
            "CODE"
        };
        children.push(Block::node(
            format!("Segment {}: {kind}", i + 1),
            rng(off, off + 8),
            vec![
                Block::leaf(
                    if sector == 0 {
                        "Sector offset: 0 (no data in file)".to_string()
                    } else {
                        format!(
                            "Sector offset: {sector} (file {:#x})",
                            (sector as u64) << shift
                        )
                    },
                    rng(off, off + 2),
                ),
                Block::leaf(length_label, rng(off + 2, off + 4)),
                Block::leaf(
                    format!("Flags: {flags:#06x}{}", segment_flags_desc(flags)),
                    rng(off + 4, off + 6),
                ),
                Block::leaf(min_alloc_label, rng(off + 6, off + 8)),
            ],
        ));
    }
    Some(
        Block::node(
            format!("Segment table ({} entries)", header.segment_count),
            rng(start, end),
            children,
        )
        .expanded(),
    )
}

fn resource_type_name(type_id: u16) -> String {
    match type_id & 0x7FFF {
        1 => "RT_CURSOR".to_string(),
        2 => "RT_BITMAP".to_string(),
        3 => "RT_ICON".to_string(),
        4 => "RT_MENU".to_string(),
        5 => "RT_DIALOG".to_string(),
        6 => "RT_STRING".to_string(),
        7 => "RT_FONTDIR".to_string(),
        8 => "RT_FONT".to_string(),
        9 => "RT_ACCELERATOR".to_string(),
        10 => "RT_RCDATA".to_string(),
        11 => "RT_MESSAGETABLE".to_string(),
        12 => "RT_GROUP_CURSOR".to_string(),
        14 => "RT_GROUP_ICON".to_string(),
        15 => "RT_NAMETABLE".to_string(),
        16 => "RT_VERSION".to_string(),
        17 => "RT_DLGINCLUDE".to_string(),
        19 => "RT_PLUGPLAY".to_string(),
        20 => "RT_VXD".to_string(),
        21 => "RT_ANICURSOR".to_string(),
        22 => "RT_ANIICON".to_string(),
        23 => "RT_HTML".to_string(),
        24 => "RT_MANIFEST".to_string(),
        n => format!("type {n}"),
    }
}

/// Resolves a resource type or name ID: integer IDs have the high bit set;
/// otherwise the value is an offset (from the resource table start) of a
/// Pascal string.
fn resource_id_name(data: &[u8], table: usize, limit: usize, id: u16, is_type: bool) -> String {
    if id & 0x8000 != 0 {
        if is_type {
            resource_type_name(id)
        } else {
            format!("{}", id & 0x7FFF)
        }
    } else {
        match read_pascal(data, table + id as usize, limit) {
            Some((name, _)) => format!("\"{name}\""),
            None => format!("name at {id:#x}"),
        }
    }
}

fn resource_flags_desc(flags: u16) -> String {
    let mut names = Vec::new();
    for (bit, name) in [(0x0010, "MOVEABLE"), (0x0020, "PURE"), (0x0040, "PRELOAD")] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    if flags & 0x1000 != 0 {
        names.push("DISCARDABLE");
    }
    join_flags(&names)
}

/// A resource's data range in the file, collected while parsing the table.
struct ResourceData {
    label: String,
    start: usize,
    end: usize,
}

fn resource_table_block(data: &[u8], header: &NeHeader) -> Option<(Block, Vec<ResourceData>)> {
    let start = header.ne + header.resource_off as usize;
    let resident = header.ne + header.resident_off as usize;
    if header.resource_off == header.resident_off || start >= data.len() {
        return None;
    }
    // The resource table runs up to the resident name table.
    let limit = if resident > start {
        resident.min(data.len())
    } else {
        data.len()
    };
    let raw_shift = read_u16(data, start)?;
    let shift = (raw_shift as u32).min(31);

    let mut children = vec![Block::leaf(
        format!("Alignment shift: {raw_shift} ({} bytes)", 1u64 << shift),
        rng(start, start + 2),
    )];
    let mut resources = Vec::new();
    let mut p = start + 2;
    let mut types = 0usize;
    let mut terminated = false;
    while p + 2 <= limit {
        let type_id = read_u16(data, p)?;
        if type_id == 0 {
            children.push(Block::leaf("End of types", rng(p, p + 2)));
            p += 2;
            terminated = true;
            break;
        }
        if p + 8 > limit {
            break;
        }
        if types == MAX_ITEMS {
            children.push(Block::leaf("(more types not shown)", rng(p, limit)));
            p = limit;
            break;
        }
        types += 1;
        let count = read_u16(data, p + 2)? as usize;
        let type_name = resource_id_name(data, start, limit, type_id, true);
        let type_end = (p + 8 + count * 12).min(limit);
        let mut type_children = vec![
            Block::leaf(
                format!("Type ID: {type_name} ({type_id:#06x})"),
                rng(p, p + 2),
            ),
            Block::leaf(format!("Count: {count}"), rng(p + 2, p + 4)),
            Block::leaf("Reserved", rng(p + 4, p + 8)),
        ];
        let mut q = p + 8;
        for i in 0..count {
            if q + 12 > limit {
                break;
            }
            if i == MAX_ITEMS {
                type_children.push(more_block(count - i, q, type_end));
                break;
            }
            let offset = read_u16(data, q)?;
            let length = read_u16(data, q + 2)?;
            let flags = read_u16(data, q + 4)?;
            let id = read_u16(data, q + 6)?;
            let file_offset = (offset as u64) << shift;
            let byte_len = (length as u64) << shift;
            let id_name = resource_id_name(data, start, limit, id, false);
            type_children.push(Block::node(
                format!("Resource {id_name}"),
                rng(q, q + 12),
                vec![
                    Block::leaf(
                        format!("Offset: {offset} (file {file_offset:#x})"),
                        rng(q, q + 2),
                    ),
                    Block::leaf(
                        format!("Length: {length} ({byte_len} bytes)"),
                        rng(q + 2, q + 4),
                    ),
                    Block::leaf(
                        format!("Flags: {flags:#06x}{}", resource_flags_desc(flags)),
                        rng(q + 4, q + 6),
                    ),
                    Block::leaf(format!("ID: {id_name} ({id:#06x})"), rng(q + 6, q + 8)),
                    Block::leaf("Reserved", rng(q + 8, q + 12)),
                ],
            ));
            let data_start = file_offset.min(data.len() as u64) as usize;
            let data_end = file_offset.saturating_add(byte_len).min(data.len() as u64) as usize;
            if offset != 0 && data_end > data_start && resources.len() < MAX_ITEMS {
                resources.push(ResourceData {
                    label: format!("{type_name} {id_name}"),
                    start: data_start,
                    end: data_end,
                });
            }
            q += 12;
        }
        children.push(Block::node(
            format!("Type {type_name} ({count} resources)"),
            rng(p, type_end),
            type_children,
        ));
        p = type_end;
    }

    // Resource name strings follow the type list, terminated by a zero byte.
    if terminated && p < limit {
        let names_start = p;
        let mut names = Vec::new();
        while p < limit {
            if read_u8(data, p) == Some(0) {
                names.push(Block::leaf("End of names", rng(p, p + 1)));
                p += 1;
                break;
            }
            let Some((name, size)) = read_pascal(data, p, limit) else {
                break;
            };
            if names.len() == MAX_ITEMS {
                names.push(Block::leaf("(more names not shown)", rng(p, limit)));
                p = limit;
                break;
            }
            names.push(Block::leaf(
                format!("Name at {:#x}: {name}", p - start),
                rng(p, p + size),
            ));
            p += size;
        }
        children.push(Block::node("Resource names", rng(names_start, p), names));
    }

    let block = Block::node(
        format!("Resource table ({types} types)"),
        rng(start, p),
        children,
    );
    Some((block, resources))
}

fn resource_data_block(mut resources: Vec<ResourceData>) -> Option<Block> {
    if resources.is_empty() {
        return None;
    }
    resources.sort_by_key(|r| r.start);
    let start = resources.iter().map(|r| r.start).min()?;
    let end = resources.iter().map(|r| r.end).max()?;
    let children = resources
        .into_iter()
        .map(|r| Block::leaf(r.label, rng(r.start, r.end)))
        .collect::<Vec<_>>();
    Some(Block::node(
        format!("Resource data ({} resources)", children.len()),
        rng(start, end),
        children,
    ))
}

/// Parses a resident or non-resident name table: Pascal strings each
/// followed by a u16 ordinal, terminated by a zero length byte. The first
/// entry is the module name (resident) or description (non-resident).
fn name_table_block(
    data: &[u8],
    title: &str,
    first_label: &str,
    start: usize,
    limit: usize,
) -> Option<Block> {
    let limit = limit.min(data.len());
    if start >= limit {
        return None;
    }
    let mut children = Vec::new();
    let mut p = start;
    let mut count = 0usize;
    while p < limit {
        if read_u8(data, p) == Some(0) {
            children.push(Block::leaf("End of table", rng(p, p + 1)));
            p += 1;
            break;
        }
        let Some((name, size)) = read_pascal(data, p, limit) else {
            break;
        };
        let Some(ordinal) = read_u16(data, p + size).filter(|_| p + size + 2 <= limit) else {
            break;
        };
        if count == MAX_ITEMS {
            let mut q = p;
            let mut rest = 0usize;
            while let Some((_, s)) = read_pascal(data, q, limit) {
                if q + s + 2 > limit {
                    break;
                }
                q += s + 2;
                rest += 1;
            }
            children.push(more_block(rest, p, q));
            p = q;
            continue;
        }
        let label = if count == 0 {
            format!("{first_label}: {name}")
        } else {
            format!("{name} (ordinal {ordinal})")
        };
        children.push(Block::leaf(label, rng(p, p + size + 2)));
        p += size + 2;
        count += 1;
    }
    if p == start {
        return None;
    }
    Some(Block::node(title, rng(start, p), children))
}

/// Collects exported names by ordinal from the resident and non-resident
/// name tables (skipping the module name / description entry).
fn entry_names(data: &[u8], header: &NeHeader) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    let mut collect = |start: usize, limit: usize| {
        let limit = limit.min(data.len());
        let mut p = start;
        let mut first = true;
        let mut n = 0;
        while p < limit && n < 65536 {
            let Some((name, size)) = read_pascal(data, p, limit) else {
                break;
            };
            let Some(ordinal) = read_u16(data, p + size) else {
                break;
            };
            if !first {
                map.entry(ordinal).or_insert(name);
            }
            first = false;
            p += size + 2;
            n += 1;
        }
    };
    collect(header.ne + header.resident_off as usize, data.len());
    if header.nonresident_off != 0 {
        let start = header.nonresident_off as usize;
        collect(
            start,
            start.saturating_add(header.nonresident_size as usize),
        );
    }
    map
}

fn module_names(data: &[u8], header: &NeHeader) -> Vec<String> {
    let table = header.ne + header.module_ref_off as usize;
    let imported = header.ne + header.imported_off as usize;
    (0..header.module_ref_count as usize)
        .map_while(|i| read_u16(data, table + i * 2))
        .map(|off| {
            read_pascal(data, imported + off as usize, data.len())
                .map(|(name, _)| name)
                .unwrap_or_else(|| format!("name at {off:#x}"))
        })
        .collect()
}

fn module_ref_table_block(data: &[u8], header: &NeHeader, names: &[String]) -> Option<Block> {
    if header.module_ref_count == 0 {
        return None;
    }
    let start = header.ne + header.module_ref_off as usize;
    if start >= data.len() {
        return None;
    }
    let count = header.module_ref_count as usize;
    let end = (start + count * 2).min(data.len());
    let mut children = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let off = start + i * 2;
        if i == MAX_ITEMS {
            children.push(more_block(count - i, off, end));
            break;
        }
        let name_off = read_u16(data, off)?;
        children.push(Block::leaf(
            format!("Module {}: {name} (name offset {name_off:#x})", i + 1),
            rng(off, off + 2),
        ));
    }
    Some(Block::node(
        format!("Module reference table ({count} modules)"),
        rng(start, end),
        children,
    ))
}

fn imported_names_block(data: &[u8], header: &NeHeader) -> Option<Block> {
    let start = header.ne + header.imported_off as usize;
    let entry = header.ne + header.entry_off as usize;
    // The imported names table runs up to the entry table.
    if entry <= start || start >= data.len() {
        return None;
    }
    let limit = entry.min(data.len());
    let mut children = Vec::new();
    let mut p = start;
    while p < limit {
        if children.len() == MAX_ITEMS {
            children.push(Block::leaf("(more names not shown)", rng(p, limit)));
            p = limit;
            break;
        }
        let len = read_u8(data, p)? as usize;
        if len == 0 {
            children.push(Block::leaf(
                format!("Name at {:#x}: (empty)", p - start),
                rng(p, p + 1),
            ));
            p += 1;
            continue;
        }
        let Some((name, size)) = read_pascal(data, p, limit) else {
            break;
        };
        children.push(Block::leaf(
            format!("Name at {:#x}: {name}", p - start),
            rng(p, p + size),
        ));
        p += size;
    }
    Some(Block::node("Imported names table", rng(start, p), children))
}

fn entry_flags_desc(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("exported".to_string());
    }
    if flags & 0x02 != 0 {
        names.push("shared data".to_string());
    }
    if flags >> 3 != 0 {
        names.push(format!("{} param words", flags >> 3));
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join(", "))
    }
}

fn entry_table_block(
    data: &[u8],
    header: &NeHeader,
    names: &HashMap<u16, String>,
) -> Option<Block> {
    if header.entry_len == 0 {
        return None;
    }
    let start = header.ne + header.entry_off as usize;
    let limit = (start + header.entry_len as usize).min(data.len());
    if start >= limit {
        return None;
    }
    let mut children = Vec::new();
    let mut p = start;
    let mut ordinal: u32 = 1;
    let mut shown = 0usize;
    while p < limit {
        let count = read_u8(data, p)? as usize;
        if count == 0 {
            children.push(Block::leaf("End of table", rng(p, p + 1)));
            p += 1;
            break;
        }
        let Some(indicator) = read_u8(data, p + 1).filter(|_| p + 2 <= limit) else {
            break;
        };
        let entry_size = match indicator {
            0x00 => 0,
            0xFF => 6,
            _ => 3,
        };
        let bundle_end = (p + 2 + count * entry_size).min(limit);
        if shown >= MAX_ITEMS {
            children.push(Block::leaf("(more bundles not shown)", rng(p, limit)));
            p = limit;
            break;
        }
        let first = ordinal;
        let last = ordinal + count as u32 - 1;
        let (title, indicator_label) = match indicator {
            0x00 => (
                format!("Bundle: ordinals {first}-{last} unused"),
                "Indicator: unused".to_string(),
            ),
            0xFF => (
                format!("Bundle: ordinals {first}-{last}, moveable segments"),
                "Indicator: moveable segment (0xff)".to_string(),
            ),
            0xFE => (
                format!("Bundle: ordinals {first}-{last}, constants"),
                "Indicator: constant (0xfe)".to_string(),
            ),
            seg => (
                format!("Bundle: ordinals {first}-{last}, segment {seg}"),
                format!("Indicator: fixed segment {seg}"),
            ),
        };
        let mut bundle = vec![
            Block::leaf(format!("Count: {count}"), rng(p, p + 1)),
            Block::leaf(indicator_label, rng(p + 1, p + 2)),
        ];
        let mut q = p + 2;
        for i in 0..count {
            if entry_size == 0 || q + entry_size > limit {
                break;
            }
            if shown >= MAX_ITEMS {
                bundle.push(more_block(count - i, q, bundle_end));
                break;
            }
            let ord = ordinal + i as u32;
            let flags = read_u8(data, q)?;
            let target = match indicator {
                0xFF => {
                    let seg = read_u8(data, q + 3)?;
                    let off = read_u16(data, q + 4)?;
                    format!("{seg}:{off:04x}")
                }
                0xFE => format!("value {:#06x}", read_u16(data, q + 1)?),
                seg => format!("{seg}:{:04x}", read_u16(data, q + 1)?),
            };
            let name = names
                .get(&(ord as u16))
                .map(|n| format!(" {n}"))
                .unwrap_or_default();
            bundle.push(Block::leaf(
                format!("Ordinal {ord}{name}: {target}{}", entry_flags_desc(flags)),
                rng(q, q + entry_size),
            ));
            shown += 1;
            q += entry_size;
        }
        children.push(Block::node(title, rng(p, bundle_end), bundle));
        ordinal += count as u32;
        shown += 1;
        p = bundle_end;
    }
    Some(Block::node("Entry table", rng(start, p), children))
}

fn reloc_source_name(kind: u8) -> String {
    match kind & 0x0F {
        0 => "LOBYTE".to_string(),
        2 => "SEGMENT".to_string(),
        3 => "FAR_ADDR".to_string(),
        5 => "OFFSET".to_string(),
        11 => "FAR48".to_string(),
        13 => "OFFSET32".to_string(),
        n => format!("type {n}"),
    }
}

fn module_name(modules: &[String], index: u16) -> String {
    match (index as usize).checked_sub(1).and_then(|i| modules.get(i)) {
        Some(name) => name.clone(),
        None => format!("module {index}"),
    }
}

fn relocation_label(
    data: &[u8],
    header: &NeHeader,
    modules: &[String],
    off: usize,
) -> Option<String> {
    let source = read_u8(data, off)?;
    let flags = read_u8(data, off + 1)?;
    let source_off = read_u16(data, off + 2)?;
    let a = read_u16(data, off + 4)?;
    let b = read_u16(data, off + 6)?;
    let target = match flags & 0x03 {
        0 => {
            let seg = a & 0xFF;
            if seg == 0xFF {
                format!("internal entry ordinal {b}")
            } else {
                format!("internal {seg}:{b:04x}")
            }
        }
        1 => format!("import {} ordinal {b}", module_name(modules, a)),
        2 => {
            let name = read_pascal(
                data,
                header.ne + header.imported_off as usize + b as usize,
                data.len(),
            )
            .map(|(n, _)| n)
            .unwrap_or_else(|| format!("name at {b:#x}"));
            format!("import {}!{name}", module_name(modules, a))
        }
        _ => format!("OS fixup type {a}"),
    };
    let additive = if flags & 0x04 != 0 { " (additive)" } else { "" };
    Some(format!(
        "{} at {source_off:#06x}: {target}{additive}",
        reloc_source_name(source)
    ))
}

fn segment_data_blocks(data: &[u8], header: &NeHeader, modules: &[String]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let len = data.len() as u64;
    for seg in segments(data, header) {
        if seg.file_offset == 0 || seg.file_offset >= len {
            continue;
        }
        if blocks.len() == MAX_ITEMS {
            break;
        }
        let start = seg.file_offset as usize;
        let data_end = seg.file_offset.saturating_add(seg.length).min(len) as usize;
        let kind = if seg.flags & SEG_DATA != 0 {
            "DATA"
        } else {
            "CODE"
        };
        let title = format!("Segment {} data ({kind})", seg.index);

        let reloc_start = data_end;
        let has_relocs = seg.flags & SEG_RELOCINFO != 0
            && seg.file_offset + seg.length <= len
            && reloc_start + 2 <= data.len();
        if !has_relocs {
            blocks.push(Block::leaf(title, rng(start, data_end)));
            continue;
        }

        let count = read_u16(data, reloc_start).unwrap_or(0) as usize;
        let reloc_end = (reloc_start + 2 + count * 8).min(data.len());
        let mut records = vec![Block::leaf(
            format!("Count: {count}"),
            rng(reloc_start, reloc_start + 2),
        )];
        for i in 0..count {
            let off = reloc_start + 2 + i * 8;
            if off + 8 > data.len() {
                break;
            }
            if i == MAX_ITEMS {
                records.push(more_block(count - i, off, reloc_end));
                break;
            }
            if let Some(label) = relocation_label(data, header, modules, off) {
                records.push(Block::leaf(label, rng(off, off + 8)));
            }
        }
        let mut children = Vec::new();
        if data_end > start {
            children.push(Block::leaf("Data", rng(start, data_end)));
        }
        children.push(Block::node(
            format!("Relocations ({count})"),
            rng(reloc_start, reloc_end),
            records,
        ));
        blocks.push(Block::node(title, rng(start, reloc_end), children));
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const NE: usize = 0x80;

    fn put(buf: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
        if buf.len() < offset + bytes.len() {
            buf.resize(offset + bytes.len(), 0);
        }
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
        put(buf, offset, &value.to_le_bytes());
    }

    fn put_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        put(buf, offset, &value.to_le_bytes());
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    // Builds a minimal Windows 3.1 DLL:
    //   0x000 DOS header (e_lfanew = 0x80), 0x040 DOS stub
    //   0x080 NE header
    //   0x0C0 segment table (2 entries)
    //   0x0D0 resource table (one RT_ICON), ends 0x0E9
    //   0x0E9 resident name table ("TEST", "Foo" @1), ends 0x0F7
    //   0x0F7 module reference table (1 entry), ends 0x0F9
    //   0x0F9 imported names table ("", "KERNEL", "Func"), ends 0x106
    //   0x106 entry table (1 bundle, 6 bytes), ends 0x10C
    //   0x10C non-resident name table ("Desc"), ends 0x114
    //   0x200 segment 1 code (0x10 bytes) + 1 relocation, ends 0x21A
    //   0x300 segment 2 data (0x20 bytes)
    //   0x400 icon resource (0x20 bytes)
    fn build_ne() -> Vec<u8> {
        let mut d = vec![0u8; 0x420];
        put(&mut d, 0, b"MZ");
        put_u16(&mut d, 0x02, 0x90);
        put_u16(&mut d, 0x04, 3);
        put_u16(&mut d, 0x08, 4);
        put_u16(&mut d, 0x18, 0x40);
        put_u32(&mut d, E_LFANEW_OFFSET, NE as u32);

        put(&mut d, NE, b"NE");
        d[NE + 0x02] = 5; // linker version
        d[NE + 0x03] = 1; // linker revision
        put_u16(&mut d, NE + 0x04, 0x86); // entry table offset
        put_u16(&mut d, NE + 0x06, 6); // entry table length
        put_u32(&mut d, NE + 0x08, 0x12345678); // CRC
        d[NE + 0x0C] = 0x01; // SINGLEDATA
        d[NE + 0x0D] = 0x83; // WINDOWAPI | DLL
        put_u16(&mut d, NE + 0x0E, 2); // auto data segment
        put_u16(&mut d, NE + 0x10, 0x400); // heap
        put_u16(&mut d, NE + 0x12, 0x2000); // stack
        put_u16(&mut d, NE + 0x14, 0x0010); // IP
        put_u16(&mut d, NE + 0x16, 1); // CS
        put_u16(&mut d, NE + 0x18, 0); // SP
        put_u16(&mut d, NE + 0x1A, 2); // SS
        put_u16(&mut d, NE + 0x1C, 2); // segment count
        put_u16(&mut d, NE + 0x1E, 1); // module ref count
        put_u16(&mut d, NE + 0x20, 8); // non-resident table size
        put_u16(&mut d, NE + 0x22, 0x40); // segment table
        put_u16(&mut d, NE + 0x24, 0x50); // resource table
        put_u16(&mut d, NE + 0x26, 0x69); // resident name table
        put_u16(&mut d, NE + 0x28, 0x77); // module ref table
        put_u16(&mut d, NE + 0x2A, 0x79); // imported names table
        put_u32(&mut d, NE + 0x2C, 0x10C); // non-resident table (absolute)
        put_u16(&mut d, NE + 0x32, 8); // alignment shift
        put_u16(&mut d, NE + 0x34, 1); // resource segments
        d[NE + 0x36] = 2; // Windows
        d[NE + 0x37] = 0x08; // gangload
        put_u16(&mut d, NE + 0x3E, 0x030A); // Windows 3.10

        // Segment table.
        put_u16(&mut d, 0xC0, 2); // sector 2 << 8 = 0x200
        put_u16(&mut d, 0xC2, 0x10);
        put_u16(&mut d, 0xC4, 0x0150); // CODE MOVEABLE PRELOAD RELOCINFO
        put_u16(&mut d, 0xC6, 0x10);
        put_u16(&mut d, 0xC8, 3); // sector 3 << 8 = 0x300
        put_u16(&mut d, 0xCA, 0x20);
        put_u16(&mut d, 0xCC, 0x0001); // DATA
        put_u16(&mut d, 0xCE, 0);

        // Resource table.
        put_u16(&mut d, 0xD0, 4); // alignment shift
        put_u16(&mut d, 0xD2, 0x8003); // RT_ICON
        put_u16(&mut d, 0xD4, 1);
        put_u16(&mut d, 0xDA, 0x40); // 0x40 << 4 = 0x400
        put_u16(&mut d, 0xDC, 2); // 2 << 4 = 32 bytes
        put_u16(&mut d, 0xDE, 0x1C30);
        put_u16(&mut d, 0xE0, 0x8001);
        put_u16(&mut d, 0xE6, 0); // end of types
        d[0xE8] = 0; // end of names

        // Resident name table.
        put(&mut d, 0xE9, b"\x04TEST\x00\x00\x03Foo\x01\x00\x00");
        // Module reference table.
        put_u16(&mut d, 0xF7, 1);
        // Imported names table.
        put(&mut d, 0xF9, b"\x00\x06KERNEL\x04Func");
        // Entry table: 1 entry in fixed segment 1, exported, offset 0x0010.
        put(&mut d, 0x106, &[1, 1, 0x01, 0x10, 0x00, 0]);
        // Non-resident name table.
        put(&mut d, 0x10C, b"\x04Desc\x00\x00\x00");

        // Segment 1 relocations: FAR_ADDR import ordinal KERNEL.5 at 0x0004.
        put_u16(&mut d, 0x210, 1);
        put(&mut d, 0x212, &[3, 1, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00]);
        d
    }

    #[test]
    fn matches_ne() {
        assert!(NeDissector.matches(&build_ne()));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!NeDissector.matches(b""));
        assert!(!NeDissector.matches(b"MZ"));
        assert!(!NeDissector.matches(b"not an executable at all"));

        // Truncated: e_lfanew points past the end of the file.
        let data = build_ne();
        assert!(!NeDissector.matches(&data[..NE + 1]));

        // A PE file must not match.
        let mut pe = build_ne();
        put(&mut pe, NE, b"PE\0\0");
        assert!(!NeDissector.matches(&pe));

        // A plain DOS executable must not match.
        let mut dos = vec![0u8; 128];
        put(&mut dos, 0, b"MZ");
        assert!(!NeDissector.matches(&dos));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = build_ne();
        let full = NeDissector.dissect(&data).len();
        for len in [
            0,
            2,
            63,
            64,
            NE,
            NE + 2,
            NE + 0x20,
            0xC8,
            0xE0,
            0x100,
            0x110,
            0x205,
            0x215,
        ] {
            let blocks = NeDissector.dissect(&data[..len]);
            assert!(blocks.len() <= full, "len {len}");
        }
        assert!(NeDissector.dissect(&data[..32]).is_empty());
        assert_eq!(NeDissector.dissect(&data[..NE + 0x20]).len(), 3);
    }

    #[test]
    fn dissect_dos_and_ne_headers() {
        let blocks = NeDissector.dissect(&build_ne());

        let dos = find_block(&blocks, "DOS header");
        assert_eq!(dos.range, ByteRange::new(0, 64));
        assert_eq!(
            find_block(&dos.children, "Signature: MZ").range,
            ByteRange::new(0, 2)
        );
        find_block(&dos.children, "Bytes on last page: 144");
        assert_eq!(
            find_block(&dos.children, "NE header offset: 128").range,
            ByteRange::new(0x3C, 0x40)
        );
        assert_eq!(
            find_block(&blocks, "DOS stub").range,
            ByteRange::new(0x40, 0x80)
        );

        let ne = find_block(&blocks, "NE header");
        assert_eq!(ne.range, ByteRange::new(0x80, 0xC0));
        let c = &ne.children;
        find_block(c, "Signature: NE");
        find_block(c, "Linker version: 5.1");
        find_block(c, "Entry table offset: 0x86 (file 0x106)");
        find_block(c, "CRC: 0x12345678");
        assert_eq!(
            find_block(c, "Program flags: 0x01 (SINGLEDATA)").range,
            ByteRange::new(0x8C, 0x8D)
        );
        find_block(c, "Application flags: 0x83 (WINDOWAPI, DLL)");
        find_block(c, "Auto data segment: 2");
        find_block(c, "CS:IP: 0001:0010");
        find_block(c, "SS:SP: 0002:0000");
        find_block(c, "Segment count: 2");
        find_block(c, "Non-resident name table offset: 0x10c");
        find_block(c, "Alignment shift: 8 (256 bytes)");
        assert_eq!(
            find_block(c, "Target OS: Windows").range,
            ByteRange::new(0xB6, 0xB7)
        );
        find_block(c, "OS/2 flags: 0x08 (GANGLOAD)");
        assert_eq!(
            find_block(c, "Expected Windows version: 3.10").range,
            ByteRange::new(0xBE, 0xC0)
        );
    }

    #[test]
    fn dissect_segment_and_resource_tables() {
        let blocks = NeDissector.dissect(&build_ne());

        let segs = find_block(&blocks, "Segment table (2 entries)");
        assert_eq!(segs.range, ByteRange::new(0xC0, 0xD0));
        let seg1 = find_block(&segs.children, "Segment 1: CODE");
        assert_eq!(seg1.range, ByteRange::new(0xC0, 0xC8));
        find_block(&seg1.children, "Sector offset: 2 (file 0x200)");
        find_block(&seg1.children, "Length: 16");
        find_block(
            &seg1.children,
            "Flags: 0x0150 (CODE, MOVEABLE, PRELOAD, RELOCINFO)",
        );
        let seg2 = find_block(&segs.children, "Segment 2: DATA");
        find_block(&seg2.children, "Minimum allocation: 65536");

        let rsrc = find_block(&blocks, "Resource table (1 types)");
        assert_eq!(rsrc.range, ByteRange::new(0xD0, 0xE9));
        find_block(&rsrc.children, "Alignment shift: 4 (16 bytes)");
        let icons = find_block(&rsrc.children, "Type RT_ICON (1 resources)");
        assert_eq!(icons.range, ByteRange::new(0xD2, 0xE6));
        find_block(&icons.children, "Type ID: RT_ICON (0x8003)");
        let icon = find_block(&icons.children, "Resource 1");
        assert_eq!(icon.range, ByteRange::new(0xDA, 0xE6));
        find_block(&icon.children, "Offset: 64 (file 0x400)");
        find_block(&icon.children, "Length: 2 (32 bytes)");
        find_block(
            &icon.children,
            "Flags: 0x1c30 (MOVEABLE, PURE, DISCARDABLE)",
        );
        find_block(&rsrc.children, "End of types");

        let rdata = find_block(&blocks, "Resource data (1 resources)");
        assert_eq!(
            find_block(&rdata.children, "RT_ICON 1").range,
            ByteRange::new(0x400, 0x420)
        );
    }

    #[test]
    fn dissect_name_and_entry_tables() {
        let blocks = NeDissector.dissect(&build_ne());

        let res = find_block(&blocks, "Resident name table");
        assert_eq!(res.range, ByteRange::new(0xE9, 0xF7));
        assert_eq!(
            find_block(&res.children, "Module name: TEST").range,
            ByteRange::new(0xE9, 0xF0)
        );
        assert_eq!(
            find_block(&res.children, "Foo (ordinal 1)").range,
            ByteRange::new(0xF0, 0xF6)
        );
        find_block(&res.children, "End of table");

        let modref = find_block(&blocks, "Module reference table (1 modules)");
        assert_eq!(modref.range, ByteRange::new(0xF7, 0xF9));
        find_block(&modref.children, "Module 1: KERNEL (name offset 0x1)");

        let imp = find_block(&blocks, "Imported names table");
        assert_eq!(imp.range, ByteRange::new(0xF9, 0x106));
        find_block(&imp.children, "Name at 0x0: (empty)");
        assert_eq!(
            find_block(&imp.children, "Name at 0x1: KERNEL").range,
            ByteRange::new(0xFA, 0x101)
        );
        find_block(&imp.children, "Name at 0x8: Func");

        let entry = find_block(&blocks, "Entry table");
        assert_eq!(entry.range, ByteRange::new(0x106, 0x10C));
        let bundle = find_block(&entry.children, "Bundle: ordinals 1-1, segment 1");
        assert_eq!(bundle.range, ByteRange::new(0x106, 0x10B));
        find_block(&bundle.children, "Indicator: fixed segment 1");
        assert_eq!(
            find_block(&bundle.children, "Ordinal 1 Foo: 1:0010 (exported)").range,
            ByteRange::new(0x108, 0x10B)
        );
        find_block(&entry.children, "End of table");

        let nonres = find_block(&blocks, "Non-resident name table");
        assert_eq!(nonres.range, ByteRange::new(0x10C, 0x114));
        find_block(&nonres.children, "Description: Desc");
    }

    #[test]
    fn dissect_segment_data_and_relocations() {
        let blocks = NeDissector.dissect(&build_ne());

        let seg1 = find_block(&blocks, "Segment 1 data (CODE)");
        assert_eq!(seg1.range, ByteRange::new(0x200, 0x21A));
        assert_eq!(
            find_block(&seg1.children, "Data").range,
            ByteRange::new(0x200, 0x210)
        );
        let relocs = find_block(&seg1.children, "Relocations (1)");
        assert_eq!(relocs.range, ByteRange::new(0x210, 0x21A));
        find_block(&relocs.children, "Count: 1");
        assert_eq!(
            find_block(
                &relocs.children,
                "FAR_ADDR at 0x0004: import KERNEL ordinal 5"
            )
            .range,
            ByteRange::new(0x212, 0x21A)
        );

        let seg2 = find_block(&blocks, "Segment 2 data (DATA)");
        assert_eq!(seg2.range, ByteRange::new(0x300, 0x320));
        assert!(seg2.children.is_empty());

        // Top-level blocks are in file order.
        let starts: Vec<u64> = blocks.iter().map(|b| b.range.start).collect();
        let mut sorted = starts.clone();
        sorted.sort();
        assert_eq!(starts, sorted);
    }

    #[test]
    fn long_lists_are_capped() {
        let mut data = build_ne();
        // 300 relocations in segment 1.
        put_u16(&mut data, 0x210, 300);
        data.resize(0x212 + 300 * 8, 0);
        let blocks = NeDissector.dissect(&data);
        let seg1 = find_block(&blocks, "Segment 1 data (CODE)");
        let relocs = find_block(&seg1.children, "Relocations (300)");
        assert_eq!(relocs.children.len(), 1 + MAX_ITEMS + 1);
        let more = find_block(&relocs.children, "(44 more not shown)");
        assert_eq!(more.range.end, relocs.range.end);
    }

    #[test]
    fn identify_reports_ne() {
        assert_eq!(super::super::identify(&build_ne()), "NE");
    }
}
