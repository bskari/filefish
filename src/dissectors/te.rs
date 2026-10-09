use super::{Block, ByteRange, Dissector};

const TE_MAGIC: &[u8] = b"VZ";
const TE_HEADER_SIZE: usize = 40;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_SECTIONS: u8 = 96;
const DEBUG_ENTRY_SIZE: usize = 28;
const MAX_DEBUG_ENTRIES: usize = 16;
const MAX_RELOC_BLOCKS: usize = 512;
const MAX_RELOC_ENTRIES_PER_BLOCK: usize = 64;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

pub struct TeDissector;

impl Dissector for TeDissector {
    fn name(&self) -> &'static str {
        "TE"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if !data.starts_with(TE_MAGIC) || data.len() < TE_HEADER_SIZE {
            return false;
        }
        let (Some(machine), Some(sections), Some(stripped)) =
            (read_u16(data, 2), read_u8(data, 4), read_u16(data, 6))
        else {
            return false;
        };
        if machine_name(machine).is_none() {
            return false;
        }
        if sections == 0 || sections > MAX_SECTIONS {
            return false;
        }
        // StrippedSize covers the removed DOS header, PE signature, COFF
        // header and optional header, so it must exceed the TE header itself.
        if (stripped as usize) <= TE_HEADER_SIZE {
            return false;
        }
        TE_HEADER_SIZE + sections as usize * SECTION_HEADER_SIZE <= data.len()
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let Some(header) = TeHeader::parse(data) else {
            return blocks;
        };

        let sections = parse_sections(data, &header);

        blocks.push(header_block(&header, &sections));

        if !sections.is_empty() {
            let table_end = TE_HEADER_SIZE + sections.len() * SECTION_HEADER_SIZE;
            blocks.push(
                Block::node(
                    format!("Section headers ({})", sections.len()),
                    range(TE_HEADER_SIZE, table_end),
                    sections.iter().map(section_header_block).collect(),
                )
                .expanded(),
            );
        }

        // Blocks that point into the image body; each is nested inside the
        // section data that contains it, or emitted at top level otherwise.
        let mut located = Vec::new();
        if let Some(block) = entry_point_block(data, &header, &sections) {
            located.push(block);
        }
        if let Some(block) = relocations_block(data, &header) {
            located.push(block);
        }
        located.extend(debug_blocks(data, &header));

        let mut section_data: Vec<Block> = sections
            .iter()
            .filter_map(|s| {
                let (start, end) = s.data_range(data.len(), header.stripped_size)?;
                Some(Block::node(
                    format!("Section data: {}", s.name),
                    range(start, end),
                    Vec::new(),
                ))
            })
            .collect();

        let mut top_level = Vec::new();
        for block in located {
            let target = section_data
                .iter_mut()
                .find(|s| s.range.start <= block.range.start && block.range.end <= s.range.end);
            match target {
                Some(section) => section.children.push(block),
                None => top_level.push(block),
            }
        }
        for section in &mut section_data {
            section.children.sort_by_key(|b| b.range.start);
            if section.children.is_empty() {
                section.expandable = false;
            }
        }

        let mut body: Vec<Block> = section_data.into_iter().chain(top_level).collect();
        body.sort_by_key(|b| b.range.start);
        blocks.extend(body);

        blocks
    }
}

struct TeHeader {
    machine: u16,
    number_of_sections: u8,
    subsystem: u8,
    stripped_size: u16,
    entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    reloc_va: u32,
    reloc_size: u32,
    debug_va: u32,
    debug_size: u32,
}

impl TeHeader {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.get(0..2)? != TE_MAGIC {
            return None;
        }
        Some(Self {
            machine: read_u16(data, 2)?,
            number_of_sections: read_u8(data, 4)?,
            subsystem: read_u8(data, 5)?,
            stripped_size: read_u16(data, 6)?,
            entry_point: read_u32(data, 8)?,
            base_of_code: read_u32(data, 12)?,
            image_base: read_u64(data, 16)?,
            reloc_va: read_u32(data, 24)?,
            reloc_size: read_u32(data, 28)?,
            debug_va: read_u32(data, 32)?,
            debug_size: read_u32(data, 36)?,
        })
    }

    /// Converts an RVA or original PE file offset to a TE file offset.
    fn to_file_offset(&self, value: u32) -> Option<usize> {
        (value as usize + TE_HEADER_SIZE).checked_sub(self.stripped_size as usize)
    }
}

struct Section {
    offset: usize,
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

impl Section {
    fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.size_of_raw_data) as u64;
        let start = self.virtual_address as u64;
        (rva as u64) >= start && (rva as u64) < start + size
    }

    fn data_range(&self, len: usize, stripped_size: u16) -> Option<(usize, usize)> {
        if self.size_of_raw_data == 0 {
            return None;
        }
        let start = (self.pointer_to_raw_data as usize + TE_HEADER_SIZE)
            .checked_sub(stripped_size as usize)?;
        if start >= len {
            return None;
        }
        let end = start
            .saturating_add(self.size_of_raw_data as usize)
            .min(len);
        Some((start, end))
    }
}

fn parse_sections(data: &[u8], header: &TeHeader) -> Vec<Section> {
    let mut sections = Vec::new();
    for i in 0..header.number_of_sections as usize {
        let offset = TE_HEADER_SIZE + i * SECTION_HEADER_SIZE;
        match parse_section(data, offset) {
            Some(section) => sections.push(section),
            None => break,
        }
    }
    sections
}

fn parse_section(data: &[u8], offset: usize) -> Option<Section> {
    let name_bytes = data.get(offset..offset + 8)?;
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    let name = String::from_utf8_lossy(&name_bytes[..name_end])
        .trim_end()
        .to_string();
    Some(Section {
        offset,
        name,
        virtual_size: read_u32(data, offset + 8)?,
        virtual_address: read_u32(data, offset + 12)?,
        size_of_raw_data: read_u32(data, offset + 16)?,
        pointer_to_raw_data: read_u32(data, offset + 20)?,
        pointer_to_relocations: read_u32(data, offset + 24)?,
        pointer_to_linenumbers: read_u32(data, offset + 28)?,
        number_of_relocations: read_u16(data, offset + 32)?,
        number_of_linenumbers: read_u16(data, offset + 34)?,
        characteristics: read_u32(data, offset + 36)?,
    })
}

fn range(start: usize, end: usize) -> ByteRange {
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

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn machine_name(value: u16) -> Option<&'static str> {
    Some(match value {
        0x014c => "I386 (IA32)",
        0x8664 => "AMD64 (x64)",
        0x0200 => "IA64",
        0x01c2 => "ARM Thumb (mixed)",
        0x01c4 => "ARMNT",
        0xAA64 => "ARM64 (AArch64)",
        0x0EBC => "EBC",
        0x5032 => "RISCV32",
        0x5064 => "RISCV64",
        0x5128 => "RISCV128",
        0x6232 => "LOONGARCH32",
        0x6264 => "LOONGARCH64",
        _ => return None,
    })
}

fn subsystem_name(value: u8) -> String {
    match value {
        0 => "UNKNOWN".to_string(),
        1 => "NATIVE".to_string(),
        2 => "WINDOWS_GUI".to_string(),
        3 => "WINDOWS_CUI".to_string(),
        5 => "OS2_CUI".to_string(),
        7 => "POSIX_CUI".to_string(),
        9 => "WINDOWS_CE_GUI".to_string(),
        10 => "EFI application".to_string(),
        11 => "EFI boot service driver".to_string(),
        12 => "EFI runtime driver".to_string(),
        13 => "EFI SAL runtime driver".to_string(),
        14 => "XBOX".to_string(),
        16 => "WINDOWS_BOOT_APPLICATION".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn section_flags(characteristics: u32) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0008, "TYPE_NO_PAD"),
        (0x0000_0020, "CNT_CODE"),
        (0x0000_0040, "CNT_INITIALIZED_DATA"),
        (0x0000_0080, "CNT_UNINITIALIZED_DATA"),
        (0x0000_0200, "LNK_INFO"),
        (0x0000_0800, "LNK_REMOVE"),
        (0x0000_1000, "LNK_COMDAT"),
        (0x0000_8000, "GPREL"),
        (0x0100_0000, "LNK_NRELOC_OVFL"),
        (0x0200_0000, "MEM_DISCARDABLE"),
        (0x0400_0000, "MEM_NOT_CACHED"),
        (0x0800_0000, "MEM_NOT_PAGED"),
        (0x1000_0000, "MEM_SHARED"),
        (0x2000_0000, "MEM_EXECUTE"),
        (0x4000_0000, "MEM_READ"),
        (0x8000_0000, "MEM_WRITE"),
    ];
    let mut names: Vec<String> = FLAGS
        .iter()
        .filter(|(bit, _)| characteristics & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    let align = (characteristics >> 20) & 0xF;
    if (1..=14).contains(&align) {
        names.push(format!("ALIGN_{}BYTES", 1u32 << (align - 1)));
    }
    names.join(" | ")
}

fn reloc_type_name(machine: u16, kind: u16) -> String {
    let is_arm = matches!(machine, 0x01c2 | 0x01c4);
    let is_riscv = matches!(machine, 0x5032 | 0x5064 | 0x5128);
    let is_loongarch = matches!(machine, 0x6232 | 0x6264);
    let name = match kind {
        0 => "ABSOLUTE",
        1 => "HIGH",
        2 => "LOW",
        3 => "HIGHLOW",
        4 => "HIGHADJ",
        5 if is_arm => "ARM_MOV32",
        5 if is_riscv => "RISCV_HIGH20",
        5 => "MIPS_JMPADDR",
        7 if is_arm => "THUMB_MOV32",
        7 if is_riscv => "RISCV_LOW12I",
        8 if is_riscv => "RISCV_LOW12S",
        8 if machine == 0x6232 => "LOONGARCH32_MARK_LA",
        8 if is_loongarch => "LOONGARCH64_MARK_LA",
        9 if machine == 0x0200 => "IA64_IMM64",
        9 => "MIPS_JMPADDR16",
        10 => "DIR64",
        _ => return format!("type {kind}"),
    };
    name.to_string()
}

fn debug_type_name(value: u32) -> String {
    match value {
        0 => "UNKNOWN".to_string(),
        1 => "COFF".to_string(),
        2 => "CODEVIEW".to_string(),
        3 => "FPO".to_string(),
        4 => "MISC".to_string(),
        5 => "EXCEPTION".to_string(),
        6 => "FIXUP".to_string(),
        7 => "OMAP_TO_SRC".to_string(),
        8 => "OMAP_FROM_SRC".to_string(),
        9 => "BORLAND".to_string(),
        11 => "CLSID".to_string(),
        12 => "VC_FEATURE".to_string(),
        13 => "POGO".to_string(),
        14 => "ILTCG".to_string(),
        15 => "MPX".to_string(),
        16 => "REPRO".to_string(),
        20 => "EX_DLLCHARACTERISTICS".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn section_name_for_rva(sections: &[Section], rva: u32) -> Option<&str> {
    sections
        .iter()
        .find(|s| s.contains_rva(rva))
        .map(|s| s.name.as_str())
}

fn describe_rva(header: &TeHeader, sections: &[Section], rva: u32) -> String {
    let mut out = format!("{rva:#x}");
    if let Some(name) = section_name_for_rva(sections, rva) {
        out.push_str(&format!(" in {name}"));
    }
    if let Some(off) = header.to_file_offset(rva) {
        out.push_str(&format!(", file offset {off:#x}"));
    }
    out
}

fn data_directory_block(
    label: &str,
    offset: usize,
    va: u32,
    size: u32,
    header: &TeHeader,
) -> Block {
    let location = if va == 0 && size == 0 {
        " (none)".to_string()
    } else {
        match header.to_file_offset(va) {
            Some(off) => format!(" at file offset {off:#x}"),
            None => " (before start of file)".to_string(),
        }
    };
    Block::node(
        format!("{label}{location}"),
        range(offset, offset + 8),
        vec![
            Block::leaf(
                format!("Virtual address: {va:#x}"),
                range(offset, offset + 4),
            ),
            Block::leaf(format!("Size: {size}"), range(offset + 4, offset + 8)),
        ],
    )
}

fn header_block(header: &TeHeader, sections: &[Section]) -> Block {
    let machine = machine_name(header.machine)
        .map(str::to_string)
        .unwrap_or_else(|| format!("unknown ({:#06x})", header.machine));
    let children = vec![
        Block::leaf("Signature: VZ", range(0, 2)),
        Block::leaf(format!("Machine: {machine}"), range(2, 4)),
        Block::leaf(
            format!("Number of sections: {}", header.number_of_sections),
            range(4, 5),
        ),
        Block::leaf(
            format!("Subsystem: {}", subsystem_name(header.subsystem)),
            range(5, 6),
        ),
        Block::leaf(
            format!("Stripped size: {:#x}", header.stripped_size),
            range(6, 8),
        ),
        Block::leaf(
            format!(
                "Address of entry point: {}",
                describe_rva(header, sections, header.entry_point)
            ),
            range(8, 12),
        ),
        Block::leaf(
            format!("Base of code: {:#x}", header.base_of_code),
            range(12, 16),
        ),
        Block::leaf(
            format!("Image base: {:#x}", header.image_base),
            range(16, 24),
        ),
        data_directory_block(
            "Base relocation directory",
            24,
            header.reloc_va,
            header.reloc_size,
            header,
        ),
        data_directory_block(
            "Debug directory",
            32,
            header.debug_va,
            header.debug_size,
            header,
        ),
    ];
    Block::node("TE header", range(0, TE_HEADER_SIZE), children).expanded()
}

fn section_header_block(section: &Section) -> Block {
    let o = section.offset;
    let flags = section_flags(section.characteristics);
    let characteristics = if flags.is_empty() {
        format!("Characteristics: {:#010x}", section.characteristics)
    } else {
        format!(
            "Characteristics: {:#010x} ({flags})",
            section.characteristics
        )
    };
    let children = vec![
        Block::leaf(format!("Name: {}", section.name), range(o, o + 8)),
        Block::leaf(
            format!("Virtual size: {:#x}", section.virtual_size),
            range(o + 8, o + 12),
        ),
        Block::leaf(
            format!("Virtual address: {:#x}", section.virtual_address),
            range(o + 12, o + 16),
        ),
        Block::leaf(
            format!("Size of raw data: {:#x}", section.size_of_raw_data),
            range(o + 16, o + 20),
        ),
        Block::leaf(
            format!("Pointer to raw data: {:#x}", section.pointer_to_raw_data),
            range(o + 20, o + 24),
        ),
        Block::leaf(
            format!(
                "Pointer to relocations: {:#x}",
                section.pointer_to_relocations
            ),
            range(o + 24, o + 28),
        ),
        Block::leaf(
            format!(
                "Pointer to line numbers: {:#x}",
                section.pointer_to_linenumbers
            ),
            range(o + 28, o + 32),
        ),
        Block::leaf(
            format!("Number of relocations: {}", section.number_of_relocations),
            range(o + 32, o + 34),
        ),
        Block::leaf(
            format!("Number of line numbers: {}", section.number_of_linenumbers),
            range(o + 34, o + 36),
        ),
        Block::leaf(characteristics, range(o + 36, o + 40)),
    ];
    Block::node(
        format!("Section: {}", section.name),
        range(o, o + SECTION_HEADER_SIZE),
        children,
    )
}

fn entry_point_block(data: &[u8], header: &TeHeader, sections: &[Section]) -> Option<Block> {
    let offset = header.to_file_offset(header.entry_point)?;
    if offset >= data.len() {
        return None;
    }
    let location = match section_name_for_rva(sections, header.entry_point) {
        Some(name) => format!(" in {name}"),
        None => String::new(),
    };
    Some(Block::leaf(
        format!("Entry point: {:#x}{location}", header.entry_point),
        range(offset, offset + 1),
    ))
}

fn relocations_block(data: &[u8], header: &TeHeader) -> Option<Block> {
    if header.reloc_size == 0 {
        return None;
    }
    let start = header.to_file_offset(header.reloc_va)?;
    if start >= data.len() {
        return None;
    }
    let end = start
        .saturating_add(header.reloc_size as usize)
        .min(data.len());

    let mut children = Vec::new();
    let mut offset = start;
    while offset + 8 <= end && children.len() < MAX_RELOC_BLOCKS {
        let (Some(page), Some(block_size)) = (read_u32(data, offset), read_u32(data, offset + 4))
        else {
            break;
        };
        if block_size < 8 {
            break;
        }
        let block_end = offset.saturating_add(block_size as usize).min(end);
        children.push(relocation_block(
            data,
            header.machine,
            offset,
            block_end,
            page,
            block_size,
        ));
        offset = block_end;
    }
    if offset < end && children.len() >= MAX_RELOC_BLOCKS {
        children.push(Block::leaf("More relocation blocks", range(offset, end)));
    }

    Some(Block::node(
        format!("Base relocations ({} blocks)", children.len()),
        range(start, end),
        children,
    ))
}

fn relocation_block(
    data: &[u8],
    machine: u16,
    start: usize,
    end: usize,
    page: u32,
    block_size: u32,
) -> Block {
    let total_entries = (block_size as usize - 8) / 2;
    let mut children = vec![
        Block::leaf(format!("Page RVA: {page:#x}"), range(start, start + 4)),
        Block::leaf(
            format!("Block size: {block_size}"),
            range(start + 4, start + 8),
        ),
    ];
    let mut offset = start + 8;
    let mut shown = 0;
    while offset + 2 <= end && shown < MAX_RELOC_ENTRIES_PER_BLOCK {
        let Some(entry) = read_u16(data, offset) else {
            break;
        };
        let kind = entry >> 12;
        let target = page.wrapping_add((entry & 0x0FFF) as u32);
        children.push(Block::leaf(
            format!("{} at {target:#x}", reloc_type_name(machine, kind)),
            range(offset, offset + 2),
        ));
        offset += 2;
        shown += 1;
    }
    if offset + 2 <= end {
        let remaining = (end - offset) / 2;
        children.push(Block::leaf(
            format!("... {remaining} more entries"),
            range(offset, end),
        ));
    }
    Block::node(
        format!("Relocation block: page {page:#x} ({total_entries} entries)"),
        range(start, end),
        children,
    )
}

fn debug_blocks(data: &[u8], header: &TeHeader) -> Vec<Block> {
    let mut blocks = Vec::new();
    if header.debug_size == 0 {
        return blocks;
    }
    let Some(start) = header.to_file_offset(header.debug_va) else {
        return blocks;
    };
    if start >= data.len() {
        return blocks;
    }
    let end = start
        .saturating_add(header.debug_size as usize)
        .min(data.len());

    let mut entries = Vec::new();
    let mut offset = start;
    while offset + DEBUG_ENTRY_SIZE <= end && entries.len() < MAX_DEBUG_ENTRIES {
        let Some((entry, record)) = debug_entry_block(data, header, offset) else {
            break;
        };
        entries.push(entry);
        blocks.extend(record);
        offset += DEBUG_ENTRY_SIZE;
    }

    blocks.insert(
        0,
        Block::node("Debug directory", range(start, end), entries).expanded(),
    );
    blocks
}

fn debug_entry_block(data: &[u8], header: &TeHeader, o: usize) -> Option<(Block, Option<Block>)> {
    let characteristics = read_u32(data, o)?;
    let time_date_stamp = read_u32(data, o + 4)?;
    let major = read_u16(data, o + 8)?;
    let minor = read_u16(data, o + 10)?;
    let kind = read_u32(data, o + 12)?;
    let size_of_data = read_u32(data, o + 16)?;
    let rva = read_u32(data, o + 20)?;
    let file_offset = read_u32(data, o + 24)?;

    let type_name = debug_type_name(kind);
    let children = vec![
        Block::leaf(
            format!("Characteristics: {characteristics:#x}"),
            range(o, o + 4),
        ),
        Block::leaf(
            format!("Time/date stamp: {time_date_stamp}"),
            range(o + 4, o + 8),
        ),
        Block::leaf(format!("Major version: {major}"), range(o + 8, o + 10)),
        Block::leaf(format!("Minor version: {minor}"), range(o + 10, o + 12)),
        Block::leaf(format!("Type: {type_name}"), range(o + 12, o + 16)),
        Block::leaf(
            format!("Size of data: {size_of_data}"),
            range(o + 16, o + 20),
        ),
        Block::leaf(format!("RVA: {rva:#x}"), range(o + 20, o + 24)),
        Block::leaf(
            format!("Pointer to raw data: {file_offset:#x}"),
            range(o + 24, o + 28),
        ),
    ];

    let record = if kind == IMAGE_DEBUG_TYPE_CODEVIEW && size_of_data > 0 {
        let pointer = if file_offset != 0 { file_offset } else { rva };
        header
            .to_file_offset(pointer)
            .and_then(|start| codeview_block(data, start, size_of_data as usize))
    } else {
        None
    };

    let label = match record.as_ref().and_then(|r| r.children.last()) {
        Some(path) if path.label.starts_with("PDB path: ") => {
            format!("Debug entry: {type_name} ({})", &path.label[10..])
        }
        _ => format!("Debug entry: {type_name}"),
    };
    Some((
        Block::node(label, range(o, o + DEBUG_ENTRY_SIZE), children),
        record,
    ))
}

fn codeview_block(data: &[u8], start: usize, size: usize) -> Option<Block> {
    if start >= data.len() {
        return None;
    }
    let end = start.saturating_add(size).min(data.len());
    let signature = data.get(start..start + 4)?;
    if start + 4 > end {
        return None;
    }
    let sig_text = String::from_utf8_lossy(signature).to_string();
    let mut children = vec![Block::leaf(
        format!("Signature: {sig_text}"),
        range(start, start + 4),
    )];

    let path_offset = match signature {
        b"RSDS" => {
            if start + 24 > end {
                return None;
            }
            children.push(Block::leaf(
                format!("GUID: {}", format_guid(&data[start + 4..start + 20])),
                range(start + 4, start + 20),
            ));
            children.push(Block::leaf(
                format!("Age: {}", read_u32(data, start + 20)?),
                range(start + 20, start + 24),
            ));
            start + 24
        }
        b"NB10" => {
            if start + 16 > end {
                return None;
            }
            children.push(Block::leaf(
                format!("Offset: {}", read_u32(data, start + 4)?),
                range(start + 4, start + 8),
            ));
            children.push(Block::leaf(
                format!("Time/date stamp: {}", read_u32(data, start + 8)?),
                range(start + 8, start + 12),
            ));
            children.push(Block::leaf(
                format!("Age: {}", read_u32(data, start + 12)?),
                range(start + 12, start + 16),
            ));
            start + 16
        }
        b"MTOC" => {
            if start + 20 > end {
                return None;
            }
            children.push(Block::leaf(
                format!("UUID: {}", format_uuid(&data[start + 4..start + 20])),
                range(start + 4, start + 20),
            ));
            start + 20
        }
        _ => {
            return Some(Block::node(
                format!("CodeView record ({sig_text})"),
                range(start, end),
                children,
            ));
        }
    };

    if path_offset < end {
        let bytes = &data[path_offset..end];
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let path = String::from_utf8_lossy(&bytes[..len]).to_string();
        let path_end = (path_offset + len + 1).min(end);
        children.push(Block::leaf(
            format!("PDB path: {path}"),
            range(path_offset, path_end),
        ));
    }

    Some(
        Block::node(
            format!("CodeView record ({sig_text})"),
            range(start, end),
            children,
        )
        .expanded(),
    )
}

fn format_guid(bytes: &[u8]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail: String = bytes[10..16].iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{tail}",
        bytes[8], bytes[9]
    )
}

fn format_uuid(bytes: &[u8]) -> String {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRIPPED: u16 = 0x1E0;

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

    fn put_section(
        buf: &mut Vec<u8>,
        offset: usize,
        name: &[u8],
        va: u32,
        size: u32,
        characteristics: u32,
    ) {
        put(buf, offset, name);
        put_u32(buf, offset + 8, size); // VirtualSize
        put_u32(buf, offset + 12, va); // VirtualAddress
        put_u32(buf, offset + 16, size); // SizeOfRawData
        put_u32(buf, offset + 20, va); // PointerToRawData (== VA, as GenFw emits)
        put_u32(buf, offset + 36, characteristics);
    }

    // Builds a TE image (x64, EFI boot service driver) with two sections:
    // .text (RVA 0x240, 0x100 bytes; holds the entry point, the debug
    // directory and an RSDS CodeView record) and .reloc (RVA 0x340, 0x20
    // bytes; one relocation block). StrippedSize is 0x1E0, so file offset =
    // RVA - 0x1E0 + 0x28: .text at 0x88, .reloc at 0x188.
    fn build_te() -> Vec<u8> {
        let mut data = Vec::new();
        put(&mut data, 0, b"VZ");
        put_u16(&mut data, 2, 0x8664); // Machine
        data.resize(TE_HEADER_SIZE, 0);
        data[4] = 2; // NumberOfSections
        data[5] = 11; // Subsystem: EFI boot service driver
        put_u16(&mut data, 6, STRIPPED);
        put_u32(&mut data, 8, 0x250); // AddressOfEntryPoint
        put_u32(&mut data, 12, 0x240); // BaseOfCode
        put(&mut data, 16, &0x10_0000u64.to_le_bytes()); // ImageBase
        put_u32(&mut data, 24, 0x340); // reloc VA
        put_u32(&mut data, 28, 12); // reloc size
        put_u32(&mut data, 32, 0x2C0); // debug VA
        put_u32(&mut data, 36, 28); // debug size

        put_section(&mut data, 40, b".text\0\0\0", 0x240, 0x100, 0x6000_0020);
        put_section(&mut data, 80, b".reloc\0\0", 0x340, 0x20, 0x4200_0040);
        data.resize(0x188 + 0x20, 0);

        // Debug directory entry at file offset 0x108.
        put_u32(&mut data, 0x108 + 12, 2); // Type: CODEVIEW
        put_u32(&mut data, 0x108 + 16, 30); // SizeOfData
        put_u32(&mut data, 0x108 + 20, 0x2E0); // RVA
        put_u32(&mut data, 0x108 + 24, 0x2E0); // FileOffset (PE)

        // RSDS record at file offset 0x128.
        put(&mut data, 0x128, b"RSDS");
        put_u32(&mut data, 0x128 + 20, 1); // Age
        put(&mut data, 0x128 + 24, b"a.pdb\0");

        // Relocation block at file offset 0x188.
        put_u32(&mut data, 0x188, 0x1000); // Page RVA
        put_u32(&mut data, 0x188 + 4, 12); // Block size
        put_u16(&mut data, 0x188 + 8, 0xA010); // DIR64 at +0x10
        put_u16(&mut data, 0x188 + 10, 0x0000); // ABSOLUTE padding

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
    fn matches_te_image() {
        assert!(TeDissector.matches(&build_te()));
    }

    #[test]
    fn does_not_match_non_te_data() {
        assert!(!TeDissector.matches(b""));
        assert!(!TeDissector.matches(b"VZ"));
        assert!(!TeDissector.matches(b"not a terse executable at all, really no"));

        // Truncated: header present but section table does not fit.
        let data = build_te();
        assert!(!TeDissector.matches(&data[..100]));

        let mut bad = build_te();
        put_u16(&mut bad, 2, 0x1234); // unknown machine
        assert!(!TeDissector.matches(&bad));

        let mut bad = build_te();
        bad[4] = 0; // no sections
        assert!(!TeDissector.matches(&bad));

        let mut bad = build_te();
        bad[4] = 97; // too many sections
        assert!(!TeDissector.matches(&bad));

        let mut bad = build_te();
        put_u16(&mut bad, 6, 40); // StrippedSize not larger than TE header
        assert!(!TeDissector.matches(&bad));
    }

    #[test]
    fn dissect_handles_truncated_input() {
        assert!(TeDissector.dissect(b"VZ").is_empty());
        assert!(TeDissector.dissect(b"").is_empty());

        let data = build_te();
        let full = TeDissector.dissect(&data);
        for len in 0..data.len() {
            let blocks = TeDissector.dissect(&data[..len]);
            assert!(blocks.len() <= full.len());
        }
        let blocks = TeDissector.dissect(&data[..60]);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "TE header");
    }

    #[test]
    fn dissect_parses_header() {
        let blocks = TeDissector.dissect(&build_te());
        let header = find_block(&blocks, "TE header");
        assert_eq!(header.range, ByteRange::new(0, 40));
        assert!(header.default_expanded);
        let c = &header.children;
        assert_eq!(find_block(c, "Signature: VZ").range, ByteRange::new(0, 2));
        assert_eq!(
            find_block(c, "Machine: AMD64 (x64)").range,
            ByteRange::new(2, 4)
        );
        find_block(c, "Number of sections: 2");
        assert_eq!(
            find_block(c, "Subsystem: EFI boot service driver").range,
            ByteRange::new(5, 6)
        );
        find_block(c, "Stripped size: 0x1e0");
        assert_eq!(
            find_block(
                c,
                "Address of entry point: 0x250 in .text, file offset 0x98"
            )
            .range,
            ByteRange::new(8, 12)
        );
        find_block(c, "Image base: 0x100000");
        let reloc = find_block(c, "Base relocation directory at file offset 0x188");
        assert_eq!(reloc.range, ByteRange::new(24, 32));
        let debug = find_block(c, "Debug directory at file offset 0x108");
        assert_eq!(debug.range, ByteRange::new(32, 40));
    }

    #[test]
    fn dissect_parses_section_headers() {
        let blocks = TeDissector.dissect(&build_te());
        let table = find_block(&blocks, "Section headers (2)");
        assert_eq!(table.range, ByteRange::new(40, 120));
        let text = find_block(&table.children, "Section: .text");
        assert_eq!(text.range, ByteRange::new(40, 80));
        find_block(
            &text.children,
            "Characteristics: 0x60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)",
        );
        let reloc = find_block(&table.children, "Section: .reloc");
        find_block(
            &reloc.children,
            "Characteristics: 0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)",
        );
    }

    #[test]
    fn dissect_locates_section_data_and_contents() {
        let blocks = TeDissector.dissect(&build_te());
        let text = find_block(&blocks, "Section data: .text");
        assert_eq!(text.range, ByteRange::new(0x88, 0x188));

        let entry = find_block(&text.children, "Entry point: 0x250 in .text");
        assert_eq!(entry.range, ByteRange::new(0x98, 0x99));

        let debug = find_block(&text.children, "Debug directory");
        assert_eq!(debug.range, ByteRange::new(0x108, 0x124));
        let entry = find_block(&debug.children, "Debug entry: CODEVIEW (a.pdb)");
        find_block(&entry.children, "Type: CODEVIEW");

        let cv = find_block(&text.children, "CodeView record (RSDS)");
        assert_eq!(cv.range, ByteRange::new(0x128, 0x146));
        find_block(&cv.children, "GUID: 00000000-0000-0000-0000-000000000000");
        find_block(&cv.children, "Age: 1");
        let path = find_block(&cv.children, "PDB path: a.pdb");
        assert_eq!(path.range, ByteRange::new(0x140, 0x146));

        let reloc_section = find_block(&blocks, "Section data: .reloc");
        assert_eq!(reloc_section.range, ByteRange::new(0x188, 0x1A8));
        let relocs = find_block(&reloc_section.children, "Base relocations (1 blocks)");
        assert_eq!(relocs.range, ByteRange::new(0x188, 0x194));
        let block = find_block(
            &relocs.children,
            "Relocation block: page 0x1000 (2 entries)",
        );
        find_block(&block.children, "Page RVA: 0x1000");
        find_block(&block.children, "Block size: 12");
        assert_eq!(
            find_block(&block.children, "DIR64 at 0x1010").range,
            ByteRange::new(0x190, 0x192)
        );
        find_block(&block.children, "ABSOLUTE at 0x1000");
    }

    #[test]
    fn relocation_entries_are_capped() {
        let mut data = build_te();
        let count = 100usize;
        let block_size = 8 + count * 2;
        put_u32(&mut data, 28, block_size as u32);
        put_u32(&mut data, 80 + 8, block_size as u32);
        put_u32(&mut data, 80 + 16, block_size as u32);
        put_u32(&mut data, 0x188 + 4, block_size as u32);
        for i in 0..count {
            put_u16(&mut data, 0x188 + 8 + i * 2, 0x3000 | i as u16);
        }
        let blocks = TeDissector.dissect(&data);
        let section = find_block(&blocks, "Section data: .reloc");
        let relocs = find_block(&section.children, "Base relocations (1 blocks)");
        let block = &relocs.children[0];
        assert_eq!(block.children.len(), 2 + MAX_RELOC_ENTRIES_PER_BLOCK + 1);
        let more = find_block(&block.children, "... 36 more entries");
        assert_eq!(more.range.end, (0x188 + block_size) as u64);
        find_block(&block.children, "HIGHLOW at 0x1001");
    }

    #[test]
    fn identify_reports_te() {
        assert_eq!(super::super::identify(&build_te()), "TE");
    }
}
