use super::{Block, ByteRange, Dissector};

const ELF_MAGIC: &[u8] = b"\x7fELF";

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;
const EI_OSABI: usize = 7;
const EI_NIDENT: usize = 16;

pub struct ElfDissector;

impl Dissector for ElfDissector {
    fn name(&self) -> &'static str {
        "ELF"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(ELF_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < EI_NIDENT {
            return blocks;
        }
        blocks.push(identification_block(data));

        let is_64_bit = data[EI_CLASS] == 2;
        let little_endian = data[EI_DATA] != 2;

        if let Some(header) = header_block(data, is_64_bit, little_endian) {
            blocks.push(header);

            if let Some((phoff, phentsize, phnum)) =
                program_header_info(data, is_64_bit, little_endian)
            {
                blocks.push(program_headers_block(data, phoff, phentsize, phnum, is_64_bit, little_endian));
            }
            if let Some((shoff, shentsize, shnum)) =
                section_header_info(data, is_64_bit, little_endian)
            {
                blocks.push(section_headers_block(data, shoff, shentsize, shnum, is_64_bit, little_endian));
            }
        }

        blocks
    }
}

fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn class_name(byte: u8) -> &'static str {
    match byte {
        1 => "32-bit",
        2 => "64-bit",
        _ => "unknown",
    }
}

fn endianness_name(byte: u8) -> &'static str {
    match byte {
        1 => "little",
        2 => "big",
        _ => "unknown",
    }
}

fn osabi_name(byte: u8) -> &'static str {
    match byte {
        0 => "Unix - System V",
        3 => "Linux",
        6 => "Solaris",
        _ => "unknown",
    }
}

fn type_name(value: u16) -> &'static str {
    match value {
        1 => "relocatable",
        2 => "executable",
        3 => "shared object",
        4 => "core",
        _ => "unknown",
    }
}

fn machine_name(value: u16) -> &'static str {
    match value {
        0x03 => "x86",
        0x28 => "ARM",
        0x3E => "x86_64",
        0xB7 => "AArch64",
        _ => "unknown",
    }
}

fn identification_block(data: &[u8]) -> Block {
    Block::node(
        "Identification",
        ByteRange::new(0, EI_NIDENT as u64),
        vec![
            Block::leaf("Magic number: ELF", ByteRange::new(0, 4)),
            Block::leaf(
                format!("Class: {}", class_name(data[EI_CLASS])),
                ByteRange::new(EI_CLASS as u64, EI_CLASS as u64 + 1),
            ),
            Block::leaf(
                format!("Endianness: {}", endianness_name(data[EI_DATA])),
                ByteRange::new(EI_DATA as u64, EI_DATA as u64 + 1),
            ),
            Block::leaf(
                format!("Version: {}", data[EI_VERSION]),
                ByteRange::new(EI_VERSION as u64, EI_VERSION as u64 + 1),
            ),
            Block::leaf(
                format!("OS/ABI: {}", osabi_name(data[EI_OSABI])),
                ByteRange::new(EI_OSABI as u64, EI_OSABI as u64 + 1),
            ),
            Block::leaf("Padding", ByteRange::new(8, EI_NIDENT as u64)),
        ],
    )
}

fn header_block(data: &[u8], is_64_bit: bool, little_endian: bool) -> Option<Block> {
    let e_type = read_u16(data, 16, little_endian)?;
    let e_machine = read_u16(data, 18, little_endian)?;
    let e_version = read_u32(data, 20, little_endian)?;

    let mut fields = vec![
        Block::leaf(
            format!("Type: {}", type_name(e_type)),
            ByteRange::new(16, 18),
        ),
        Block::leaf(
            format!("Machine: {}", machine_name(e_machine)),
            ByteRange::new(18, 20),
        ),
        Block::leaf(
            format!("Version: {}", if e_version == 1 { "current".to_string() } else { e_version.to_string() }),
            ByteRange::new(20, 24),
        ),
    ];

    let end = if is_64_bit {
        let e_entry = read_u64(data, 24, little_endian)?;
        let e_phoff = read_u64(data, 32, little_endian)?;
        let e_shoff = read_u64(data, 40, little_endian)?;
        let e_flags = read_u32(data, 48, little_endian)?;
        let e_ehsize = read_u16(data, 52, little_endian)?;
        let e_phentsize = read_u16(data, 54, little_endian)?;
        let e_phnum = read_u16(data, 56, little_endian)?;
        let e_shentsize = read_u16(data, 58, little_endian)?;
        let e_shnum = read_u16(data, 60, little_endian)?;
        let e_shstrndx = read_u16(data, 62, little_endian)?;

        fields.push(Block::leaf(format!("Entry: {e_entry:#x}"), ByteRange::new(24, 32)));
        fields.push(Block::leaf(format!("Program header offset: {e_phoff:#x}"), ByteRange::new(32, 40)));
        fields.push(Block::leaf(format!("Section header offset: {e_shoff:#x}"), ByteRange::new(40, 48)));
        fields.push(Block::leaf(format!("Flags: {e_flags:#x}"), ByteRange::new(48, 52)));
        fields.push(Block::leaf(format!("Header size: {e_ehsize}"), ByteRange::new(52, 54)));
        fields.push(Block::leaf(format!("Program header size: {e_phentsize}"), ByteRange::new(54, 56)));
        fields.push(Block::leaf(format!("Program header count: {e_phnum}"), ByteRange::new(56, 58)));
        fields.push(Block::leaf(format!("Section header size: {e_shentsize}"), ByteRange::new(58, 60)));
        fields.push(Block::leaf(format!("Section header count: {e_shnum}"), ByteRange::new(60, 62)));
        fields.push(Block::leaf(format!("Section header string index: {e_shstrndx}"), ByteRange::new(62, 64)));
        64
    } else {
        let e_entry = read_u32(data, 24, little_endian)?;
        let e_phoff = read_u32(data, 28, little_endian)?;
        let e_shoff = read_u32(data, 32, little_endian)?;
        let e_flags = read_u32(data, 36, little_endian)?;
        let e_ehsize = read_u16(data, 40, little_endian)?;
        let e_phentsize = read_u16(data, 42, little_endian)?;
        let e_phnum = read_u16(data, 44, little_endian)?;
        let e_shentsize = read_u16(data, 46, little_endian)?;
        let e_shnum = read_u16(data, 48, little_endian)?;
        let e_shstrndx = read_u16(data, 50, little_endian)?;

        fields.push(Block::leaf(format!("Entry: {e_entry:#x}"), ByteRange::new(24, 28)));
        fields.push(Block::leaf(format!("Program header offset: {e_phoff:#x}"), ByteRange::new(28, 32)));
        fields.push(Block::leaf(format!("Section header offset: {e_shoff:#x}"), ByteRange::new(32, 36)));
        fields.push(Block::leaf(format!("Flags: {e_flags:#x}"), ByteRange::new(36, 40)));
        fields.push(Block::leaf(format!("Header size: {e_ehsize}"), ByteRange::new(40, 42)));
        fields.push(Block::leaf(format!("Program header size: {e_phentsize}"), ByteRange::new(42, 44)));
        fields.push(Block::leaf(format!("Program header count: {e_phnum}"), ByteRange::new(44, 46)));
        fields.push(Block::leaf(format!("Section header size: {e_shentsize}"), ByteRange::new(46, 48)));
        fields.push(Block::leaf(format!("Section header count: {e_shnum}"), ByteRange::new(48, 50)));
        fields.push(Block::leaf(format!("Section header string index: {e_shstrndx}"), ByteRange::new(50, 52)));
        52
    };

    Some(Block::node(
        format!("Header: {}", class_name(data[EI_CLASS])),
        ByteRange::new(16, end),
        fields,
    ))
}

fn program_header_info(data: &[u8], is_64_bit: bool, little_endian: bool) -> Option<(u64, u64, u64)> {
    if is_64_bit {
        Some((
            read_u64(data, 32, little_endian)?,
            read_u16(data, 54, little_endian)? as u64,
            read_u16(data, 56, little_endian)? as u64,
        ))
    } else {
        Some((
            read_u32(data, 28, little_endian)? as u64,
            read_u16(data, 42, little_endian)? as u64,
            read_u16(data, 44, little_endian)? as u64,
        ))
    }
}

fn section_header_info(data: &[u8], is_64_bit: bool, little_endian: bool) -> Option<(u64, u64, u64)> {
    if is_64_bit {
        Some((
            read_u64(data, 40, little_endian)?,
            read_u16(data, 58, little_endian)? as u64,
            read_u16(data, 60, little_endian)? as u64,
        ))
    } else {
        Some((
            read_u32(data, 32, little_endian)? as u64,
            read_u16(data, 46, little_endian)? as u64,
            read_u16(data, 48, little_endian)? as u64,
        ))
    }
}

fn section_header_string_index(data: &[u8], is_64_bit: bool, little_endian: bool) -> Option<u16> {
    if is_64_bit {
        read_u16(data, 62, little_endian)
    } else {
        read_u16(data, 50, little_endian)
    }
}

fn section_header_offset(data: &[u8], header_offset: u64, is_64_bit: bool, little_endian: bool) -> Option<u64> {
    let off = header_offset as usize;
    if is_64_bit {
        read_u64(data, off + 24, little_endian)
    } else {
        read_u32(data, off + 16, little_endian).map(u64::from)
    }
}

fn read_c_string(data: &[u8], offset: u64) -> Option<String> {
    let start = offset as usize;
    let bytes = data.get(start..)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn section_name(data: &[u8], strtab_offset: Option<u64>, sh_name: u32) -> Option<String> {
    let strtab_offset = strtab_offset?;
    if sh_name == 0 {
        return None;
    }
    read_c_string(data, strtab_offset + sh_name as u64).filter(|s| !s.is_empty())
}

fn program_header_type_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        _ => "unknown",
    }
}

fn program_header_flags_name(value: u32) -> String {
    let mut flags = String::new();
    flags.push(if value & 0x4 != 0 { 'R' } else { ' ' });
    flags.push(if value & 0x2 != 0 { 'W' } else { ' ' });
    flags.push(if value & 0x1 != 0 { 'X' } else { ' ' });
    flags
}

fn section_header_type_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        _ => "unknown",
    }
}

fn program_header_entry_block(data: &[u8], offset: u64, is_64_bit: bool, little_endian: bool, index: u64) -> Option<Block> {
    let off = offset as usize;
    let mut fields = Vec::new();

    let (p_type, entry_size) = if is_64_bit {
        let p_type = read_u32(data, off, little_endian)?;
        let p_flags = read_u32(data, off + 4, little_endian)?;
        let p_offset = read_u64(data, off + 8, little_endian)?;
        let p_vaddr = read_u64(data, off + 16, little_endian)?;
        let p_paddr = read_u64(data, off + 24, little_endian)?;
        let p_filesz = read_u64(data, off + 32, little_endian)?;
        let p_memsz = read_u64(data, off + 40, little_endian)?;
        let p_align = read_u64(data, off + 48, little_endian)?;

        fields.push(Block::leaf(format!("Type: {}", program_header_type_name(p_type)), ByteRange::new(offset, offset + 4)));
        fields.push(Block::leaf(format!("Flags: {}", program_header_flags_name(p_flags)), ByteRange::new(offset + 4, offset + 8)));
        fields.push(Block::leaf(format!("Offset: {p_offset:#x}"), ByteRange::new(offset + 8, offset + 16)));
        fields.push(Block::leaf(format!("Virtual address: {p_vaddr:#x}"), ByteRange::new(offset + 16, offset + 24)));
        fields.push(Block::leaf(format!("Physical address: {p_paddr:#x}"), ByteRange::new(offset + 24, offset + 32)));
        fields.push(Block::leaf(format!("File size: {p_filesz:#x}"), ByteRange::new(offset + 32, offset + 40)));
        fields.push(Block::leaf(format!("Memory size: {p_memsz:#x}"), ByteRange::new(offset + 40, offset + 48)));
        fields.push(Block::leaf(format!("Alignment: {p_align:#x}"), ByteRange::new(offset + 48, offset + 56)));
        (p_type, 56u64)
    } else {
        let p_type = read_u32(data, off, little_endian)?;
        let p_offset = read_u32(data, off + 4, little_endian)?;
        let p_vaddr = read_u32(data, off + 8, little_endian)?;
        let p_paddr = read_u32(data, off + 12, little_endian)?;
        let p_filesz = read_u32(data, off + 16, little_endian)?;
        let p_memsz = read_u32(data, off + 20, little_endian)?;
        let p_flags = read_u32(data, off + 24, little_endian)?;
        let p_align = read_u32(data, off + 28, little_endian)?;

        fields.push(Block::leaf(format!("Type: {}", program_header_type_name(p_type)), ByteRange::new(offset, offset + 4)));
        fields.push(Block::leaf(format!("Offset: {p_offset:#x}"), ByteRange::new(offset + 4, offset + 8)));
        fields.push(Block::leaf(format!("Virtual address: {p_vaddr:#x}"), ByteRange::new(offset + 8, offset + 12)));
        fields.push(Block::leaf(format!("Physical address: {p_paddr:#x}"), ByteRange::new(offset + 12, offset + 16)));
        fields.push(Block::leaf(format!("File size: {p_filesz:#x}"), ByteRange::new(offset + 16, offset + 20)));
        fields.push(Block::leaf(format!("Memory size: {p_memsz:#x}"), ByteRange::new(offset + 20, offset + 24)));
        fields.push(Block::leaf(format!("Flags: {}", program_header_flags_name(p_flags)), ByteRange::new(offset + 24, offset + 28)));
        fields.push(Block::leaf(format!("Alignment: {p_align:#x}"), ByteRange::new(offset + 28, offset + 32)));
        (p_type, 32u64)
    };

    Some(Block::node(
        format!("Program header {index}: {}", program_header_type_name(p_type)),
        ByteRange::new(offset, offset + entry_size),
        fields,
    ))
}

fn section_header_entry_block(
    data: &[u8],
    offset: u64,
    is_64_bit: bool,
    little_endian: bool,
    index: u64,
    strtab_offset: Option<u64>,
) -> Option<Block> {
    let off = offset as usize;
    let mut fields = Vec::new();

    let (sh_type, entry_size, sh_name) = if is_64_bit {
        let sh_name = read_u32(data, off, little_endian)?;
        let sh_type = read_u32(data, off + 4, little_endian)?;
        let sh_flags = read_u64(data, off + 8, little_endian)?;
        let sh_addr = read_u64(data, off + 16, little_endian)?;
        let sh_offset = read_u64(data, off + 24, little_endian)?;
        let sh_size = read_u64(data, off + 32, little_endian)?;
        let sh_link = read_u32(data, off + 40, little_endian)?;
        let sh_info = read_u32(data, off + 44, little_endian)?;
        let sh_addralign = read_u64(data, off + 48, little_endian)?;
        let sh_entsize = read_u64(data, off + 56, little_endian)?;

        fields.push(Block::leaf(
            format!("Name: {} ({sh_name:#x})", section_name(data, strtab_offset, sh_name).unwrap_or_else(|| "(none)".to_string())),
            ByteRange::new(offset, offset + 4),
        ));
        fields.push(Block::leaf(format!("Type: {}", section_header_type_name(sh_type)), ByteRange::new(offset + 4, offset + 8)));
        fields.push(Block::leaf(format!("Flags: {sh_flags:#x}"), ByteRange::new(offset + 8, offset + 16)));
        fields.push(Block::leaf(format!("Address: {sh_addr:#x}"), ByteRange::new(offset + 16, offset + 24)));
        fields.push(Block::leaf(format!("Offset: {sh_offset:#x}"), ByteRange::new(offset + 24, offset + 32)));
        fields.push(Block::leaf(format!("Size: {sh_size:#x}"), ByteRange::new(offset + 32, offset + 40)));
        fields.push(Block::leaf(format!("Link: {sh_link}"), ByteRange::new(offset + 40, offset + 44)));
        fields.push(Block::leaf(format!("Info: {sh_info}"), ByteRange::new(offset + 44, offset + 48)));
        fields.push(Block::leaf(format!("Address alignment: {sh_addralign:#x}"), ByteRange::new(offset + 48, offset + 56)));
        fields.push(Block::leaf(format!("Entry size: {sh_entsize:#x}"), ByteRange::new(offset + 56, offset + 64)));
        (sh_type, 64u64, sh_name)
    } else {
        let sh_name = read_u32(data, off, little_endian)?;
        let sh_type = read_u32(data, off + 4, little_endian)?;
        let sh_flags = read_u32(data, off + 8, little_endian)?;
        let sh_addr = read_u32(data, off + 12, little_endian)?;
        let sh_offset = read_u32(data, off + 16, little_endian)?;
        let sh_size = read_u32(data, off + 20, little_endian)?;
        let sh_link = read_u32(data, off + 24, little_endian)?;
        let sh_info = read_u32(data, off + 28, little_endian)?;
        let sh_addralign = read_u32(data, off + 32, little_endian)?;
        let sh_entsize = read_u32(data, off + 36, little_endian)?;

        fields.push(Block::leaf(
            format!("Name: {} ({sh_name:#x})", section_name(data, strtab_offset, sh_name).unwrap_or_else(|| "(none)".to_string())),
            ByteRange::new(offset, offset + 4),
        ));
        fields.push(Block::leaf(format!("Type: {}", section_header_type_name(sh_type)), ByteRange::new(offset + 4, offset + 8)));
        fields.push(Block::leaf(format!("Flags: {sh_flags:#x}"), ByteRange::new(offset + 8, offset + 12)));
        fields.push(Block::leaf(format!("Address: {sh_addr:#x}"), ByteRange::new(offset + 12, offset + 16)));
        fields.push(Block::leaf(format!("Offset: {sh_offset:#x}"), ByteRange::new(offset + 16, offset + 20)));
        fields.push(Block::leaf(format!("Size: {sh_size:#x}"), ByteRange::new(offset + 20, offset + 24)));
        fields.push(Block::leaf(format!("Link: {sh_link}"), ByteRange::new(offset + 24, offset + 28)));
        fields.push(Block::leaf(format!("Info: {sh_info}"), ByteRange::new(offset + 28, offset + 32)));
        fields.push(Block::leaf(format!("Address alignment: {sh_addralign:#x}"), ByteRange::new(offset + 32, offset + 36)));
        fields.push(Block::leaf(format!("Entry size: {sh_entsize:#x}"), ByteRange::new(offset + 36, offset + 40)));
        (sh_type, 40u64, sh_name)
    };

    let label = match section_name(data, strtab_offset, sh_name) {
        Some(name) => format!("Section header {index}: {name}"),
        None => format!("Section header {index}: {}", section_header_type_name(sh_type)),
    };

    Some(Block::node(label, ByteRange::new(offset, offset + entry_size), fields))
}

fn program_headers_block(data: &[u8], offset: u64, entry_size: u64, count: u64, is_64_bit: bool, little_endian: bool) -> Block {
    let entries = (0..count)
        .filter_map(|i| program_header_entry_block(data, offset + i * entry_size, is_64_bit, little_endian, i))
        .collect();
    Block::node(
        "Program headers",
        ByteRange::new(offset, offset + entry_size * count),
        entries,
    )
}

fn section_headers_block(data: &[u8], offset: u64, entry_size: u64, count: u64, is_64_bit: bool, little_endian: bool) -> Block {
    let strtab_offset = section_header_string_index(data, is_64_bit, little_endian)
        .filter(|&index| (index as u64) < count)
        .and_then(|index| section_header_offset(data, offset + index as u64 * entry_size, is_64_bit, little_endian));

    let entries = (0..count)
        .filter_map(|i| section_header_entry_block(data, offset + i * entry_size, is_64_bit, little_endian, i, strtab_offset))
        .collect();
    Block::node(
        "Section headers",
        ByteRange::new(offset, offset + entry_size * count),
        entries,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
        if buf.len() < offset + bytes.len() {
            buf.resize(offset + bytes.len(), 0);
        }
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u16(buf: &mut Vec<u8>, offset: usize, value: u16, little_endian: bool) {
        let bytes = if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
        push_bytes(buf, offset, &bytes);
    }

    fn put_u32(buf: &mut Vec<u8>, offset: usize, value: u32, little_endian: bool) {
        let bytes = if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
        push_bytes(buf, offset, &bytes);
    }

    fn put_u64(buf: &mut Vec<u8>, offset: usize, value: u64, little_endian: bool) {
        let bytes = if little_endian { value.to_le_bytes() } else { value.to_be_bytes() };
        push_bytes(buf, offset, &bytes);
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label == label)
            .unwrap_or_else(|| panic!("block {label:?} not found; have {:?}", blocks.iter().map(|b| &b.label).collect::<Vec<_>>()))
    }

    // Builds a minimal, syntactically valid ELF64 file (little-endian by
    // default) with one LOAD program header and a section header table
    // containing a null section, ".text", and ".shstrtab".
    fn build_elf64(little_endian: bool) -> Vec<u8> {
        let mut data = vec![0u8; 64]; // EHDR

        data[0..4].copy_from_slice(ELF_MAGIC);
        data[EI_CLASS] = 2; // 64-bit
        data[EI_DATA] = if little_endian { 1 } else { 2 };
        data[EI_VERSION] = 1;
        data[EI_OSABI] = 3; // Linux

        put_u16(&mut data, 16, 2, little_endian); // e_type: executable
        put_u16(&mut data, 18, 0x3E, little_endian); // e_machine: x86_64
        put_u32(&mut data, 20, 1, little_endian); // e_version
        put_u64(&mut data, 24, 0x401000, little_endian); // e_entry
        put_u64(&mut data, 32, 64, little_endian); // e_phoff
        put_u64(&mut data, 40, 120, little_endian); // e_shoff
        put_u32(&mut data, 48, 0, little_endian); // e_flags
        put_u16(&mut data, 52, 64, little_endian); // e_ehsize
        put_u16(&mut data, 54, 56, little_endian); // e_phentsize
        put_u16(&mut data, 56, 1, little_endian); // e_phnum
        put_u16(&mut data, 58, 64, little_endian); // e_shentsize
        put_u16(&mut data, 60, 3, little_endian); // e_shnum
        put_u16(&mut data, 62, 2, little_endian); // e_shstrndx

        // Program header 0 at offset 64: LOAD, R+X
        let ph = 64;
        put_u32(&mut data, ph, 1, little_endian); // p_type: LOAD
        put_u32(&mut data, ph + 4, 0x5, little_endian); // p_flags: R+X
        put_u64(&mut data, ph + 8, 0, little_endian); // p_offset
        put_u64(&mut data, ph + 16, 0x400000, little_endian); // p_vaddr
        put_u64(&mut data, ph + 24, 0x400000, little_endian); // p_paddr
        put_u64(&mut data, ph + 32, 0x1000, little_endian); // p_filesz
        put_u64(&mut data, ph + 40, 0x1000, little_endian); // p_memsz
        put_u64(&mut data, ph + 48, 0x1000, little_endian); // p_align

        // String table content, placed after the section header table.
        let strtab_offset = 120 + 3 * 64;
        let mut strtab = vec![0u8]; // index 0: empty name
        let text_name_offset = strtab.len();
        strtab.extend_from_slice(b".text\0");
        let shstrtab_name_offset = strtab.len();
        strtab.extend_from_slice(b".shstrtab\0");

        // Section header 0: NULL section (all zero).
        let sh0 = 120;

        // Section header 1: ".text"
        let sh1 = 120 + 64;
        put_u32(&mut data, sh1, text_name_offset as u32, little_endian); // sh_name
        put_u32(&mut data, sh1 + 4, 1, little_endian); // sh_type: PROGBITS
        put_u64(&mut data, sh1 + 8, 0x6, little_endian); // sh_flags
        put_u64(&mut data, sh1 + 16, 0x401000, little_endian); // sh_addr
        put_u64(&mut data, sh1 + 24, 0x1000, little_endian); // sh_offset
        put_u64(&mut data, sh1 + 32, 0x10, little_endian); // sh_size
        put_u32(&mut data, sh1 + 40, 0, little_endian); // sh_link
        put_u32(&mut data, sh1 + 44, 0, little_endian); // sh_info
        put_u64(&mut data, sh1 + 48, 16, little_endian); // sh_addralign
        put_u64(&mut data, sh1 + 56, 0, little_endian); // sh_entsize

        // Section header 2: ".shstrtab"
        let sh2 = 120 + 128;
        put_u32(&mut data, sh2, shstrtab_name_offset as u32, little_endian); // sh_name
        put_u32(&mut data, sh2 + 4, 3, little_endian); // sh_type: STRTAB
        put_u64(&mut data, sh2 + 8, 0, little_endian); // sh_flags
        put_u64(&mut data, sh2 + 16, 0, little_endian); // sh_addr
        put_u64(&mut data, sh2 + 24, strtab_offset as u64, little_endian); // sh_offset
        put_u64(&mut data, sh2 + 32, strtab.len() as u64, little_endian); // sh_size
        put_u32(&mut data, sh2 + 40, 0, little_endian); // sh_link
        put_u32(&mut data, sh2 + 44, 0, little_endian); // sh_info
        put_u64(&mut data, sh2 + 48, 1, little_endian); // sh_addralign
        put_u64(&mut data, sh2 + 56, 0, little_endian); // sh_entsize

        let _ = sh0; // null section is intentionally left all-zero

        push_bytes(&mut data, strtab_offset, &strtab);

        data
    }

    #[test]
    fn matches_elf_magic() {
        let data = build_elf64(true);
        assert!(ElfDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_elf_data() {
        assert!(!ElfDissector.matches(b"not an elf file"));
        assert!(!ElfDissector.matches(b""));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_identification() {
        let blocks = ElfDissector.dissect(&[0x7f, b'E', b'L']);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_identifies_class_and_endianness() {
        let data = build_elf64(true);
        let blocks = ElfDissector.dissect(&data);

        let ident = find_block(&blocks, "Identification");
        assert_eq!(ident.children[0].label, "Magic number: ELF");
        assert_eq!(ident.children[0].range.start, 0);
        assert_eq!(ident.children[0].range.end, 4);
        assert_eq!(ident.children[1].label, "Class: 64-bit");
        assert_eq!(ident.children[2].label, "Endianness: little");
        assert_eq!(ident.children[4].label, "OS/ABI: Linux");

        let header = find_block(&blocks, "Header: 64-bit");
        assert!(header.children.iter().any(|b| b.label == "Type: executable"));
        assert!(header.children.iter().any(|b| b.label == "Machine: x86_64"));
    }

    #[test]
    fn dissect_expands_program_headers() {
        let data = build_elf64(true);
        let blocks = ElfDissector.dissect(&data);

        let program_headers = find_block(&blocks, "Program headers");
        assert!(program_headers.expandable);
        assert_eq!(program_headers.children.len(), 1);

        let entry = &program_headers.children[0];
        assert_eq!(entry.label, "Program header 0: LOAD");
        assert_eq!(entry.range, ByteRange::new(64, 64 + 56));
        assert!(entry.children.iter().any(|b| b.label == "Flags: R X"));
    }

    #[test]
    fn dissect_resolves_section_names_from_string_table() {
        let data = build_elf64(true);
        let blocks = ElfDissector.dissect(&data);

        let section_headers = find_block(&blocks, "Section headers");
        assert!(section_headers.expandable);
        assert_eq!(section_headers.children.len(), 3);

        assert_eq!(section_headers.children[0].label, "Section header 0: NULL");
        assert_eq!(section_headers.children[1].label, "Section header 1: .text");
        assert_eq!(section_headers.children[2].label, "Section header 2: .shstrtab");

        let text_name_field = &section_headers.children[1].children[0];
        assert!(text_name_field.label.starts_with("Name: .text"));
    }

    #[test]
    fn dissect_handles_big_endian_32_bit_header_without_program_or_section_headers() {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(ELF_MAGIC);
        data[EI_CLASS] = 1; // 32-bit
        data[EI_DATA] = 2; // big-endian
        data[EI_VERSION] = 1;
        data[EI_OSABI] = 0;

        put_u16(&mut data, 16, 1, false); // e_type: relocatable
        put_u16(&mut data, 18, 0x28, false); // e_machine: ARM
        put_u32(&mut data, 20, 1, false);
        put_u32(&mut data, 24, 0, false); // e_entry
        put_u32(&mut data, 28, 0, false); // e_phoff
        put_u32(&mut data, 32, 0, false); // e_shoff
        put_u32(&mut data, 36, 0, false); // e_flags
        put_u16(&mut data, 40, 52, false); // e_ehsize
        put_u16(&mut data, 42, 0, false); // e_phentsize
        put_u16(&mut data, 44, 0, false); // e_phnum: none
        put_u16(&mut data, 46, 0, false); // e_shentsize
        put_u16(&mut data, 48, 0, false); // e_shnum: none
        put_u16(&mut data, 50, 0, false); // e_shstrndx

        let blocks = ElfDissector.dissect(&data);

        let ident = find_block(&blocks, "Identification");
        assert_eq!(ident.children[1].label, "Class: 32-bit");
        assert_eq!(ident.children[2].label, "Endianness: big");

        let header = find_block(&blocks, "Header: 32-bit");
        assert!(header.children.iter().any(|b| b.label == "Type: relocatable"));
        assert!(header.children.iter().any(|b| b.label == "Machine: ARM"));

        assert!(find_block(&blocks, "Program headers").children.is_empty());
        assert!(find_block(&blocks, "Section headers").children.is_empty());
    }

    #[test]
    fn identify_reports_elf() {
        let data = build_elf64(true);
        assert_eq!(super::super::identify(&data), "ELF");
    }
}
