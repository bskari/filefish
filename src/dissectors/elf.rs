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
                blocks.push(program_headers_block(phoff, phentsize, phnum));
            }
            if let Some((shoff, shentsize, shnum)) =
                section_header_info(data, is_64_bit, little_endian)
            {
                blocks.push(section_headers_block(shoff, shentsize, shnum));
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

fn program_headers_block(offset: u64, entry_size: u64, count: u64) -> Block {
    let entries = (0..count)
        .map(|i| {
            let start = offset + i * entry_size;
            Block::leaf(format!("Program header {i}"), ByteRange::new(start, start + entry_size))
        })
        .collect();
    Block::node_collapsed(
        "Program headers",
        ByteRange::new(offset, offset + entry_size * count),
        entries,
    )
}

fn section_headers_block(offset: u64, entry_size: u64, count: u64) -> Block {
    let entries = (0..count)
        .map(|i| {
            let start = offset + i * entry_size;
            Block::leaf(format!("Section header {i}"), ByteRange::new(start, start + entry_size))
        })
        .collect();
    Block::node_collapsed(
        "Section headers",
        ByteRange::new(offset, offset + entry_size * count),
        entries,
    )
}
