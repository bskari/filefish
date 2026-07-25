use super::{Block, ByteRange, Dissector};

const DOS_MAGIC: &[u8] = b"MZ";
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const E_LFANEW_OFFSET: usize = 0x3C;

pub struct PeDissector;

impl Dissector for PeDissector {
    fn name(&self) -> &'static str {
        "PE"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if !data.starts_with(DOS_MAGIC) {
            return false;
        }
        match pe_header_offset(data) {
            Some(offset) => data
                .get(offset..offset + 4)
                .map(|sig| sig == PE_SIGNATURE)
                .unwrap_or(false),
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 64 {
            return blocks;
        }
        blocks.push(dos_header_block(data));

        let Some(pe_offset) = pe_header_offset(data) else {
            return blocks;
        };
        if data.get(pe_offset..pe_offset + 4) != Some(PE_SIGNATURE) {
            return blocks;
        }
        blocks.push(Block::leaf(
            "PE signature: PE\\0\\0",
            ByteRange::new(pe_offset as u64, pe_offset as u64 + 4),
        ));

        let coff_offset = pe_offset + 4;
        let Some((coff_block, number_of_sections, size_of_optional_header)) =
            coff_header_block(data, coff_offset)
        else {
            return blocks;
        };
        blocks.push(coff_block);

        let optional_header_offset = coff_offset + 20;
        let optional_header_end = optional_header_offset + size_of_optional_header as usize;
        if size_of_optional_header > 0 {
            if let Some(block) =
                optional_header_block(data, optional_header_offset, size_of_optional_header as usize)
            {
                blocks.push(block);
            }
        }

        let section_table_offset = optional_header_end;
        for i in 0..number_of_sections {
            let offset = section_table_offset + i as usize * 40;
            match section_block(data, offset) {
                Some(block) => blocks.push(block),
                None => break,
            }
        }

        blocks
    }
}

fn pe_header_offset(data: &[u8]) -> Option<usize> {
    let bytes: [u8; 4] = data.get(E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4)?.try_into().ok()?;
    let offset = u32::from_le_bytes(bytes) as usize;
    if offset.checked_add(4)? > data.len() {
        return None;
    }
    Some(offset)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn dos_header_block(data: &[u8]) -> Block {
    let e_lfanew = read_u32(data, E_LFANEW_OFFSET).unwrap_or(0);

    let mut children = vec![Block::leaf("Signature: MZ", ByteRange::new(0, 2))];

    if E_LFANEW_OFFSET > 2 {
        children.push(Block::leaf(
            "DOS stub",
            ByteRange::new(2, E_LFANEW_OFFSET as u64),
        ));
    }

    children.push(Block::leaf(
        format!("PE header offset: {e_lfanew}"),
        ByteRange::new(E_LFANEW_OFFSET as u64, E_LFANEW_OFFSET as u64 + 4),
    ));

    if E_LFANEW_OFFSET + 4 < 64 {
        children.push(Block::leaf(
            "DOS stub (remainder)",
            ByteRange::new(E_LFANEW_OFFSET as u64 + 4, 64),
        ));
    }

    Block::node("DOS header", ByteRange::new(0, 64), children).expanded()
}

fn machine_name(value: u16) -> String {
    match value {
        0x014c => "I386".to_string(),
        0x0200 => "IA64".to_string(),
        0x8664 => "AMD64".to_string(),
        0x01c4 => "ARMNT".to_string(),
        0xAA64 => "ARM64".to_string(),
        _ => format!("unknown ({value:#06x})"),
    }
}

fn coff_header_block(data: &[u8], offset: usize) -> Option<(Block, u16, u16)> {
    if data.len() < offset + 20 {
        return None;
    }

    let machine = read_u16(data, offset)?;
    let number_of_sections = read_u16(data, offset + 2)?;
    let time_date_stamp = read_u32(data, offset + 4)?;
    let pointer_to_symbol_table = read_u32(data, offset + 8)?;
    let number_of_symbols = read_u32(data, offset + 12)?;
    let size_of_optional_header = read_u16(data, offset + 16)?;
    let characteristics = read_u16(data, offset + 18)?;

    let children = vec![
        Block::leaf(
            format!("Machine: {}", machine_name(machine)),
            ByteRange::new(offset as u64, offset as u64 + 2),
        ),
        Block::leaf(
            format!("Number of sections: {number_of_sections}"),
            ByteRange::new(offset as u64 + 2, offset as u64 + 4),
        ),
        Block::leaf(
            format!("Time/date stamp: {time_date_stamp}"),
            ByteRange::new(offset as u64 + 4, offset as u64 + 8),
        ),
        Block::leaf(
            format!("Pointer to symbol table: {pointer_to_symbol_table:#x}"),
            ByteRange::new(offset as u64 + 8, offset as u64 + 12),
        ),
        Block::leaf(
            format!("Number of symbols: {number_of_symbols}"),
            ByteRange::new(offset as u64 + 12, offset as u64 + 16),
        ),
        Block::leaf(
            format!("Size of optional header: {size_of_optional_header}"),
            ByteRange::new(offset as u64 + 16, offset as u64 + 18),
        ),
        Block::leaf(
            format!("Characteristics: {characteristics:#06x}"),
            ByteRange::new(offset as u64 + 18, offset as u64 + 20),
        ),
    ];

    let block = Block::node(
        "COFF file header",
        ByteRange::new(offset as u64, offset as u64 + 20),
        children,
    )
    .expanded();

    Some((block, number_of_sections, size_of_optional_header))
}

fn optional_header_block(data: &[u8], offset: usize, size: usize) -> Option<Block> {
    if data.len() < offset {
        return None;
    }
    let available = data.len().saturating_sub(offset).min(size);
    if available == 0 {
        return None;
    }
    let end = offset + available;

    let mut children = Vec::new();

    if available >= 2 {
        let magic = read_u16(data, offset)?;
        let magic_label = match magic {
            0x10b => "PE32".to_string(),
            0x20b => "PE32+ (64-bit)".to_string(),
            _ => format!("unknown ({magic:#06x})"),
        };
        children.push(Block::leaf(
            format!("Magic: {magic_label}"),
            ByteRange::new(offset as u64, offset as u64 + 2),
        ));

        if end as u64 > offset as u64 + 2 {
            children.push(Block::leaf(
                "Optional header data",
                ByteRange::new(offset as u64 + 2, end as u64),
            ));
        }
    } else {
        children.push(Block::leaf(
            "Optional header data",
            ByteRange::new(offset as u64, end as u64),
        ));
    }

    Some(Block::node(
        "Optional header",
        ByteRange::new(offset as u64, end as u64),
        children,
    ))
}

fn section_block(data: &[u8], offset: usize) -> Option<Block> {
    if data.len() < offset + 40 {
        return None;
    }

    let name_bytes = data.get(offset..offset + 8)?;
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    let name = String::from_utf8_lossy(&name_bytes[..name_end]).trim_end().to_string();

    let virtual_size = read_u32(data, offset + 8)?;
    let virtual_address = read_u32(data, offset + 12)?;
    let size_of_raw_data = read_u32(data, offset + 16)?;
    let pointer_to_raw_data = read_u32(data, offset + 20)?;
    let pointer_to_relocations = read_u32(data, offset + 24)?;
    let pointer_to_linenumbers = read_u32(data, offset + 28)?;
    let number_of_relocations = read_u16(data, offset + 32)?;
    let number_of_linenumbers = read_u16(data, offset + 34)?;
    let characteristics = read_u32(data, offset + 36)?;

    let children = vec![
        Block::leaf(
            format!("Name: {name}"),
            ByteRange::new(offset as u64, offset as u64 + 8),
        ),
        Block::leaf(
            format!("Virtual size: {virtual_size:#x}"),
            ByteRange::new(offset as u64 + 8, offset as u64 + 12),
        ),
        Block::leaf(
            format!("Virtual address: {virtual_address:#x}"),
            ByteRange::new(offset as u64 + 12, offset as u64 + 16),
        ),
        Block::leaf(
            format!("Size of raw data: {size_of_raw_data:#x}"),
            ByteRange::new(offset as u64 + 16, offset as u64 + 20),
        ),
        Block::leaf(
            format!("Pointer to raw data: {pointer_to_raw_data:#x}"),
            ByteRange::new(offset as u64 + 20, offset as u64 + 24),
        ),
        Block::leaf(
            format!("Pointer to relocations: {pointer_to_relocations:#x}"),
            ByteRange::new(offset as u64 + 24, offset as u64 + 28),
        ),
        Block::leaf(
            format!("Pointer to line numbers: {pointer_to_linenumbers:#x}"),
            ByteRange::new(offset as u64 + 28, offset as u64 + 32),
        ),
        Block::leaf(
            format!("Number of relocations: {number_of_relocations}"),
            ByteRange::new(offset as u64 + 32, offset as u64 + 34),
        ),
        Block::leaf(
            format!("Number of line numbers: {number_of_linenumbers}"),
            ByteRange::new(offset as u64 + 34, offset as u64 + 36),
        ),
        Block::leaf(
            format!("Characteristics: {characteristics:#010x}"),
            ByteRange::new(offset as u64 + 36, offset as u64 + 40),
        ),
    ];

    Some(Block::node(
        format!("Section: {name}"),
        ByteRange::new(offset as u64, offset as u64 + 40),
        children,
    ))
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

    fn put_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
        push_bytes(buf, offset, &value.to_le_bytes());
    }

    fn put_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        push_bytes(buf, offset, &value.to_le_bytes());
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label == label)
            .unwrap_or_else(|| panic!("block {label:?} not found; have {:?}", blocks.iter().map(|b| &b.label).collect::<Vec<_>>()))
    }

    // Builds a minimal synthetic PE file: DOS header, PE signature, COFF
    // header (AMD64, 1 section, no optional header), and one ".text" section.
    fn build_pe() -> Vec<u8> {
        let pe_offset = 64usize;
        let mut data = vec![0u8; pe_offset];

        data[0..2].copy_from_slice(DOS_MAGIC);
        put_u32(&mut data, E_LFANEW_OFFSET, pe_offset as u32);

        push_bytes(&mut data, pe_offset, PE_SIGNATURE);

        let coff_offset = pe_offset + 4;
        put_u16(&mut data, coff_offset, 0x8664); // Machine: AMD64
        put_u16(&mut data, coff_offset + 2, 1); // NumberOfSections
        put_u32(&mut data, coff_offset + 4, 0); // TimeDateStamp
        put_u32(&mut data, coff_offset + 8, 0); // PointerToSymbolTable
        put_u32(&mut data, coff_offset + 12, 0); // NumberOfSymbols
        put_u16(&mut data, coff_offset + 16, 0); // SizeOfOptionalHeader
        put_u16(&mut data, coff_offset + 18, 0x0002); // Characteristics: EXECUTABLE_IMAGE

        let section_offset = coff_offset + 20;
        push_bytes(&mut data, section_offset, b".text\0\0\0");
        put_u32(&mut data, section_offset + 8, 0x1000); // VirtualSize
        put_u32(&mut data, section_offset + 12, 0x1000); // VirtualAddress
        put_u32(&mut data, section_offset + 16, 0x200); // SizeOfRawData
        put_u32(&mut data, section_offset + 20, 0x400); // PointerToRawData
        put_u32(&mut data, section_offset + 24, 0); // PointerToRelocations
        put_u32(&mut data, section_offset + 28, 0); // PointerToLinenumbers
        put_u16(&mut data, section_offset + 32, 0); // NumberOfRelocations
        put_u16(&mut data, section_offset + 34, 0); // NumberOfLinenumbers
        put_u32(&mut data, section_offset + 36, 0x60000020); // Characteristics

        data
    }

    #[test]
    fn matches_pe_magic() {
        let data = build_pe();
        assert!(PeDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_pe_data() {
        assert!(!PeDissector.matches(b""));
        assert!(!PeDissector.matches(b"not a pe file"));

        // A plain DOS executable: "MZ" signature but no valid PE header at
        // e_lfanew (garbage bytes instead of "PE\0\0").
        let mut dos_only = vec![0u8; 128];
        dos_only[0..2].copy_from_slice(DOS_MAGIC);
        put_u32(&mut dos_only, E_LFANEW_OFFSET, 100);
        push_bytes(&mut dos_only, 100, b"NOPE");
        assert!(!PeDissector.matches(&dos_only));
    }

    #[test]
    fn dissect_returns_graceful_result_for_truncated_header() {
        let blocks = PeDissector.dissect(b"MZ");
        assert!(blocks.is_empty());

        // Full DOS header but e_lfanew points out of bounds.
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(DOS_MAGIC);
        put_u32(&mut data, E_LFANEW_OFFSET, 1000);
        let blocks = PeDissector.dissect(&data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "DOS header");
    }

    #[test]
    fn dissect_parses_headers_and_sections() {
        let data = build_pe();
        let blocks = PeDissector.dissect(&data);

        let dos_header = find_block(&blocks, "DOS header");
        assert!(dos_header.children.iter().any(|b| b.label == "Signature: MZ"));
        assert!(dos_header.children.iter().any(|b| b.label == "PE header offset: 64"));

        let coff = find_block(&blocks, "COFF file header");
        assert!(coff.default_expanded);
        assert!(coff.children.iter().any(|b| b.label == "Machine: AMD64"));
        assert!(coff.children.iter().any(|b| b.label == "Number of sections: 1"));

        let section = find_block(&blocks, "Section: .text");
        assert!(section.children.iter().any(|b| b.label == "Name: .text"));
    }

    #[test]
    fn identify_reports_pe() {
        let data = build_pe();
        assert_eq!(super::super::identify(&data), "PE");
    }
}
