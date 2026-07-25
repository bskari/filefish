use super::{Block, ByteRange, Dissector};

const MAGIC_32: u32 = 0xFEEDFACE;
const MAGIC_64: u32 = 0xFEEDFACF;

pub struct MachoDissector;

impl Dissector for MachoDissector {
    fn name(&self) -> &'static str {
        "Mach-O"
    }

    fn matches(&self, data: &[u8]) -> bool {
        match read_u32(data, 0) {
            Some(magic) => magic == MAGIC_32 || magic == MAGIC_64,
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        let Some(magic) = read_u32(data, 0) else {
            return blocks;
        };
        let is_64 = magic == MAGIC_64;
        let header_size = if is_64 { 32 } else { 28 };

        if data.len() < header_size {
            return blocks;
        }

        let Some((header, ncmds, sizeofcmds)) = header_block(data, is_64) else {
            return blocks;
        };
        blocks.push(header);

        let mut offset = header_size;
        let cmds_end = header_size + sizeofcmds as usize;
        for _ in 0..ncmds {
            if offset + 8 > data.len() || offset + 8 > cmds_end {
                break;
            }
            match load_command_block(data, offset) {
                Some((block, cmdsize)) => {
                    offset += cmdsize;
                    blocks.push(block);
                }
                None => break,
            }
        }

        blocks
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn cpu_type_name(value: i32) -> String {
    const X86_64: i32 = 0x01000007u32 as i32;
    const ARM64: i32 = 0x0100000Cu32 as i32;
    match value {
        7 => "x86".to_string(),
        X86_64 => "x86_64".to_string(),
        12 => "ARM".to_string(),
        ARM64 => "ARM64".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn file_type_name(value: u32) -> String {
    match value {
        1 => "MH_OBJECT".to_string(),
        2 => "MH_EXECUTE".to_string(),
        6 => "MH_DYLIB".to_string(),
        9 => "MH_DYSYM".to_string(),
        _ => format!("unknown ({value})"),
    }
}

fn header_block(data: &[u8], is_64: bool) -> Option<(Block, u32, u32)> {
    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return None;
    }

    let magic = read_u32(data, 0)?;
    let cputype = read_i32(data, 4)?;
    let cpusubtype = read_i32(data, 8)?;
    let filetype = read_u32(data, 12)?;
    let ncmds = read_u32(data, 16)?;
    let sizeofcmds = read_u32(data, 20)?;
    let flags = read_u32(data, 24)?;

    let mut children = vec![
        Block::leaf(format!("Magic: {magic:#010x}"), ByteRange::new(0, 4)),
        Block::leaf(format!("64-bit: {is_64}"), ByteRange::new(0, 4)),
        Block::leaf(
            format!("CPU type: {}", cpu_type_name(cputype)),
            ByteRange::new(4, 8),
        ),
        Block::leaf(format!("CPU subtype: {cpusubtype}"), ByteRange::new(8, 12)),
        Block::leaf(
            format!("File type: {}", file_type_name(filetype)),
            ByteRange::new(12, 16),
        ),
        Block::leaf(format!("Number of load commands: {ncmds}"), ByteRange::new(16, 20)),
        Block::leaf(
            format!("Size of load commands: {sizeofcmds}"),
            ByteRange::new(20, 24),
        ),
        Block::leaf(format!("Flags: {flags:#010x}"), ByteRange::new(24, 28)),
    ];

    if is_64 {
        let reserved = read_u32(data, 28)?;
        children.push(Block::leaf(
            format!("Reserved: {reserved:#010x}"),
            ByteRange::new(28, 32),
        ));
    }

    let block = Block::node(
        "Mach header",
        ByteRange::new(0, header_size as u64),
        children,
    )
    .expanded();

    Some((block, ncmds, sizeofcmds))
}

fn load_command_name(cmd: u32) -> String {
    match cmd {
        0x1 => "LC_SEGMENT".to_string(),
        0x19 => "LC_SEGMENT_64".to_string(),
        0x2 => "LC_SYMTAB".to_string(),
        0xC => "LC_LOAD_DYLIB".to_string(),
        0xD => "LC_ID_DYLIB".to_string(),
        0xE => "LC_LOAD_DYLINKER".to_string(),
        0x80000028 => "LC_MAIN".to_string(),
        _ => format!("LC_UNKNOWN ({cmd:#010x})"),
    }
}

fn load_command_block(data: &[u8], offset: usize) -> Option<(Block, usize)> {
    if data.len() < offset + 8 {
        return None;
    }

    let cmd = read_u32(data, offset)?;
    let cmdsize = read_u32(data, offset + 4)?;

    if cmdsize < 8 {
        return None;
    }
    let cmdsize = cmdsize as usize;
    if offset.checked_add(cmdsize)? > data.len() {
        return None;
    }

    let name = load_command_name(cmd);

    let mut children = vec![
        Block::leaf(
            format!("Command: {name}"),
            ByteRange::new(offset as u64, offset as u64 + 4),
        ),
        Block::leaf(
            format!("Command size: {cmdsize}"),
            ByteRange::new(offset as u64 + 4, offset as u64 + 8),
        ),
    ];

    let mut label = format!("Load command: {name}");

    if cmd == 0x19 && data.len() >= offset + 24 {
        let name_bytes = &data[offset + 8..offset + 24];
        let seg_name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let seg_name = String::from_utf8_lossy(&name_bytes[..seg_name_end]).to_string();

        children.push(Block::leaf(
            format!("Segment name: {seg_name}"),
            ByteRange::new(offset as u64 + 8, offset as u64 + 24),
        ));

        label = format!("Load command: {name} ({seg_name})");
    }

    let block = Block::node(
        label,
        ByteRange::new(offset as u64, offset as u64 + cmdsize as u64),
        children,
    );

    Some((block, cmdsize))
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

    fn put_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        push_bytes(buf, offset, &value.to_le_bytes());
    }

    fn put_i32(buf: &mut Vec<u8>, offset: usize, value: i32) {
        push_bytes(buf, offset, &value.to_le_bytes());
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label == label)
            .unwrap_or_else(|| {
                panic!(
                    "block {label:?} not found; have {:?}",
                    blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
                )
            })
    }

    // Builds a minimal synthetic 64-bit Mach-O file: header (ARM64,
    // MH_EXECUTE, ncmds=1) followed by one LC_SEGMENT_64 load command
    // named "__TEXT".
    fn build_macho64() -> Vec<u8> {
        let header_size = 32usize;
        let cmdsize = 24usize; // 8 (cmd/cmdsize) + 16 (segname), minimal
        let mut data = vec![0u8; header_size];

        put_u32(&mut data, 0, MAGIC_64);
        put_i32(&mut data, 4, 0x0100000Cu32 as i32); // cputype ARM64
        put_i32(&mut data, 8, 0); // cpusubtype
        put_u32(&mut data, 12, 2); // filetype MH_EXECUTE
        put_u32(&mut data, 16, 1); // ncmds
        put_u32(&mut data, 20, cmdsize as u32); // sizeofcmds
        put_u32(&mut data, 24, 0); // flags
        put_u32(&mut data, 28, 0); // reserved

        let cmd_offset = header_size;
        put_u32(&mut data, cmd_offset, 0x19); // LC_SEGMENT_64
        put_u32(&mut data, cmd_offset + 4, cmdsize as u32);
        push_bytes(&mut data, cmd_offset + 8, b"__TEXT\0\0\0\0\0\0\0\0\0\0");

        data
    }

    #[test]
    fn matches_macho_magic_64() {
        let data = build_macho64();
        assert!(MachoDissector.matches(&data));
    }

    #[test]
    fn matches_macho_magic_32() {
        let mut data = vec![0u8; 28];
        put_u32(&mut data, 0, MAGIC_32);
        assert!(MachoDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_macho_data() {
        assert!(!MachoDissector.matches(b""));
        assert!(!MachoDissector.matches(b"not a macho file"));
        assert!(!MachoDissector.matches(b"\x7fELF"));
        assert!(!MachoDissector.matches(b"MZ\0\0"));
    }

    #[test]
    fn dissect_returns_graceful_result_for_truncated_header() {
        let blocks = MachoDissector.dissect(b"\xCF\xFA\xED\xFE");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_header_and_load_commands() {
        let data = build_macho64();
        let blocks = MachoDissector.dissect(&data);

        let header = find_block(&blocks, "Mach header");
        assert!(header.default_expanded);
        assert!(header.children.iter().any(|b| b.label == "CPU type: ARM64"));
        assert!(header.children.iter().any(|b| b.label == "File type: MH_EXECUTE"));
        assert!(header.children.iter().any(|b| b.label == "64-bit: true"));

        let load_cmd = find_block(&blocks, "Load command: LC_SEGMENT_64 (__TEXT)");
        assert!(load_cmd
            .children
            .iter()
            .any(|b| b.label == "Segment name: __TEXT"));
    }

    #[test]
    fn identify_reports_macho() {
        let data = build_macho64();
        assert_eq!(super::super::identify(&data), "Mach-O");
    }
}
