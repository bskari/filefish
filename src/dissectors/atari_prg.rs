use super::{Block, ByteRange, Dissector};

const PRG_MAGIC: u16 = 0x601A;
const HEADER_LEN: usize = 28;
const DRI_SYMBOL_LEN: usize = 14;
const MAX_SYMBOLS: usize = 256;
const MAX_FIXUPS: usize = 256;
/// First two instructions of the MiNT "a.out in TOS" startup stub
/// (`move.l 26(pc),d4` / `jmp ...`), followed by an a.out exec header.
const MINT_STUB: [u8; 8] = [0x28, 0x3A, 0x00, 0x1A, 0x4E, 0xFB, 0x48, 0xFA];

/// GST extended-name marker: the next 14-byte entry holds more name characters.
const GST_EXTENDED: u16 = 0x0048;

pub struct AtariPrgDissector;

impl Dissector for AtariPrgDissector {
    fn name(&self) -> &'static str {
        "Atari ST program"
    }

    fn matches(&self, data: &[u8]) -> bool {
        let Some(header) = Header::parse(data) else {
            return false;
        };
        header.magic == PRG_MAGIC && header.relocation_start() <= data.len() as u64
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let Some(header) = Header::parse(data) else {
            return blocks;
        };
        blocks.push(header_block(&header));

        let len = data.len() as u64;
        let text_start = HEADER_LEN as u64;
        let data_start = text_start + u64::from(header.text);
        let syms_start = data_start + u64::from(header.data);
        let reloc_start = header.relocation_start();

        if header.text > 0 && text_start < len {
            let mut children = Vec::new();
            if data.get(HEADER_LEN..HEADER_LEN + MINT_STUB.len()) == Some(&MINT_STUB[..]) {
                children.push(Block::leaf(
                    "MiNT a.out startup stub",
                    clamp(text_start, text_start + MINT_STUB.len() as u64, len),
                ));
            }
            let label = format!("Text segment ({} bytes)", header.text);
            let range = clamp(text_start, data_start, len);
            if children.is_empty() {
                blocks.push(Block::leaf(label, range));
            } else {
                blocks.push(Block::node(label, range, children));
            }
        }
        if header.data > 0 && data_start < len {
            blocks.push(Block::leaf(
                format!("Data segment ({} bytes)", header.data),
                clamp(data_start, syms_start, len),
            ));
        }
        if header.symbols > 0 && syms_start < len {
            blocks.push(symbol_table_block(data, &header, syms_start, reloc_start));
        }

        let mut end = reloc_start.min(len);
        if header.absflag == 0 && reloc_start < len {
            let (block, reloc_end) = relocation_block(data, reloc_start as usize);
            blocks.push(block);
            end = reloc_end as u64;
        }
        if end < len {
            blocks.push(Block::leaf(
                format!("Trailing data ({} bytes)", len - end),
                ByteRange::new(end, len),
            ));
        }
        blocks
    }
}

struct Header {
    magic: u16,
    text: u32,
    data: u32,
    bss: u32,
    symbols: u32,
    reserved: u32,
    flags: u32,
    absflag: u16,
}

impl Header {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_LEN {
            return None;
        }
        Some(Self {
            magic: read_u16_be(data, 0)?,
            text: read_u32_be(data, 2)?,
            data: read_u32_be(data, 6)?,
            bss: read_u32_be(data, 10)?,
            symbols: read_u32_be(data, 14)?,
            reserved: read_u32_be(data, 18)?,
            flags: read_u32_be(data, 22)?,
            absflag: read_u16_be(data, 26)?,
        })
    }

    fn relocation_start(&self) -> u64 {
        HEADER_LEN as u64 + u64::from(self.text) + u64::from(self.data) + u64::from(self.symbols)
    }

    fn is_mint(&self, data: &[u8]) -> bool {
        data.get(HEADER_LEN..HEADER_LEN + MINT_STUB.len()) == Some(&MINT_STUB[..])
    }
}

fn header_block(h: &Header) -> Block {
    let flag_range = span(22, 26);
    let protection = match (h.flags >> 4) & 3 {
        0 => "private",
        1 => "global",
        2 => "super",
        _ => "readable",
    };
    let tpa = h.flags >> 28;
    let flag_children = vec![
        Block::leaf(
            format!("Fastload (bit 0): {}", yes_no(h.flags & 1 != 0)),
            flag_range,
        ),
        Block::leaf(
            format!("Load into TT-RAM (bit 1): {}", yes_no(h.flags & 2 != 0)),
            flag_range,
        ),
        Block::leaf(
            format!("Malloc from TT-RAM (bit 2): {}", yes_no(h.flags & 4 != 0)),
            flag_range,
        ),
        Block::leaf(
            format!("Memory protection (bits 4-5): {protection}"),
            flag_range,
        ),
        Block::leaf(
            format!("Shared text (bit 11): {}", yes_no(h.flags & 0x800 != 0)),
            flag_range,
        ),
        Block::leaf(
            format!(
                "TPA size (bits 28-31): {tpa} ({} KB minimum TT-RAM)",
                (tpa + 1) * 128
            ),
            flag_range,
        ),
    ];
    let absflag = if h.absflag == 0 {
        "0 (relocation info present)".to_string()
    } else {
        format!("{} (no relocation info)", h.absflag)
    };
    Block::node(
        "GEMDOS program header",
        span(0, HEADER_LEN),
        vec![
            Block::leaf(format!("Magic: 0x{:04X} (BRA.S +26)", h.magic), span(0, 2)),
            Block::leaf(format!("Text size: {}", h.text), span(2, 6)),
            Block::leaf(format!("Data size: {}", h.data), span(6, 10)),
            Block::leaf(format!("BSS size: {}", h.bss), span(10, 14)),
            Block::leaf(format!("Symbol table size: {}", h.symbols), span(14, 18)),
            Block::leaf(format!("Reserved: 0x{:08X}", h.reserved), span(18, 22)),
            Block::node(
                format!("Program flags: 0x{:08X}", h.flags),
                flag_range,
                flag_children,
            ),
            Block::leaf(format!("Absolute flag: {absflag}"), span(26, 28)),
        ],
    )
    .expanded()
}

fn symbol_table_block(data: &[u8], h: &Header, start: u64, end: u64) -> Block {
    let len = data.len() as u64;
    let range = clamp(start, end, len);
    let size = h.symbols;
    if h.is_mint(data) {
        return Block::leaf(
            format!("Symbol table (MiNT a.out format, {size} bytes)"),
            range,
        );
    }
    if size as usize % DRI_SYMBOL_LEN != 0 {
        return Block::leaf(
            format!("Symbol table (unknown format, {size} bytes)"),
            range,
        );
    }

    let (start, end) = (range.start as usize, range.end as usize);
    let mut children = Vec::new();
    let mut count = 0usize;
    let mut listed_end = start;
    let mut off = start;
    while off + DRI_SYMBOL_LEN <= end {
        let Some(sym_type) = read_u16_be(data, off + 8) else {
            break;
        };
        let value = read_u32_be(data, off + 10).unwrap_or(0);
        let mut name = name_bytes(&data[off..off + 8]);
        let mut entry_end = off + DRI_SYMBOL_LEN;
        let extended = sym_type & GST_EXTENDED == GST_EXTENDED;
        if extended && entry_end + DRI_SYMBOL_LEN <= end {
            name.push_str(&name_bytes(&data[entry_end..entry_end + DRI_SYMBOL_LEN]));
            entry_end += DRI_SYMBOL_LEN;
        }
        count += 1;
        if children.len() < MAX_SYMBOLS {
            let mut fields = vec![
                Block::leaf(format!("Name: {name}"), span(off, off + 8)),
                Block::leaf(
                    format!("Type: 0x{sym_type:04X} ({})", symbol_type_names(sym_type)),
                    span(off + 8, off + 10),
                ),
                Block::leaf(format!("Value: 0x{value:08X}"), span(off + 10, off + 14)),
            ];
            if entry_end > off + DRI_SYMBOL_LEN {
                fields.push(Block::leaf(
                    "GST extended name continuation",
                    span(off + DRI_SYMBOL_LEN, entry_end),
                ));
            }
            children.push(Block::node(
                format!("{name} = 0x{value:08X}"),
                span(off, entry_end),
                fields,
            ));
            listed_end = entry_end;
        }
        off = entry_end;
    }
    if count > children.len() {
        children.push(Block::leaf(
            format!("... {} more symbols", count - children.len()),
            span(listed_end, end),
        ));
    }
    Block::node(
        format!("Symbol table (DRI/GST, {count} symbols)"),
        range,
        children,
    )
}

fn symbol_type_names(t: u16) -> String {
    const NAMES: &[(u16, &str)] = &[
        (0x8000, "defined"),
        (0x4000, "equated"),
        (0x2000, "global"),
        (0x1000, "equated register"),
        (0x0800, "external ref"),
        (0x0400, "data based"),
        (0x0200, "text based"),
        (0x0100, "BSS based"),
    ];
    let mut parts: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| t & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if t & GST_EXTENDED == GST_EXTENDED {
        parts.push("GST extended name");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

/// Returns the relocation table block and the exclusive end offset of the table.
fn relocation_block(data: &[u8], start: usize) -> (Block, usize) {
    let Some(first) = read_u32_be(data, start) else {
        let end = data.len();
        return (
            Block::leaf("Relocation table (truncated)", span(start, end)),
            end,
        );
    };
    if first == 0 {
        let end = start + 4;
        return (
            Block::node(
                "Relocation table (no fixups)",
                span(start, end),
                vec![Block::leaf(
                    "First fixup offset: 0 (none)",
                    span(start, end),
                )],
            ),
            end,
        );
    }

    let mut fixups = vec![Block::leaf(
        format!("Fixup: text+0x{first:08X}"),
        span(start, start + 4),
    )];
    let mut count = 1usize;
    let mut target = u64::from(first);
    let mut pos = start + 4;
    let mut status = "truncated";
    while let Some(&b) = data.get(pos) {
        pos += 1;
        match b {
            0 => {
                status = "";
                break;
            }
            1 => target += 254,
            b if b % 2 == 1 => {
                status = "invalid odd delta";
                break;
            }
            b => {
                target += u64::from(b);
                count += 1;
                if fixups.len() < MAX_FIXUPS {
                    fixups.push(Block::leaf(
                        format!("Fixup: text+0x{target:08X}"),
                        span(pos - 1, pos),
                    ));
                }
            }
        }
    }

    let mut children = vec![Block::leaf(
        format!("First fixup offset: text+0x{first:08X}"),
        span(start, start + 4),
    )];
    if pos > start + 4 {
        children.push(Block::leaf(
            format!("Offset byte stream ({} bytes)", pos - start - 4),
            span(start + 4, pos),
        ));
    }
    let listed = fixups.len();
    let list_label = if count > listed {
        format!("Fixup targets (first {listed} of {count})")
    } else {
        format!("Fixup targets ({count})")
    };
    children.push(Block::node(list_label, span(start, pos), fixups));

    let mut label = format!("Relocation table ({count} fixups)");
    if !status.is_empty() {
        label.push_str(&format!(" [{status}]"));
    }
    (
        Block::node(label, span(start, pos), children).expanded(),
        pos,
    )
}

fn name_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn clamp(start: u64, end: u64, len: u64) -> ByteRange {
    ByteRange::new(start.min(len), end.min(len))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &[u8], sym_type: u16, value: u32) -> Vec<u8> {
        let mut entry = vec![0u8; 8];
        entry[..name.len()].copy_from_slice(name);
        entry.extend_from_slice(&sym_type.to_be_bytes());
        entry.extend_from_slice(&value.to_be_bytes());
        entry
    }

    fn build_prg(
        text: &[u8],
        data_seg: &[u8],
        symbols: &[u8],
        flags: u32,
        reloc: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&PRG_MAGIC.to_be_bytes());
        data.extend_from_slice(&(text.len() as u32).to_be_bytes());
        data.extend_from_slice(&(data_seg.len() as u32).to_be_bytes());
        data.extend_from_slice(&0x100u32.to_be_bytes()); // BSS
        data.extend_from_slice(&(symbols.len() as u32).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&flags.to_be_bytes());
        data.extend_from_slice(&(if reloc.is_some() { 0u16 } else { 1u16 }).to_be_bytes());
        data.extend_from_slice(text);
        data.extend_from_slice(data_seg);
        data.extend_from_slice(symbols);
        if let Some(reloc) = reloc {
            data.extend_from_slice(reloc);
        }
        data
    }

    fn sample() -> Vec<u8> {
        let mut symbols = sym(b"_main", 0xA200, 0x10);
        symbols.extend(sym(b"verylong", 0xA248, 0x20));
        symbols.extend_from_slice(b"symbolname\0\0\0\0");
        // first fixup at text+4, then +254 (no fixup), then +8 => text+0x10A, end
        let reloc = [0, 0, 0, 4, 1, 8, 0];
        build_prg(
            &[0u8; 0x200],
            &[0u8; 16],
            &symbols,
            0x1000_0827,
            Some(&reloc),
        )
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
    fn matches_built_prg() {
        assert!(AtariPrgDissector.matches(&sample()));
    }

    #[test]
    fn rejects_non_prg_and_short_input() {
        assert!(!AtariPrgDissector.matches(b""));
        assert!(!AtariPrgDissector.matches(b"\x60\x1A"));
        assert!(!AtariPrgDissector.matches(b"not an atari program, nope!!"));
        let data = sample();
        assert!(!AtariPrgDissector.matches(&data[..27]));
    }

    #[test]
    fn rejects_sizes_exceeding_file() {
        let mut data = sample();
        data[2..6].copy_from_slice(&0x10000u32.to_be_bytes());
        assert!(!AtariPrgDissector.matches(&data));
        let mut data = sample();
        data[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        data[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        data[14..18].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(!AtariPrgDissector.matches(&data));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        assert!(AtariPrgDissector.dissect(b"\x60\x1A\0\0").is_empty());
        let data = sample();
        let full = AtariPrgDissector.dissect(&data).len();
        for cut in [28, 40, 0x228, 0x240, data.len() - 3] {
            let blocks = AtariPrgDissector.dissect(&data[..cut]);
            assert!(!blocks.is_empty());
            assert!(blocks.len() <= full);
        }
    }

    #[test]
    fn dissect_header_and_segments() {
        let data = sample();
        let blocks = AtariPrgDissector.dissect(&data);
        let header = find_block(&blocks, "GEMDOS program header");
        assert_eq!(header.range, ByteRange::new(0, 28));
        find_block(&header.children, "Magic: 0x601A (BRA.S +26)");
        assert_eq!(
            find_block(&header.children, "Text size: 512").range,
            ByteRange::new(2, 6)
        );
        find_block(&header.children, "BSS size: 256");
        let flags = find_block(&header.children, "Program flags: 0x10000827");
        assert_eq!(flags.range, ByteRange::new(22, 26));
        find_block(&flags.children, "Fastload (bit 0): yes");
        find_block(&flags.children, "Load into TT-RAM (bit 1): yes");
        find_block(&flags.children, "Malloc from TT-RAM (bit 2): yes");
        find_block(&flags.children, "Memory protection (bits 4-5): super");
        find_block(&flags.children, "Shared text (bit 11): yes");
        find_block(
            &flags.children,
            "TPA size (bits 28-31): 1 (256 KB minimum TT-RAM)",
        );
        find_block(
            &header.children,
            "Absolute flag: 0 (relocation info present)",
        );

        assert_eq!(
            find_block(&blocks, "Text segment (512 bytes)").range,
            ByteRange::new(28, 540)
        );
        assert_eq!(
            find_block(&blocks, "Data segment (16 bytes)").range,
            ByteRange::new(540, 556)
        );
    }

    #[test]
    fn dissect_symbols_with_gst_extension() {
        let data = sample();
        let blocks = AtariPrgDissector.dissect(&data);
        let table = find_block(&blocks, "Symbol table (DRI/GST, 2 symbols)");
        assert_eq!(table.range, ByteRange::new(556, 598));
        let main = find_block(&table.children, "_main = 0x00000010");
        assert_eq!(main.range, ByteRange::new(556, 570));
        find_block(&main.children, "Type: 0xA200 (defined, global, text based)");
        let long = find_block(&table.children, "verylongsymbolname = 0x00000020");
        assert_eq!(long.range, ByteRange::new(570, 598));
        assert_eq!(
            find_block(&long.children, "GST extended name continuation").range,
            ByteRange::new(584, 598)
        );
    }

    #[test]
    fn dissect_relocations() {
        let data = sample();
        let blocks = AtariPrgDissector.dissect(&data);
        let reloc = find_block(&blocks, "Relocation table (2 fixups)");
        assert_eq!(reloc.range, ByteRange::new(598, 605));
        assert_eq!(reloc.range.end, data.len() as u64);
        find_block(&reloc.children, "First fixup offset: text+0x00000004");
        let list = find_block(&reloc.children, "Fixup targets (2)");
        find_block(&list.children, "Fixup: text+0x00000004");
        assert_eq!(
            find_block(&list.children, "Fixup: text+0x0000010A").range,
            ByteRange::new(603, 604)
        );
    }

    #[test]
    fn dissect_absolute_and_no_fixups() {
        let data = build_prg(&[0u8; 4], &[], &[], 0, Some(&[0, 0, 0, 0]));
        let blocks = AtariPrgDissector.dissect(&data);
        assert_eq!(
            find_block(&blocks, "Relocation table (no fixups)").range,
            ByteRange::new(32, 36)
        );

        let mut data = build_prg(&[0u8; 4], &[], &[], 0, None);
        data.extend_from_slice(b"xx");
        let blocks = AtariPrgDissector.dissect(&data);
        assert!(!blocks.iter().any(|b| b.label.starts_with("Relocation")));
        assert_eq!(
            find_block(&blocks, "Trailing data (2 bytes)").range,
            ByteRange::new(32, 34)
        );
    }

    #[test]
    fn caps_long_fixup_list() {
        let mut reloc = vec![0, 0, 0, 2];
        reloc.extend(std::iter::repeat_n(2u8, 999));
        reloc.push(0);
        let data = build_prg(&[0u8; 4], &[], &[], 0, Some(&reloc));
        let blocks = AtariPrgDissector.dissect(&data);
        let table = find_block(&blocks, "Relocation table (1000 fixups)");
        let list = find_block(&table.children, "Fixup targets (first 256 of 1000)");
        assert_eq!(list.children.len(), MAX_FIXUPS);
    }

    #[test]
    fn mint_symbol_table_shown_as_range() {
        let mut text = MINT_STUB.to_vec();
        text.extend_from_slice(&[0u8; 8]);
        let data = build_prg(&text, &[], &[0u8; 24], 0, None);
        let blocks = AtariPrgDissector.dissect(&data);
        let table = find_block(&blocks, "Symbol table (MiNT a.out format, 24 bytes)");
        assert_eq!(table.range, ByteRange::new(44, 68));
    }

    #[test]
    fn identify_returns_name() {
        assert_eq!(super::super::identify(&sample()), "Atari ST program");
    }
}
