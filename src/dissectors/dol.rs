//! Nintendo GameCube / Wii DOL executable ("Dolphin" format).
//!
//! The file starts with a fixed 0x100-byte big-endian header describing up
//! to 7 text and 11 data sections plus a BSS range and the entry point. There
//! is no magic number, so `matches` is a strict structural heuristic.

use super::{Block, ByteRange, Dissector};

const HEADER_LEN: usize = 0x100;
const TEXT_COUNT: usize = 7;
const DATA_COUNT: usize = 11;
const SECTION_COUNT: usize = TEXT_COUNT + DATA_COUNT;

const OFFSETS_AT: usize = 0x00;
const ADDRESSES_AT: usize = 0x48;
const SIZES_AT: usize = 0x90;
const BSS_ADDR_AT: usize = 0xD8;
const BSS_SIZE_AT: usize = 0xDC;
const ENTRY_AT: usize = 0xE0;
const PADDING_AT: usize = 0xE4;

/// Memory regions a section may be loaded into (half-open, cached mirrors):
/// GameCube/Wii MEM1 (24 MiB) and Wii MEM2 (64 MiB).
const LOAD_REGIONS: [(u64, u64); 2] = [(0x8000_0000, 0x8180_0000), (0x9000_0000, 0x9400_0000)];

/// Required alignment of section offsets, load addresses and sizes. PowerPC
/// code needs 4-byte alignment; real files are usually 32-byte aligned, but
/// not every homebrew toolchain pads sizes that far.
const ALIGN: u32 = 4;

pub struct DolDissector;

#[derive(Clone, Copy)]
struct Section {
    /// Index into the 18 header slots (0..7 text, 7..18 data).
    slot: usize,
    offset: u32,
    address: u32,
    size: u32,
}

impl Section {
    fn is_text(&self) -> bool {
        self.slot < TEXT_COUNT
    }

    fn name(&self) -> String {
        if self.is_text() {
            format!("Text {}", self.slot)
        } else {
            format!("Data {}", self.slot - TEXT_COUNT)
        }
    }

    fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn contains_address(&self, addr: u32) -> bool {
        let addr = addr as u64;
        addr >= self.address as u64 && addr < self.address as u64 + self.size as u64
    }
}

struct Header {
    sections: [Section; SECTION_COUNT],
    bss_address: u32,
    bss_size: u32,
    entry: u32,
}

impl Dissector for DolDissector {
    fn name(&self) -> &'static str {
        "DOL"
    }

    fn matches(&self, data: &[u8]) -> bool {
        parse_header(data).is_some_and(|h| is_plausible(&h, data))
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let Some(header) = parse_header(data) else {
            return Vec::new();
        };
        let mut blocks = vec![header_block(&header)];

        let mut present: Vec<Section> = header
            .sections
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();
        present.sort_by_key(|s| (s.offset, s.slot));

        let len = data.len();
        let mut cursor = HEADER_LEN;
        for section in &present {
            let start = (section.offset as usize).min(len);
            let end = (section.offset as u64 + section.size as u64).min(len as u64) as usize;
            if start > cursor {
                blocks.push(gap_block("Gap", cursor, start));
            }
            let truncated = if end - start < section.size as usize {
                ", truncated"
            } else {
                ""
            };
            blocks.push(Block::leaf(
                format!(
                    "{} (load 0x{:08X}, 0x{:X} bytes{truncated})",
                    section.name(),
                    section.address,
                    section.size
                ),
                span(start, end),
            ));
            cursor = cursor.max(end);
        }
        if cursor < len {
            blocks.push(gap_block("Trailing data", cursor, len));
        }

        blocks
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn parse_header(data: &[u8]) -> Option<Header> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let mut sections = [Section {
        slot: 0,
        offset: 0,
        address: 0,
        size: 0,
    }; SECTION_COUNT];
    for (slot, section) in sections.iter_mut().enumerate() {
        *section = Section {
            slot,
            offset: read_u32_be(data, OFFSETS_AT + 4 * slot)?,
            address: read_u32_be(data, ADDRESSES_AT + 4 * slot)?,
            size: read_u32_be(data, SIZES_AT + 4 * slot)?,
        };
    }
    Some(Header {
        sections,
        bss_address: read_u32_be(data, BSS_ADDR_AT)?,
        bss_size: read_u32_be(data, BSS_SIZE_AT)?,
        entry: read_u32_be(data, ENTRY_AT)?,
    })
}

fn in_load_region(address: u32, size: u32) -> bool {
    let start = address as u64;
    let end = start + size as u64;
    LOAD_REGIONS
        .iter()
        .any(|&(lo, hi)| start >= lo && end <= hi)
}

fn is_plausible(header: &Header, data: &[u8]) -> bool {
    let len = data.len() as u64;

    if data[PADDING_AT..HEADER_LEN].iter().any(|&b| b != 0) {
        return false;
    }

    let present: Vec<&Section> = header.sections.iter().filter(|s| !s.is_empty()).collect();
    if !present.iter().any(|s| s.is_text()) {
        return false;
    }

    for s in &present {
        let end = s.offset as u64 + s.size as u64;
        if (s.offset as usize) < HEADER_LEN
            || end > len
            || s.offset % ALIGN != 0
            || s.size % ALIGN != 0
            || s.address % ALIGN != 0
            || !in_load_region(s.address, s.size)
        {
            return false;
        }
    }

    // No two sections may share file bytes.
    let mut ranges: Vec<(u64, u64)> = present
        .iter()
        .map(|s| (s.offset as u64, s.offset as u64 + s.size as u64))
        .collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[1].0 < w[0].1) {
        return false;
    }

    if header.bss_size != 0 && !in_load_region(header.bss_address, header.bss_size) {
        return false;
    }

    present
        .iter()
        .any(|s| s.is_text() && s.contains_address(header.entry))
}

fn header_block(header: &Header) -> Block {
    let mut children = Vec::new();
    for section in &header.sections {
        children.push(section_entry_block(section));
    }

    children.push(Block::leaf(
        format!("BSS address: 0x{:08X}", header.bss_address),
        span(BSS_ADDR_AT, BSS_ADDR_AT + 4),
    ));
    children.push(Block::leaf(
        format!("BSS size: 0x{:X} bytes", header.bss_size),
        span(BSS_SIZE_AT, BSS_SIZE_AT + 4),
    ));

    let containing = header
        .sections
        .iter()
        .find(|s| s.is_text() && !s.is_empty() && s.contains_address(header.entry))
        .map(|s| format!("in {}", s.name()))
        .unwrap_or_else(|| "not in any text section".to_string());
    children.push(Block::leaf(
        format!("Entry point: 0x{:08X} ({containing})", header.entry),
        span(ENTRY_AT, ENTRY_AT + 4),
    ));
    children.push(Block::leaf(
        format!("Padding ({} bytes)", HEADER_LEN - PADDING_AT),
        span(PADDING_AT, HEADER_LEN),
    ));

    Block::node("DOL header", span(0, HEADER_LEN), children).expanded()
}

/// One node per header slot. The slot's three fields live in separate tables,
/// so the node spans from its offset field to its size field and the leaves
/// carry the exact ranges.
fn section_entry_block(section: &Section) -> Block {
    let offset_at = OFFSETS_AT + 4 * section.slot;
    let address_at = ADDRESSES_AT + 4 * section.slot;
    let size_at = SIZES_AT + 4 * section.slot;
    let label = if section.is_empty() {
        format!("{}: unused", section.name())
    } else {
        format!(
            "{}: offset 0x{:X}, load 0x{:08X}, 0x{:X} bytes",
            section.name(),
            section.offset,
            section.address,
            section.size
        )
    };
    Block::node(
        label,
        span(offset_at, size_at + 4),
        vec![
            Block::leaf(
                format!("File offset: 0x{:X}", section.offset),
                span(offset_at, offset_at + 4),
            ),
            Block::leaf(
                format!("Load address: 0x{:08X}", section.address),
                span(address_at, address_at + 4),
            ),
            Block::leaf(
                format!("Size: 0x{:X} bytes", section.size),
                span(size_at, size_at + 4),
            ),
        ],
    )
}

fn gap_block(what: &str, start: usize, end: usize) -> Block {
    Block::leaf(format!("{what} ({} bytes)", end - start), span(start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (slot, offset, address, size)
    type Entry = (usize, u32, u32, u32);

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn build_dol(entries: &[Entry], bss: (u32, u32), entry: u32, file_len: usize) -> Vec<u8> {
        let mut data = vec![0u8; file_len];
        for &(slot, offset, address, size) in entries {
            put_u32(&mut data, OFFSETS_AT + 4 * slot, offset);
            put_u32(&mut data, ADDRESSES_AT + 4 * slot, address);
            put_u32(&mut data, SIZES_AT + 4 * slot, size);
            for (i, b) in data[offset as usize..(offset + size) as usize]
                .iter_mut()
                .enumerate()
            {
                *b = (i as u8) | 1;
            }
        }
        put_u32(&mut data, BSS_ADDR_AT, bss.0);
        put_u32(&mut data, BSS_SIZE_AT, bss.1);
        put_u32(&mut data, ENTRY_AT, entry);
        data
    }

    /// Text 0 at 0x100, Data 0 at 0x200, a gap, Text 1 at 0x300, trailing.
    fn sample() -> Vec<u8> {
        build_dol(
            &[
                (0, 0x100, 0x8000_3100, 0x100),
                (TEXT_COUNT, 0x200, 0x8000_5000, 0x80),
                (1, 0x300, 0x8000_3200, 0x40),
            ],
            (0x8000_6000, 0x200),
            0x8000_3210,
            0x360,
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
    fn matches_built_dol() {
        assert!(DolDissector.matches(&sample()));
    }

    #[test]
    fn matches_wii_mem2_section() {
        let data = build_dol(&[(0, 0x100, 0x9000_0000, 0x20)], (0, 0), 0x9000_0000, 0x120);
        assert!(DolDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_dol_data() {
        assert!(!DolDissector.matches(b""));
        assert!(!DolDissector.matches(b"not a dol file"));
        assert!(!DolDissector.matches(&[0u8; 0x200]));
        assert!(!DolDissector.matches(&[0xFFu8; 0x200]));
        let truncated = sample();
        assert!(!DolDissector.matches(&truncated[..0xFF]));
        // Section data cut off.
        assert!(!DolDissector.matches(&truncated[..0x320]));
    }

    #[test]
    fn rejects_structural_violations() {
        let base = |entries: &[Entry], bss: (u32, u32), entry: u32| {
            DolDissector.matches(&build_dol(entries, bss, entry, 0x400))
        };
        let text = (0, 0x100, 0x8000_3100, 0x100);
        assert!(base(&[text], (0, 0), 0x8000_3100));
        // Entry outside text.
        assert!(!base(&[text], (0, 0), 0x8000_3200));
        // Entry in a data section only.
        assert!(!base(
            &[text, (TEXT_COUNT, 0x200, 0x8000_5000, 0x20)],
            (0, 0),
            0x8000_5000
        ));
        // No text section at all.
        assert!(!base(
            &[(TEXT_COUNT, 0x100, 0x8000_5000, 0x20)],
            (0, 0),
            0x8000_5000
        ));
        // Offset inside the header.
        assert!(!base(&[(0, 0xF0, 0x8000_3100, 0x20)], (0, 0), 0x8000_3100));
        // Misaligned size.
        assert!(!base(&[(0, 0x100, 0x8000_3100, 0x22)], (0, 0), 0x8000_3100));
        // Load address outside RAM.
        assert!(!base(&[(0, 0x100, 0x0000_3100, 0x20)], (0, 0), 0x0000_3100));
        assert!(!base(&[(0, 0x100, 0x817F_FFF0, 0x20)], (0, 0), 0x817F_FFF0));
        // Overlapping sections in the file.
        assert!(!base(
            &[text, (1, 0x180, 0x8000_4000, 0x100)],
            (0, 0),
            0x8000_3100
        ));
        // BSS outside RAM.
        assert!(!base(&[text], (0x1000, 0x20), 0x8000_3100));
        // Non-zero padding.
        let mut data = build_dol(&[text], (0, 0), 0x8000_3100, 0x400);
        data[0xF0] = 1;
        assert!(!DolDissector.matches(&data));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        assert!(DolDissector.dissect(&sample()[..0x80]).is_empty());
    }

    #[test]
    fn dissect_truncated_sections_does_not_panic() {
        let data = sample();
        let blocks = DolDissector.dissect(&data[..0x220]);
        let data0 = find_block(&blocks, "Data 0 (load 0x80005000, 0x80 bytes, truncated)");
        assert_eq!(data0.range, ByteRange::new(0x200, 0x220));
        assert!(blocks.len() < DolDissector.dissect(&data).len());
    }

    #[test]
    fn dissect_parses_header_fields() {
        let blocks = DolDissector.dissect(&sample());
        let header = find_block(&blocks, "DOL header");
        assert_eq!(header.range, ByteRange::new(0, 0x100));
        assert_eq!(header.children.len(), SECTION_COUNT + 4);

        let text0 = find_block(
            &header.children,
            "Text 0: offset 0x100, load 0x80003100, 0x100 bytes",
        );
        assert_eq!(text0.range, ByteRange::new(0x00, 0x94));
        assert_eq!(
            find_block(&text0.children, "File offset: 0x100").range,
            ByteRange::new(0x00, 0x04)
        );
        assert_eq!(
            find_block(&text0.children, "Load address: 0x80003100").range,
            ByteRange::new(0x48, 0x4C)
        );
        assert_eq!(
            find_block(&text0.children, "Size: 0x100 bytes").range,
            ByteRange::new(0x90, 0x94)
        );

        let data0 = find_block(
            &header.children,
            "Data 0: offset 0x200, load 0x80005000, 0x80 bytes",
        );
        assert_eq!(data0.range, ByteRange::new(0x1C, 0xB0));
        find_block(&header.children, "Text 2: unused");
        find_block(&header.children, "Data 10: unused");

        assert_eq!(
            find_block(&header.children, "BSS address: 0x80006000").range,
            ByteRange::new(0xD8, 0xDC)
        );
        assert_eq!(
            find_block(&header.children, "BSS size: 0x200 bytes").range,
            ByteRange::new(0xDC, 0xE0)
        );
        assert_eq!(
            find_block(&header.children, "Entry point: 0x80003210 (in Text 1)").range,
            ByteRange::new(0xE0, 0xE4)
        );
        assert_eq!(
            find_block(&header.children, "Padding (28 bytes)").range,
            ByteRange::new(0xE4, 0x100)
        );
    }

    #[test]
    fn dissect_lists_sections_in_file_order() {
        let blocks = DolDissector.dissect(&sample());
        let labels: Vec<&str> = blocks.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "DOL header",
                "Text 0 (load 0x80003100, 0x100 bytes)",
                "Data 0 (load 0x80005000, 0x80 bytes)",
                "Gap (128 bytes)",
                "Text 1 (load 0x80003200, 0x40 bytes)",
                "Trailing data (32 bytes)",
            ]
        );
        assert_eq!(blocks[1].range, ByteRange::new(0x100, 0x200));
        assert_eq!(blocks[2].range, ByteRange::new(0x200, 0x280));
        assert_eq!(blocks[3].range, ByteRange::new(0x280, 0x300));
        assert_eq!(blocks[4].range, ByteRange::new(0x300, 0x340));
        assert_eq!(blocks[5].range, ByteRange::new(0x340, 0x360));
    }

    #[test]
    fn does_not_claim_ico_or_cur() {
        // DOL sits before ICO in the match order because both usually start
        // with 00 00 01 00, so real icons must still be identified as ICO.
        for kind in [1u8, 2] {
            let mut data = vec![0, 0, kind, 0, 1, 0];
            // ICONDIRENTRY: 16x16, 0 colors, planes/hotspot, 32 bpp, size, offset.
            data.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
            data.extend_from_slice(&0x468u32.to_le_bytes());
            data.extend_from_slice(&22u32.to_le_bytes());
            data.extend_from_slice(&40u32.to_le_bytes());
            data.extend_from_slice(&16i32.to_le_bytes());
            data.extend_from_slice(&32i32.to_le_bytes());
            data.resize(22 + 0x468, 0);
            assert!(!DolDissector.matches(&data));
            assert_eq!(super::super::identify(&data), "ICO");
        }
    }

    #[test]
    fn identify_reports_dol() {
        assert_eq!(super::super::identify(&sample()), "DOL");
    }

    #[test]
    fn does_not_claim_other_formats() {
        let magics: &[&[u8]] = &[
            b"\x7fELF\x02\x01\x01",
            b"MZ\x90\x00",
            b"\xcf\xfa\xed\xfe",
            b"\x89PNG\r\n\x1a\n",
            b"BM",
            b"GIF89a",
            b"\xff\xd8\xff\xe0",
            b"PK\x03\x04",
            b"\x1f\x8b\x08",
            b"%PDF-1.7\n",
            b"MThd\x00\x00\x00\x06",
            b"Rar!\x1a\x07\x01\x00",
            b"7z\xbc\xaf\x27\x1c",
            b"\xfd7zXZ\x00",
            b"BZh91AY&SY",
            b"RIFF\x00\x00\x00\x00WAVE",
            b"OggS",
            b"fLaC",
            b"\x00asm\x01\x00\x00\x00",
            b"dex\n035\x00",
            b"\xca\xfe\xba\xbe",
            b"SQLite format 3\x00",
            b"\x00\x00\x01\x00\x01\x00",
            b"ID3\x04\x00",
        ];
        for magic in magics {
            let mut data = magic.to_vec();
            data.resize(0x200, 0);
            assert!(!DolDissector.matches(&data), "DOL matched {magic:?}");
            assert_ne!(super::super::identify(&data), "DOL", "{magic:?}");
        }
    }
}
