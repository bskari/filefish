use super::{Block, ByteRange, Dissector};

const NRO_MAGIC: &[u8] = b"NRO0";
const NRO_MAGIC_OFFSET: usize = 0x10;
const NRO_HEADER_END: u64 = 0x80;
const MOD0_MAGIC: &[u8] = b"MOD0";
const MOD0_SIZE: u64 = 0x1C;
const ASET_MAGIC: &[u8] = b"ASET";
const ASET_HEADER_SIZE: u64 = 0x38;
const NACP_SIZE: u64 = 0x4000;
const NACP_TITLE_ENTRY_SIZE: u64 = 0x300;
const NACP_NAME_SIZE: u64 = 0x200;
const NACP_PUBLISHER_SIZE: u64 = 0x100;
const NACP_DISPLAY_VERSION_OFFSET: u64 = 0x3060;
const NACP_DISPLAY_VERSION_SIZE: u64 = 0x10;
// NRO images are loaded into memory whole; anything beyond this is not sane.
const MAX_NRO_SIZE: u32 = 0x4000_0000;

pub struct NroDissector;

impl Dissector for NroDissector {
    fn name(&self) -> &'static str {
        "NRO"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.get(NRO_MAGIC_OFFSET..NRO_MAGIC_OFFSET + 4) != Some(NRO_MAGIC) {
            return false;
        }
        match read_u32(data, 0x18) {
            Some(size) => (NRO_HEADER_END as u32..=MAX_NRO_SIZE).contains(&size),
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let data_len = data.len() as u64;

        if data.len() < 0x10 {
            return blocks;
        }
        let mod0_offset = read_u32(data, 4).unwrap_or(0);
        blocks.push(start_header_block(mod0_offset));

        if data_len < NRO_HEADER_END {
            return blocks;
        }
        blocks.push(nro_header_block(data));

        if mod0_offset != 0 {
            if let Some(block) = mod0_block(data, mod0_offset as u64) {
                blocks.push(block);
            }
        }

        let segments = [(".text", 0x20), (".ro", 0x28), (".data", 0x30)];
        for (name, header_off) in segments {
            let offset = read_u32(data, header_off).unwrap_or(0) as u64;
            let size = read_u32(data, header_off + 4).unwrap_or(0) as u64;
            if size == 0 || offset >= data_len {
                continue;
            }
            let range = clamp(offset, size, data_len);
            let label = format!("{name} segment ({size} bytes)");
            if name == ".ro" {
                let children = ro_subsections(data, offset, range);
                if !children.is_empty() {
                    blocks.push(Block::node(label, range, children));
                    continue;
                }
            }
            blocks.push(Block::leaf(label, range));
        }

        let total_size = read_u32(data, 0x18).unwrap_or(0) as u64;
        if let Some(block) = aset_block(data, total_size) {
            blocks.push(block);
        } else if total_size < data_len {
            blocks.push(Block::leaf(
                "Trailing data",
                ByteRange::new(total_size, data_len),
            ));
        }

        blocks
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    read_u32(data, offset).map(|v| v as i32)
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn clamp(start: u64, size: u64, data_len: u64) -> ByteRange {
    let start = start.min(data_len);
    ByteRange::new(start, start.saturating_add(size).min(data_len))
}

/// Reads a NUL-terminated UTF-8 string from a fixed-size field.
fn read_cstr(data: &[u8], offset: u64, max_len: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    let end = usize::try_from(offset.checked_add(max_len)?).ok()?;
    let field = data.get(start..end)?;
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    Some(String::from_utf8_lossy(&field[..len]).into_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn start_header_block(mod0_offset: u32) -> Block {
    Block::node(
        "Start header",
        ByteRange::new(0, 0x10),
        vec![
            Block::leaf("Unused", ByteRange::new(0, 4)),
            Block::leaf(
                format!("MOD0 offset: {mod0_offset:#x}"),
                ByteRange::new(4, 8),
            ),
            Block::leaf("Padding", ByteRange::new(8, 0x10)),
        ],
    )
    .expanded()
}

fn nro_header_block(data: &[u8]) -> Block {
    let u = |off: usize| read_u32(data, off).unwrap_or(0);
    let r = |start: u64, len: u64| ByteRange::new(start, start + len);

    let segment = |name: &str, off: usize| -> Block {
        let o = off as u64;
        Block::node(
            format!("{name} segment header"),
            r(o, 8),
            vec![
                Block::leaf(format!("Memory offset: {:#x}", u(off)), r(o, 4)),
                Block::leaf(format!("Size: {:#x}", u(off + 4)), r(o + 4, 4)),
            ],
        )
    };
    let relative = |name: &str, off: usize| -> Block {
        let o = off as u64;
        Block::node(
            format!("{name} segment header"),
            r(o, 8),
            vec![
                Block::leaf(format!("Offset (from .ro): {:#x}", u(off)), r(o, 4)),
                Block::leaf(format!("Size: {:#x}", u(off + 4)), r(o + 4, 4)),
            ],
        )
    };

    let module_id = data.get(0x40..0x60).map(hex).unwrap_or_default();

    Block::node(
        "NRO header",
        ByteRange::new(0x10, NRO_HEADER_END),
        vec![
            Block::leaf("Magic: NRO0", r(0x10, 4)),
            Block::leaf(format!("Version: {}", u(0x14)), r(0x14, 4)),
            Block::leaf(format!("Total size: {:#x}", u(0x18)), r(0x18, 4)),
            Block::leaf(format!("Flags: {:#x}", u(0x1C)), r(0x1C, 4)),
            segment(".text", 0x20),
            segment(".ro", 0x28),
            segment(".data", 0x30),
            Block::leaf(format!("BSS size: {:#x}", u(0x38)), r(0x38, 4)),
            Block::leaf("Reserved", r(0x3C, 4)),
            Block::leaf(format!("Module ID: {module_id}"), r(0x40, 0x20)),
            Block::leaf(format!("DSO handle offset: {:#x}", u(0x60)), r(0x60, 4)),
            Block::leaf("Reserved", r(0x64, 4)),
            relative(".apiInfo", 0x68),
            relative(".dynstr", 0x70),
            relative(".dynsym", 0x78),
        ],
    )
    .expanded()
}

fn ro_subsections(data: &[u8], ro_offset: u64, ro_range: ByteRange) -> Vec<Block> {
    let mut children = Vec::new();
    for (name, header_off) in [(".apiInfo", 0x68), (".dynstr", 0x70), (".dynsym", 0x78)] {
        let rel = read_u32(data, header_off).unwrap_or(0) as u64;
        let size = read_u32(data, header_off + 4).unwrap_or(0) as u64;
        let start = ro_offset + rel;
        if size == 0 || start < ro_range.start || start >= ro_range.end {
            continue;
        }
        let end = (start + size).min(ro_range.end);
        children.push(Block::leaf(
            format!("{name} ({size} bytes)"),
            ByteRange::new(start, end),
        ));
    }
    children
}

fn mod0_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = usize::try_from(offset).ok()?;
    if data.get(off..off.checked_add(4)?)? != MOD0_MAGIC {
        return None;
    }
    let data_len = data.len() as u64;
    let range = clamp(offset, MOD0_SIZE, data_len);
    let mut children = vec![Block::leaf(
        "Magic: MOD0",
        ByteRange::new(offset, offset + 4),
    )];
    let fields = [
        (4, "Dynamic offset"),
        (8, "BSS start offset"),
        (0xC, "BSS end offset"),
        (0x10, "eh_frame_hdr start offset"),
        (0x14, "eh_frame_hdr end offset"),
        (0x18, "Module object offset"),
    ];
    for (rel, name) in fields {
        let Some(value) = read_i32(data, off + rel) else {
            break;
        };
        let absolute = offset as i64 + value as i64;
        let start = offset + rel as u64;
        children.push(Block::leaf(
            format!(
                "{name}: {}{:#x} (-> {absolute:#x})",
                if value < 0 { "-" } else { "+" },
                value.unsigned_abs()
            ),
            ByteRange::new(start, start + 4),
        ));
    }
    Some(Block::node("MOD0 header", range, children).expanded())
}

fn aset_block(data: &[u8], aset_offset: u64) -> Option<Block> {
    let off = usize::try_from(aset_offset).ok()?;
    if data.get(off..off.checked_add(4)?)? != ASET_MAGIC {
        return None;
    }
    let data_len = data.len() as u64;
    let header_range = clamp(aset_offset, ASET_HEADER_SIZE, data_len);
    let mut header_children = vec![Block::leaf(
        "Magic: ASET",
        ByteRange::new(aset_offset, aset_offset + 4),
    )];
    if let Some(version) = read_u32(data, off + 4) {
        header_children.push(Block::leaf(
            format!("Version: {version}"),
            ByteRange::new(aset_offset + 4, aset_offset + 8),
        ));
    }

    let mut content_blocks = Vec::new();
    for (i, name) in ["Icon", "NACP", "RomFS"].into_iter().enumerate() {
        let entry_off = off + 8 + i * 16;
        let (Some(rel), Some(size)) = (read_u64(data, entry_off), read_u64(data, entry_off + 8))
        else {
            break;
        };
        let entry_start = entry_off as u64;
        header_children.push(Block::node(
            format!("{name} entry"),
            ByteRange::new(entry_start, entry_start + 16),
            vec![
                Block::leaf(
                    format!("Offset: {rel:#x}"),
                    ByteRange::new(entry_start, entry_start + 8),
                ),
                Block::leaf(
                    format!("Size: {size:#x}"),
                    ByteRange::new(entry_start + 8, entry_start + 16),
                ),
            ],
        ));

        let Some(start) = aset_offset.checked_add(rel) else {
            continue;
        };
        if size == 0 || start >= data_len {
            continue;
        }
        let range = clamp(start, size, data_len);
        content_blocks.push(match name {
            "Icon" => Block::leaf(format!("Icon (JPEG, {size} bytes)"), range),
            "NACP" => nacp_block(data, range, size),
            _ => Block::leaf(format!("RomFS ({size} bytes)"), range),
        });
    }

    let mut children = vec![Block::node("ASET header", header_range, header_children).expanded()];
    children.extend(content_blocks);
    let end = children
        .iter()
        .map(|b| b.range.end)
        .max()
        .unwrap_or(header_range.end)
        .max(header_range.end);
    Some(
        Block::node(
            "Asset section (ASET)",
            ByteRange::new(aset_offset, end),
            children,
        )
        .expanded(),
    )
}

fn nacp_block(data: &[u8], range: ByteRange, size: u64) -> Block {
    let label = format!("NACP ({size} bytes)");
    if range.end - range.start < NACP_SIZE {
        return Block::leaf(label, range);
    }
    let base = range.start;
    let name = read_cstr(data, base, NACP_NAME_SIZE).unwrap_or_default();
    let publisher = read_cstr(data, base + NACP_NAME_SIZE, NACP_PUBLISHER_SIZE).unwrap_or_default();
    let version_off = base + NACP_DISPLAY_VERSION_OFFSET;
    let version = read_cstr(data, version_off, NACP_DISPLAY_VERSION_SIZE).unwrap_or_default();
    Block::node(
        label,
        range,
        vec![
            Block::node(
                "Title entry 0",
                ByteRange::new(base, base + NACP_TITLE_ENTRY_SIZE),
                vec![
                    Block::leaf(
                        format!("Name: {name}"),
                        ByteRange::new(base, base + NACP_NAME_SIZE),
                    ),
                    Block::leaf(
                        format!("Publisher: {publisher}"),
                        ByteRange::new(base + NACP_NAME_SIZE, base + NACP_TITLE_ENTRY_SIZE),
                    ),
                ],
            )
            .expanded(),
            Block::leaf(
                format!("Display version: {version}"),
                ByteRange::new(version_off, version_off + NACP_DISPLAY_VERSION_SIZE),
            ),
        ],
    )
    .expanded()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT_SIZE: u32 = 0x100;
    const RO_SIZE: u32 = 0x80;
    const DATA_SIZE: u32 = 0x40;
    const MOD0_OFF: u32 = 0x80;

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn build_nro(with_aset: bool) -> Vec<u8> {
        let total = TEXT_SIZE + RO_SIZE + DATA_SIZE;
        let mut data = vec![0u8; total as usize];
        put_u32(&mut data, 4, MOD0_OFF);
        data[0x10..0x14].copy_from_slice(b"NRO0");
        put_u32(&mut data, 0x18, total);
        put_u32(&mut data, 0x20, 0);
        put_u32(&mut data, 0x24, TEXT_SIZE);
        put_u32(&mut data, 0x28, TEXT_SIZE);
        put_u32(&mut data, 0x2C, RO_SIZE);
        put_u32(&mut data, 0x30, TEXT_SIZE + RO_SIZE);
        put_u32(&mut data, 0x34, DATA_SIZE);
        put_u32(&mut data, 0x38, 0x1000);
        for (i, b) in data[0x40..0x60].iter_mut().enumerate() {
            *b = i as u8;
        }
        // .dynstr at .ro+0x10, 0x20 bytes
        put_u32(&mut data, 0x70, 0x10);
        put_u32(&mut data, 0x74, 0x20);

        // MOD0 at 0x80
        let m = MOD0_OFF as usize;
        data[m..m + 4].copy_from_slice(b"MOD0");
        put_u32(&mut data, m + 4, 0x100); // dynamic
        put_u32(&mut data, m + 8, (-8i32) as u32); // bss start

        if with_aset {
            let aset = data.len();
            let icon = b"\xFF\xD8\xFF\xE0icon";
            let icon_rel = ASET_HEADER_SIZE as usize;
            let nacp_rel = icon_rel + icon.len();
            let romfs_rel = nacp_rel + NACP_SIZE as usize;
            data.resize(aset + romfs_rel + 0x20, 0);
            data[aset..aset + 4].copy_from_slice(b"ASET");
            put_u32(&mut data, aset + 4, 0); // version
            put_u64(&mut data, aset + 8, icon_rel as u64);
            put_u64(&mut data, aset + 0x10, icon.len() as u64);
            put_u64(&mut data, aset + 0x18, nacp_rel as u64);
            put_u64(&mut data, aset + 0x20, NACP_SIZE);
            put_u64(&mut data, aset + 0x28, romfs_rel as u64);
            put_u64(&mut data, aset + 0x30, 0x20);
            data[aset + icon_rel..aset + nacp_rel].copy_from_slice(icon);
            let n = aset + nacp_rel;
            data[n..n + 5].copy_from_slice(b"Hello");
            data[n + 0x200..n + 0x203].copy_from_slice(b"Bob");
            data[n + 0x3060..n + 0x3065].copy_from_slice(b"1.2.3");
        }
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
    fn matches_nro() {
        assert!(NroDissector.matches(&build_nro(false)));
        assert!(NroDissector.matches(&build_nro(true)));
    }

    #[test]
    fn does_not_match_non_nro_data() {
        assert!(!NroDissector.matches(b""));
        assert!(!NroDissector.matches(b"not an nro file at all, really"));
        let data = build_nro(false);
        assert!(!NroDissector.matches(&data[..0x14]));
        assert!(!NroDissector.matches(&data[..0x18]));
        let mut bad_size = data.clone();
        put_u32(&mut bad_size, 0x18, 0x10);
        assert!(!NroDissector.matches(&bad_size));
        put_u32(&mut bad_size, 0x18, u32::MAX);
        assert!(!NroDissector.matches(&bad_size));
    }

    #[test]
    fn dissect_truncated_input() {
        assert!(NroDissector.dissect(b"").is_empty());
        let data = build_nro(true);
        let blocks = NroDissector.dissect(&data[..0x40]);
        assert_eq!(blocks.len(), 1);
        for len in 0..data.len() {
            NroDissector.dissect(&data[..len]);
        }
    }

    #[test]
    fn dissect_headers_and_segments() {
        let data = build_nro(false);
        let blocks = NroDissector.dissect(&data);

        let start = find_block(&blocks, "Start header");
        assert_eq!(start.range, ByteRange::new(0, 0x10));
        find_block(&start.children, "MOD0 offset: 0x80");

        let header = find_block(&blocks, "NRO header");
        assert_eq!(header.range, ByteRange::new(0x10, 0x80));
        find_block(&header.children, "Magic: NRO0");
        find_block(&header.children, "Total size: 0x1c0");
        let id = find_block(
            &header.children,
            "Module ID: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(id.range, ByteRange::new(0x40, 0x60));

        let mod0 = find_block(&blocks, "MOD0 header");
        assert_eq!(mod0.range, ByteRange::new(0x80, 0x9C));
        find_block(&mod0.children, "Dynamic offset: +0x100 (-> 0x180)");
        find_block(&mod0.children, "BSS start offset: -0x8 (-> 0x78)");

        let text = find_block(&blocks, ".text segment (256 bytes)");
        assert_eq!(text.range, ByteRange::new(0, 0x100));
        let ro = find_block(&blocks, ".ro segment (128 bytes)");
        assert_eq!(ro.range, ByteRange::new(0x100, 0x180));
        let dynstr = find_block(&ro.children, ".dynstr (32 bytes)");
        assert_eq!(dynstr.range, ByteRange::new(0x110, 0x130));
        let d = find_block(&blocks, ".data segment (64 bytes)");
        assert_eq!(d.range, ByteRange::new(0x180, 0x1C0));
    }

    #[test]
    fn dissect_asset_section() {
        let data = build_nro(true);
        let blocks = NroDissector.dissect(&data);
        let aset = find_block(&blocks, "Asset section (ASET)");
        assert_eq!(aset.range, ByteRange::new(0x1C0, data.len() as u64));
        let header = find_block(&aset.children, "ASET header");
        assert_eq!(header.range, ByteRange::new(0x1C0, 0x1F8));
        let icon = find_block(&aset.children, "Icon (JPEG, 8 bytes)");
        assert_eq!(icon.range, ByteRange::new(0x1F8, 0x200));
        let nacp = find_block(&aset.children, "NACP (16384 bytes)");
        assert_eq!(nacp.range, ByteRange::new(0x200, 0x4200));
        let title = find_block(&nacp.children, "Title entry 0");
        find_block(&title.children, "Name: Hello");
        find_block(&title.children, "Publisher: Bob");
        let ver = find_block(&nacp.children, "Display version: 1.2.3");
        assert_eq!(ver.range, ByteRange::new(0x3260, 0x3270));
        let romfs = find_block(&aset.children, "RomFS (32 bytes)");
        assert_eq!(romfs.range, ByteRange::new(0x4200, 0x4220));
    }

    #[test]
    fn identify_reports_nro() {
        assert_eq!(super::super::identify(&build_nro(true)), "NRO");
    }
}
