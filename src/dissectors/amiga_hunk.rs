use super::{Block, ByteRange, Dissector};

const HUNK_UNIT: u32 = 0x3E7;
const HUNK_NAME: u32 = 0x3E8;
const HUNK_CODE: u32 = 0x3E9;
const HUNK_DATA: u32 = 0x3EA;
const HUNK_BSS: u32 = 0x3EB;
const HUNK_RELOC32: u32 = 0x3EC;
const HUNK_RELOC16: u32 = 0x3ED;
const HUNK_RELOC8: u32 = 0x3EE;
const HUNK_EXT: u32 = 0x3EF;
const HUNK_SYMBOL: u32 = 0x3F0;
const HUNK_DEBUG: u32 = 0x3F1;
const HUNK_END: u32 = 0x3F2;
const HUNK_HEADER: u32 = 0x3F3;
const HUNK_OVERLAY: u32 = 0x3F5;
const HUNK_BREAK: u32 = 0x3F6;
const HUNK_DREL32: u32 = 0x3F7;
const HUNK_DREL16: u32 = 0x3F8;
const HUNK_DREL8: u32 = 0x3F9;
const HUNK_LIB: u32 = 0x3FA;
const HUNK_INDEX: u32 = 0x3FB;
const HUNK_RELOC32SHORT: u32 = 0x3FC;
const HUNK_RELRELOC32: u32 = 0x3FD;
const HUNK_ABSRELOC16: u32 = 0x3FE;

const MEMF_CHIP: u32 = 1 << 30;
const MEMF_FAST: u32 = 1 << 31;
const MEM_MASK: u32 = MEMF_CHIP | MEMF_FAST;
const HUNKF_ADVISORY: u32 = 1 << 29;
const HUNK_TYPE_MASK: u32 = 0x1FFF_FFFF;
const SIZE_MASK: u32 = 0x3FFF_FFFF;

/// Longest symbol/unit name accepted by `matches`, in longwords.
const MAX_MATCH_NAME_LONGS: u32 = 64;
/// Most resident library names accepted in a HUNK_HEADER.
const MAX_RESIDENT_LIBS: usize = 16;
/// Most hunks accepted in a HUNK_HEADER table.
const MAX_HUNKS: u32 = 0x10000;
/// Longest list of child leaves shown before summarizing the rest.
const MAX_LIST: usize = 64;
/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct AmigaHunkDissector;

impl Dissector for AmigaHunkDissector {
    fn name(&self) -> &'static str {
        "Amiga Hunk"
    }

    fn matches(&self, data: &[u8]) -> bool {
        match read_u32(data, 0) {
            Some(HUNK_HEADER) => match parse_header(data) {
                // If anything follows the size table it must be a hunk that
                // can start a load file.
                Some(h) => match read_u32(data, h.end) {
                    Some(id) => matches!(
                        id & HUNK_TYPE_MASK,
                        HUNK_CODE | HUNK_DATA | HUNK_BSS | HUNK_NAME | HUNK_DEBUG
                    ),
                    None => h.end == data.len(),
                },
                None => false,
            },
            Some(HUNK_UNIT) => {
                let Some(longs) = read_u32(data, 4) else {
                    return false;
                };
                if longs > MAX_MATCH_NAME_LONGS {
                    return false;
                }
                let name_end = 8 + longs as usize * 4;
                let Some(name) = data.get(8..name_end) else {
                    return false;
                };
                if !name.iter().all(|&b| b == 0 || (0x20..0x7F).contains(&b)) {
                    return false;
                }
                matches!(
                    read_u32(data, name_end).map(|id| id & HUNK_TYPE_MASK),
                    Some(HUNK_NAME | HUNK_CODE | HUNK_DATA | HUNK_BSS)
                )
            }
            Some(HUNK_LIB) => {
                let Some(longs) = read_u32(data, 4) else {
                    return false;
                };
                let Some(end) = (longs as usize)
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(8))
                else {
                    return false;
                };
                if end > data.len() || longs == 0 {
                    return false;
                }
                matches!(
                    read_u32(data, 8).map(|id| id & HUNK_TYPE_MASK),
                    Some(HUNK_NAME | HUNK_CODE | HUNK_DATA | HUNK_BSS)
                )
            }
            _ => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < 4 {
            return blocks;
        }
        if read_u32(data, 0) == Some(HUNK_HEADER) {
            match parse_header(data) {
                Some(header) => {
                    let start = header.end;
                    let first = header.first;
                    let mems = header.mems;
                    blocks.push(header.block);
                    let mut stream = Stream::new(data, data.len(), true, first, &mems);
                    stream.run(start);
                    blocks.extend(stream.out);
                }
                None => blocks.push(Block::leaf(
                    "Unparsed data (truncated HUNK_HEADER)",
                    span(0, data.len()),
                )),
            }
        } else {
            let mut stream = Stream::new(data, data.len(), false, 0, &[]);
            stream.run(0);
            blocks.extend(stream.out);
        }
        blocks
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// `start + longs * 4`, or `None` if that would pass `end`.
fn longs_end(start: usize, longs: u32, end: usize) -> Option<usize> {
    let e = (longs as usize).checked_mul(4)?.checked_add(start)?;
    (e <= end).then_some(e)
}

fn read_name(data: &[u8], start: usize, end: usize) -> String {
    let bytes = data.get(start..end).unwrap_or(&[]);
    let bytes = match bytes.iter().position(|&b| b == 0) {
        Some(n) => &bytes[..n],
        None => bytes,
    };
    let mut s: String = bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if s.chars().count() > MAX_LABEL_CHARS {
        s = s.chars().take(MAX_LABEL_CHARS).collect();
        s.push('…');
    }
    s
}

fn hunk_type_name(ty: u32) -> Option<&'static str> {
    Some(match ty {
        HUNK_UNIT => "HUNK_UNIT",
        HUNK_NAME => "HUNK_NAME",
        HUNK_CODE => "HUNK_CODE",
        HUNK_DATA => "HUNK_DATA",
        HUNK_BSS => "HUNK_BSS",
        HUNK_RELOC32 => "HUNK_RELOC32",
        HUNK_RELOC16 => "HUNK_RELOC16",
        HUNK_RELOC8 => "HUNK_RELOC8",
        HUNK_EXT => "HUNK_EXT",
        HUNK_SYMBOL => "HUNK_SYMBOL",
        HUNK_DEBUG => "HUNK_DEBUG",
        HUNK_END => "HUNK_END",
        HUNK_HEADER => "HUNK_HEADER",
        HUNK_OVERLAY => "HUNK_OVERLAY",
        HUNK_BREAK => "HUNK_BREAK",
        HUNK_DREL32 => "HUNK_DREL32",
        HUNK_DREL16 => "HUNK_DREL16",
        HUNK_DREL8 => "HUNK_DREL8",
        HUNK_LIB => "HUNK_LIB",
        HUNK_INDEX => "HUNK_INDEX",
        HUNK_RELOC32SHORT => "HUNK_RELOC32SHORT",
        HUNK_RELRELOC32 => "HUNK_RELRELOC32",
        HUNK_ABSRELOC16 => "HUNK_ABSRELOC16",
        _ => return None,
    })
}

fn mem_name(bits: u32) -> &'static str {
    match bits & MEM_MASK {
        0 => "ANY",
        MEMF_CHIP => "CHIP",
        MEMF_FAST => "FAST",
        _ => "EXT",
    }
}

fn id_leaf(raw: u32, pos: usize) -> Block {
    let ty = raw & HUNK_TYPE_MASK;
    let name = hunk_type_name(ty).unwrap_or("unknown");
    let mut flags = String::new();
    if raw & MEMF_CHIP != 0 {
        flags.push_str(" | CHIP");
    }
    if raw & MEMF_FAST != 0 {
        flags.push_str(" | FAST");
    }
    if raw & HUNKF_ADVISORY != 0 {
        flags.push_str(" | ADVISORY");
    }
    Block::leaf(
        format!("ID: {name}{flags} (0x{raw:08X})"),
        span(pos, pos + 4),
    )
}

/// Leaves for a list of `count` offsets of `width` bytes, capped at MAX_LIST.
fn offset_leaves(data: &[u8], start: usize, count: usize, width: usize) -> Vec<Block> {
    let shown = count.min(MAX_LIST);
    let mut leaves = Vec::with_capacity(shown + 1);
    for i in 0..shown {
        let off = start + i * width;
        let value = if width == 2 {
            read_u16(data, off).map(u32::from)
        } else {
            read_u32(data, off)
        };
        if let Some(v) = value {
            leaves.push(Block::leaf(
                format!("Offset: 0x{v:06X}"),
                span(off, off + width),
            ));
        }
    }
    if count > shown {
        leaves.push(Block::leaf(
            format!("… {} more offsets", count - shown),
            span(start + shown * width, start + count * width),
        ));
    }
    leaves
}

struct Header {
    block: Block,
    end: usize,
    first: u32,
    mems: Vec<u32>,
}

fn parse_header(data: &[u8]) -> Option<Header> {
    if read_u32(data, 0)? != HUNK_HEADER {
        return None;
    }
    let mut children = vec![id_leaf(HUNK_HEADER, 0)];

    let mut p = 4;
    let mut libs = Vec::new();
    loop {
        let longs = read_u32(data, p)?;
        if longs == 0 {
            break;
        }
        if longs > MAX_MATCH_NAME_LONGS || libs.len() >= MAX_RESIDENT_LIBS {
            return None;
        }
        let name_end = longs_end(p + 4, longs, data.len())?;
        libs.push(Block::leaf(
            format!("Library: {}", read_name(data, p + 4, name_end)),
            span(p, name_end),
        ));
        p = name_end;
    }
    let libs_start = 4;
    p += 4;
    if libs.is_empty() {
        children.push(Block::leaf("Resident libraries: none", span(libs_start, p)));
    } else {
        libs.push(Block::leaf("End of list", span(p - 4, p)));
        children.push(Block::node(
            format!("Resident libraries ({})", libs.len() - 1),
            span(libs_start, p),
            libs,
        ));
    }

    let table_size = read_u32(data, p)?;
    let first = read_u32(data, p + 4)?;
    let last = read_u32(data, p + 8)?;
    if first > last || table_size > MAX_HUNKS || last - first >= table_size {
        return None;
    }
    children.push(Block::leaf(
        format!("Table size: {table_size}"),
        span(p, p + 4),
    ));
    children.push(Block::leaf(
        format!("First hunk: {first}"),
        span(p + 4, p + 8),
    ));
    children.push(Block::leaf(
        format!("Last hunk: {last}"),
        span(p + 8, p + 12),
    ));
    p += 12;

    let count = (last - first + 1) as usize;
    let sizes_start = p;
    let mut sizes = Vec::new();
    let mut mems = Vec::with_capacity(count);
    for i in 0..count {
        let w = read_u32(data, p)?;
        let bytes = (w & SIZE_MASK) as u64 * 4;
        let hunk = first as usize + i;
        let entry_start = p;
        p += 4;
        let mem = if w & MEM_MASK == MEM_MASK {
            let attrs = read_u32(data, p)?;
            p += 4;
            format!("attributes 0x{attrs:08X}")
        } else {
            mem_name(w).to_string()
        };
        mems.push(w & MEM_MASK);
        if i < MAX_LIST {
            sizes.push(Block::leaf(
                format!("Hunk {hunk}: {bytes} bytes ({mem})"),
                span(entry_start, p),
            ));
        } else if i == MAX_LIST {
            sizes.push(Block::leaf(
                format!("… {} more hunks", count - MAX_LIST),
                span(entry_start, p),
            ));
        } else if let Some(last_leaf) = sizes.last_mut() {
            last_leaf.range.end = p as u64;
        }
    }
    children.push(Block::node(
        format!("Hunk sizes ({count})"),
        span(sizes_start, p),
        sizes,
    ));

    Some(Header {
        block: Block::node(format!("HUNK_HEADER ({count} hunks)"), span(0, p), children).expanded(),
        end: p,
        first,
        mems,
    })
}

struct Group {
    start: usize,
    end: usize,
    title: Option<String>,
    children: Vec<Block>,
}

/// Parses a sequence of hunks, grouping each CODE/DATA/BSS hunk with the
/// NAME before it and the relocation/symbol/debug blocks up to its END.
struct Stream<'a> {
    data: &'a [u8],
    end: usize,
    load_file: bool,
    hunk_num: u32,
    first_hunk: u32,
    mems: &'a [u32],
    group: Option<Group>,
    out: Vec<Block>,
}

impl<'a> Stream<'a> {
    fn new(data: &'a [u8], end: usize, load_file: bool, first: u32, mems: &'a [u32]) -> Self {
        Self {
            data,
            end,
            load_file,
            hunk_num: first,
            first_hunk: first,
            mems,
            group: None,
            out: Vec::new(),
        }
    }

    fn flush(&mut self) {
        if let Some(g) = self.group.take() {
            match g.title {
                Some(title) => self
                    .out
                    .push(Block::node(title, span(g.start, g.end), g.children)),
                None => self.out.extend(g.children),
            }
        }
    }

    fn push(&mut self, block: Block) {
        match &mut self.group {
            Some(g) => {
                g.end = block.range.end as usize;
                g.children.push(block);
            }
            None => self.out.push(block),
        }
    }

    fn start_group(&mut self, start: usize) {
        if self.group.as_ref().is_some_and(|g| g.title.is_some()) {
            self.flush();
        }
        if self.group.is_none() {
            self.group = Some(Group {
                start,
                end: start,
                title: None,
                children: Vec::new(),
            });
        }
    }

    fn unparsed(&mut self, pos: usize, why: &str) {
        self.flush();
        if pos < self.end {
            self.out.push(Block::leaf(
                format!("Unparsed data ({why})"),
                span(pos, self.end),
            ));
        }
    }

    fn run(&mut self, start: usize) {
        let mut pos = start;
        loop {
            if pos >= self.end {
                break;
            }
            let Some(raw) = read_u32(self.data, pos).filter(|_| pos + 4 <= self.end) else {
                self.unparsed(pos, "trailing bytes");
                break;
            };
            let ty = raw & HUNK_TYPE_MASK;
            let result = match ty {
                HUNK_CODE | HUNK_DATA | HUNK_BSS => {
                    self.start_group(pos);
                    self.content(pos, raw).map(|(block, title)| {
                        if let Some(g) = &mut self.group {
                            g.title = Some(title);
                        }
                        self.hunk_num = self.hunk_num.wrapping_add(1);
                        block
                    })
                }
                HUNK_NAME => {
                    self.start_group(pos);
                    self.named(pos, raw, "HUNK_NAME")
                }
                HUNK_END => Some(Block::leaf("HUNK_END", span(pos, pos + 4))),
                HUNK_DREL32 if self.load_file => {
                    // LoadSeg (V37+) reads 0x3F7 in load files as RELOC32SHORT.
                    self.reloc_short(pos, raw, "HUNK_DREL32 (as RELOC32SHORT)")
                }
                HUNK_RELOC32SHORT => self.reloc_short(pos, raw, "HUNK_RELOC32SHORT"),
                HUNK_RELOC32 | HUNK_RELOC16 | HUNK_RELOC8 | HUNK_DREL32 | HUNK_DREL16
                | HUNK_DREL8 | HUNK_RELRELOC32 | HUNK_ABSRELOC16 => {
                    self.reloc_long(pos, raw, hunk_type_name(ty).unwrap_or("reloc"))
                }
                HUNK_EXT => self.ext(pos, raw),
                HUNK_SYMBOL => self.symbols(pos, raw),
                HUNK_DEBUG => self.debug(pos, raw),
                HUNK_UNIT if !self.load_file => {
                    self.flush();
                    self.hunk_num = 0;
                    self.first_hunk = 0;
                    self.named(pos, raw, "HUNK_UNIT").map(Block::expanded)
                }
                HUNK_INDEX => self.sized(pos, raw, "HUNK_INDEX", "Index data"),
                HUNK_LIB if !self.load_file => {
                    self.flush();
                    self.lib(pos, raw)
                }
                HUNK_BREAK => {
                    self.flush();
                    Some(Block::leaf("HUNK_BREAK", span(pos, pos + 4)))
                }
                HUNK_OVERLAY if self.load_file => {
                    self.flush();
                    match self.overlay(pos, raw) {
                        Some(block) => {
                            let end = block.range.end as usize;
                            self.out.push(block);
                            self.unparsed(end, "overlays not parsed");
                        }
                        None => self.unparsed(pos, "truncated HUNK_OVERLAY"),
                    }
                    break;
                }
                _ if raw & HUNKF_ADVISORY != 0 => {
                    self.sized(pos, raw, "Advisory hunk", "Skipped data")
                }
                _ => {
                    self.unparsed(pos, &format!("unknown hunk ID 0x{raw:08X}"));
                    break;
                }
            };
            let Some(block) = result else {
                let name = hunk_type_name(ty).unwrap_or("hunk");
                self.unparsed(pos, &format!("truncated or malformed {name}"));
                break;
            };
            pos = block.range.end as usize;
            self.push(block);
            if ty == HUNK_END {
                self.flush();
            }
        }
        self.flush();
    }

    fn content(&self, pos: usize, raw: u32) -> Option<(Block, String)> {
        let ty = raw & HUNK_TYPE_MASK;
        let size_word = read_u32(self.data, pos + 4).filter(|_| pos + 8 <= self.end)?;
        let longs = size_word & SIZE_MASK;
        let bytes = longs as u64 * 4;
        let (kind, name) = match ty {
            HUNK_CODE => ("CODE", "HUNK_CODE"),
            HUNK_DATA => ("DATA", "HUNK_DATA"),
            _ => ("BSS", "HUNK_BSS"),
        };
        let end = if ty == HUNK_BSS {
            pos + 8
        } else {
            longs_end(pos + 8, longs, self.end)?
        };

        let mut mem_bits = raw & MEM_MASK;
        if mem_bits == 0 {
            mem_bits = size_word & MEM_MASK;
        }
        if mem_bits == 0 && self.load_file {
            let idx = self.hunk_num.wrapping_sub(self.first_hunk) as usize;
            mem_bits = self.mems.get(idx).copied().unwrap_or(0);
        }
        let mem = mem_name(mem_bits);
        let title = format!("Hunk {}: {kind} ({bytes} bytes, {mem})", self.hunk_num);

        let mut children = vec![
            id_leaf(raw, pos),
            Block::leaf(
                format!("Size: {longs} longwords ({bytes} bytes)"),
                span(pos + 4, pos + 8),
            ),
        ];
        if end > pos + 8 {
            let label = if ty == HUNK_CODE { "Code" } else { "Data" };
            children.push(Block::leaf(label, span(pos + 8, end)));
        }
        Some((
            Block::node(format!("{name} ({bytes} bytes)"), span(pos, end), children),
            title,
        ))
    }

    /// HUNK_NAME / HUNK_UNIT: a longword count followed by a name.
    fn named(&self, pos: usize, raw: u32, label: &str) -> Option<Block> {
        let longs = read_u32(self.data, pos + 4)?;
        let end = longs_end(pos + 8, longs, self.end)?;
        let name = read_name(self.data, pos + 8, end);
        Some(Block::node(
            format!("{label}: {name}"),
            span(pos, end),
            vec![
                id_leaf(raw, pos),
                Block::leaf(
                    format!("Name length: {longs} longwords"),
                    span(pos + 4, pos + 8),
                ),
                Block::leaf(format!("Name: {name}"), span(pos + 8, end)),
            ],
        ))
    }

    /// A hunk consisting of a longword count followed by opaque data.
    fn sized(&self, pos: usize, raw: u32, label: &str, data_label: &str) -> Option<Block> {
        let longs = read_u32(self.data, pos + 4).filter(|_| pos + 8 <= self.end)?;
        let end = longs_end(pos + 8, longs, self.end)?;
        let mut children = vec![
            id_leaf(raw, pos),
            Block::leaf(format!("Size: {longs} longwords"), span(pos + 4, pos + 8)),
        ];
        if end > pos + 8 {
            children.push(Block::leaf(data_label, span(pos + 8, end)));
        }
        Some(Block::node(
            format!("{label} ({} bytes)", end - pos - 8),
            span(pos, end),
            children,
        ))
    }

    fn lib(&self, pos: usize, raw: u32) -> Option<Block> {
        let longs = read_u32(self.data, pos + 4).filter(|_| pos + 8 <= self.end)?;
        let end = longs_end(pos + 8, longs, self.end)?;
        let mut inner = Stream::new(self.data, end, false, 0, &[]);
        inner.run(pos + 8);
        let mut children = vec![
            id_leaf(raw, pos),
            Block::leaf(format!("Size: {longs} longwords"), span(pos + 4, pos + 8)),
        ];
        children.extend(inner.out);
        Some(
            Block::node(
                format!("HUNK_LIB ({} bytes)", end - pos - 8),
                span(pos, end),
                children,
            )
            .expanded(),
        )
    }

    fn overlay(&self, pos: usize, raw: u32) -> Option<Block> {
        let longs = read_u32(self.data, pos + 4).filter(|_| pos + 8 <= self.end)?;
        let end = longs_end(pos + 8, longs.checked_add(1)?, self.end)?;
        Some(Block::node(
            format!("HUNK_OVERLAY (table {longs} longwords)"),
            span(pos, end),
            vec![
                id_leaf(raw, pos),
                Block::leaf(
                    format!("Table size: {longs} longwords"),
                    span(pos + 4, pos + 8),
                ),
                Block::leaf("Overlay table", span(pos + 8, end)),
            ],
        ))
    }

    /// Relocations as (count, target hunk, offsets…) groups of longwords.
    fn reloc_long(&self, pos: usize, raw: u32, name: &str) -> Option<Block> {
        let mut children = vec![id_leaf(raw, pos)];
        let mut p = pos + 4;
        let mut total = 0usize;
        let mut groups = 0usize;
        loop {
            let count = read_u32(self.data, p).filter(|_| p + 4 <= self.end)?;
            if count == 0 {
                children.push(Block::leaf("End marker", span(p, p + 4)));
                p += 4;
                break;
            }
            let target = read_u32(self.data, p + 4).filter(|_| p + 8 <= self.end)?;
            let end = longs_end(p + 8, count, self.end)?;
            total += count as usize;
            groups += 1;
            if groups <= MAX_LIST {
                let mut leaves = vec![
                    Block::leaf(format!("Count: {count}"), span(p, p + 4)),
                    Block::leaf(format!("Target hunk: {target}"), span(p + 4, p + 8)),
                ];
                leaves.extend(offset_leaves(self.data, p + 8, count as usize, 4));
                children.push(Block::node(
                    format!("To hunk {target}: {count} offsets"),
                    span(p, end),
                    leaves,
                ));
            } else if groups == MAX_LIST + 1 {
                children.push(Block::leaf("… more groups", span(p, end)));
            } else if let Some(last) = children.last_mut() {
                last.range.end = end as u64;
            }
            p = end;
        }
        Some(Block::node(
            format!("{name} ({total} relocations)"),
            span(pos, p),
            children,
        ))
    }

    /// Relocations as (count, target hunk, offsets…) groups of 16-bit words,
    /// padded to a longword at the end.
    fn reloc_short(&self, pos: usize, raw: u32, name: &str) -> Option<Block> {
        let mut children = vec![id_leaf(raw, pos)];
        let mut p = pos + 4;
        let mut total = 0usize;
        let mut groups = 0usize;
        loop {
            let count = read_u16(self.data, p).filter(|_| p + 2 <= self.end)?;
            if count == 0 {
                children.push(Block::leaf("End marker", span(p, p + 2)));
                p += 2;
                break;
            }
            let target = read_u16(self.data, p + 2).filter(|_| p + 4 <= self.end)?;
            let end = p + 4 + count as usize * 2;
            if end > self.end {
                return None;
            }
            total += count as usize;
            groups += 1;
            if groups <= MAX_LIST {
                let mut leaves = vec![
                    Block::leaf(format!("Count: {count}"), span(p, p + 2)),
                    Block::leaf(format!("Target hunk: {target}"), span(p + 2, p + 4)),
                ];
                leaves.extend(offset_leaves(self.data, p + 4, count as usize, 2));
                children.push(Block::node(
                    format!("To hunk {target}: {count} offsets"),
                    span(p, end),
                    leaves,
                ));
            } else if groups == MAX_LIST + 1 {
                children.push(Block::leaf("… more groups", span(p, end)));
            } else if let Some(last) = children.last_mut() {
                last.range.end = end as u64;
            }
            p = end;
        }
        if (p - pos) % 4 != 0 {
            if p + 2 > self.end {
                return None;
            }
            children.push(Block::leaf("Padding", span(p, p + 2)));
            p += 2;
        }
        Some(Block::node(
            format!("{name} ({total} relocations)"),
            span(pos, p),
            children,
        ))
    }

    fn ext(&self, pos: usize, raw: u32) -> Option<Block> {
        let mut children = vec![id_leaf(raw, pos)];
        let mut p = pos + 4;
        let mut entries = 0usize;
        loop {
            let w = read_u32(self.data, p).filter(|_| p + 4 <= self.end)?;
            if w == 0 {
                children.push(Block::leaf("End marker", span(p, p + 4)));
                p += 4;
                break;
            }
            let ty = (w >> 24) as u8;
            let longs = w & 0x00FF_FFFF;
            let name_end = longs_end(p + 4, longs, self.end)?;
            let name = read_name(self.data, p + 4, name_end);
            let kind = ext_type_name(ty)?;
            let mut leaves = vec![
                Block::leaf(
                    format!("Type: {kind} ({ty}), name length: {longs} longwords"),
                    span(p, p + 4),
                ),
                Block::leaf(format!("Name: {name}"), span(p + 4, name_end)),
            ];
            let (label, end) = match ty {
                0..=3 => {
                    let value =
                        read_u32(self.data, name_end).filter(|_| name_end + 4 <= self.end)?;
                    leaves.push(Block::leaf(
                        format!("Value: 0x{value:08X}"),
                        span(name_end, name_end + 4),
                    ));
                    (format!("{kind} {name} = 0x{value:X}"), name_end + 4)
                }
                130 | 137 => {
                    let size =
                        read_u32(self.data, name_end).filter(|_| name_end + 4 <= self.end)?;
                    let count =
                        read_u32(self.data, name_end + 4).filter(|_| name_end + 8 <= self.end)?;
                    let end = longs_end(name_end + 8, count, self.end)?;
                    leaves.push(Block::leaf(
                        format!("Size: {size} bytes"),
                        span(name_end, name_end + 4),
                    ));
                    leaves.push(Block::leaf(
                        format!("Reference count: {count}"),
                        span(name_end + 4, name_end + 8),
                    ));
                    leaves.extend(offset_leaves(self.data, name_end + 8, count as usize, 4));
                    (format!("{kind} {name} (size {size}, {count} refs)"), end)
                }
                _ => {
                    let count =
                        read_u32(self.data, name_end).filter(|_| name_end + 4 <= self.end)?;
                    let end = longs_end(name_end + 4, count, self.end)?;
                    leaves.push(Block::leaf(
                        format!("Reference count: {count}"),
                        span(name_end, name_end + 4),
                    ));
                    leaves.extend(offset_leaves(self.data, name_end + 4, count as usize, 4));
                    (format!("{kind} {name} ({count} refs)"), end)
                }
            };
            entries += 1;
            if entries <= MAX_LIST {
                children.push(Block::node(label, span(p, end), leaves));
            } else if entries == MAX_LIST + 1 {
                children.push(Block::leaf("… more symbols", span(p, end)));
            } else if let Some(last) = children.last_mut() {
                last.range.end = end as u64;
            }
            p = end;
        }
        Some(Block::node(
            format!("HUNK_EXT ({entries} entries)"),
            span(pos, p),
            children,
        ))
    }

    fn symbols(&self, pos: usize, raw: u32) -> Option<Block> {
        let mut children = vec![id_leaf(raw, pos)];
        let mut p = pos + 4;
        let mut entries = 0usize;
        loop {
            let longs = read_u32(self.data, p).filter(|_| p + 4 <= self.end)?;
            if longs == 0 {
                children.push(Block::leaf("End marker", span(p, p + 4)));
                p += 4;
                break;
            }
            let name_end = longs_end(p + 4, longs, self.end)?;
            let value = read_u32(self.data, name_end).filter(|_| name_end + 4 <= self.end)?;
            let end = name_end + 4;
            entries += 1;
            if entries <= MAX_LIST {
                let name = read_name(self.data, p + 4, name_end);
                children.push(Block::leaf(format!("{name} = 0x{value:X}"), span(p, end)));
            } else if entries == MAX_LIST + 1 {
                children.push(Block::leaf("… more symbols", span(p, end)));
            } else if let Some(last) = children.last_mut() {
                last.range.end = end as u64;
            }
            p = end;
        }
        Some(Block::node(
            format!("HUNK_SYMBOL ({entries} symbols)"),
            span(pos, p),
            children,
        ))
    }

    fn debug(&self, pos: usize, raw: u32) -> Option<Block> {
        let longs = read_u32(self.data, pos + 4).filter(|_| pos + 8 <= self.end)?;
        let end = longs_end(pos + 8, longs, self.end)?;
        let bytes = end - pos - 8;
        let mut children = vec![
            id_leaf(raw, pos),
            Block::leaf(format!("Size: {longs} longwords"), span(pos + 4, pos + 8)),
        ];
        let d = pos + 8;
        let line = bytes >= 12 && self.data.get(d + 4..d + 8) == Some(b"LINE".as_slice());
        let mut parsed_line = false;
        if line {
            // LINE format: base offset, "LINE", name length, name, (line, offset) pairs.
            let base = read_u32(self.data, d)?;
            let name_longs = read_u32(self.data, d + 8)?;
            if let Some(name_end) = longs_end(d + 12, name_longs, end) {
                let name = read_name(self.data, d + 12, name_end);
                let pairs = (end - name_end) / 8;
                children.push(Block::leaf(
                    format!("Base offset: 0x{base:X}"),
                    span(d, d + 4),
                ));
                children.push(Block::leaf("Format: LINE", span(d + 4, d + 8)));
                children.push(Block::leaf(
                    format!("Name length: {name_longs} longwords"),
                    span(d + 8, d + 12),
                ));
                children.push(Block::leaf(
                    format!("Source file: {name}"),
                    span(d + 12, name_end),
                ));
                if end > name_end {
                    children.push(Block::leaf(
                        format!("Line table ({pairs} entries)"),
                        span(name_end, end),
                    ));
                }
                parsed_line = true;
            }
        }
        if !parsed_line && bytes > 0 {
            children.push(Block::leaf("Debug data", span(d, end)));
        }
        let label = if line {
            format!("HUNK_DEBUG (LINE, {bytes} bytes)")
        } else {
            format!("HUNK_DEBUG ({bytes} bytes)")
        };
        Some(Block::node(label, span(pos, end), children))
    }
}

fn ext_type_name(ty: u8) -> Option<&'static str> {
    Some(match ty {
        0 => "EXT_SYMB",
        1 => "EXT_DEF",
        2 => "EXT_ABS",
        3 => "EXT_RES",
        129 => "EXT_REF32",
        130 => "EXT_COMMON",
        131 => "EXT_REF16",
        132 => "EXT_REF8",
        133 => "EXT_DEXT32",
        134 => "EXT_DEXT16",
        135 => "EXT_DEXT8",
        136 => "EXT_RELREF32",
        137 => "EXT_RELCOMMON",
        138 => "EXT_ABSREF16",
        139 => "EXT_ABSREF8",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn push_name(buf: &mut Vec<u8>, name: &str) {
        let longs = name.len().div_ceil(4);
        push_u32(buf, longs as u32);
        let mut bytes = name.as_bytes().to_vec();
        bytes.resize(longs * 4, 0);
        buf.extend_from_slice(&bytes);
    }

    /// Executable with a CODE hunk (2 longwords, with RELOC32, SYMBOL and
    /// DEBUG) and a CHIP BSS hunk (4 longwords).
    fn build_exe() -> Vec<u8> {
        let mut d = Vec::new();
        push_u32(&mut d, HUNK_HEADER); // 0
        push_u32(&mut d, 0); // 4: no resident libraries
        push_u32(&mut d, 2); // 8: table size
        push_u32(&mut d, 0); // 12: first
        push_u32(&mut d, 1); // 16: last
        push_u32(&mut d, 2); // 20: hunk 0 size
        push_u32(&mut d, MEMF_CHIP | 4); // 24: hunk 1 size, CHIP
        // 28: hunk 0
        push_u32(&mut d, HUNK_CODE);
        push_u32(&mut d, 2);
        d.extend_from_slice(&[0x4E, 0x75, 0, 0, 0, 0, 0, 0]); // 36..44
        // 44: RELOC32: one group of 1 offset to hunk 1
        push_u32(&mut d, HUNK_RELOC32);
        push_u32(&mut d, 1);
        push_u32(&mut d, 1);
        push_u32(&mut d, 4);
        push_u32(&mut d, 0); // 60..64
        // 64: SYMBOL
        push_u32(&mut d, HUNK_SYMBOL);
        push_name(&mut d, "_main"); // 68..80
        push_u32(&mut d, 0); // 80: value
        push_u32(&mut d, 0); // 84: end
        // 88: DEBUG, LINE format, 5 longwords
        push_u32(&mut d, HUNK_DEBUG);
        push_u32(&mut d, 5);
        push_u32(&mut d, 0); // base
        d.extend_from_slice(b"LINE");
        push_name(&mut d, "a.c"); // 104..112
        push_u32(&mut d, 0); // 112..116
        // 116: END
        push_u32(&mut d, HUNK_END);
        // 120: hunk 1 BSS
        push_u32(&mut d, HUNK_BSS);
        push_u32(&mut d, 4);
        push_u32(&mut d, HUNK_END); // 128..132
        d
    }

    fn build_unit() -> Vec<u8> {
        let mut d = Vec::new();
        push_u32(&mut d, HUNK_UNIT); // 0
        push_name(&mut d, "test.o"); // 4..16
        push_u32(&mut d, HUNK_NAME); // 16
        push_name(&mut d, "CODE"); // 20..28
        push_u32(&mut d, HUNK_CODE); // 28
        push_u32(&mut d, 1);
        push_u32(&mut d, 0x4E75_4E75); // 36..40
        // 40: EXT with a DEF and a REF32
        push_u32(&mut d, HUNK_EXT);
        push_u32(&mut d, (1 << 24) | 2); // 44: EXT_DEF, 2 longwords
        d.extend_from_slice(b"_foo\0\0\0\0"); // 48..56
        push_u32(&mut d, 0x10); // 56..60
        push_u32(&mut d, (129 << 24) | 1); // 60: EXT_REF32
        d.extend_from_slice(b"_bar"); // 64..68
        push_u32(&mut d, 2); // 68: count
        push_u32(&mut d, 0);
        push_u32(&mut d, 4); // ..80
        push_u32(&mut d, 0); // 80: end
        // 84: RELOC32SHORT: 1 group of 2 offsets, terminator, padding
        push_u32(&mut d, HUNK_RELOC32SHORT);
        d.extend_from_slice(&[0, 2, 0, 0, 0, 2, 0, 6, 0, 0]); // 88..98
        d.extend_from_slice(&[0, 0]); // 98..100: padding
        push_u32(&mut d, HUNK_END); // 100..104
        d
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
    fn matches_built_files() {
        assert!(AmigaHunkDissector.matches(&build_exe()));
        assert!(AmigaHunkDissector.matches(&build_unit()));
        let mut lib = Vec::new();
        push_u32(&mut lib, HUNK_LIB);
        push_u32(&mut lib, 3);
        push_u32(&mut lib, HUNK_CODE);
        push_u32(&mut lib, 0);
        push_u32(&mut lib, HUNK_END);
        assert!(AmigaHunkDissector.matches(&lib));
        let blocks = AmigaHunkDissector.dissect(&lib);
        let node = find_block(&blocks, "HUNK_LIB (12 bytes)");
        assert_eq!(node.range, ByteRange::new(0, 20));
        assert_eq!(
            find_block(&node.children, "Hunk 0: CODE (0 bytes, ANY)").range,
            ByteRange::new(8, 20)
        );
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!AmigaHunkDissector.matches(b""));
        assert!(!AmigaHunkDissector.matches(b"\0\0\x03"));
        assert!(!AmigaHunkDissector.matches(b"not an amiga file"));
        // Truncated header: size table cut off.
        assert!(!AmigaHunkDissector.matches(&build_exe()[..24]));
        // first > last
        let mut bad = build_exe();
        bad[12..16].copy_from_slice(&2u32.to_be_bytes());
        assert!(!AmigaHunkDissector.matches(&bad));
        // table size too small
        let mut bad = build_exe();
        bad[8..12].copy_from_slice(&1u32.to_be_bytes());
        assert!(!AmigaHunkDissector.matches(&bad));
        // unit with absurd name length
        let mut bad = build_unit();
        bad[4..8].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(!AmigaHunkDissector.matches(&bad));
    }

    #[test]
    fn dissects_header() {
        let blocks = AmigaHunkDissector.dissect(&build_exe());
        let header = find_block(&blocks, "HUNK_HEADER (2 hunks)");
        assert_eq!(header.range, ByteRange::new(0, 28));
        let c = &header.children;
        assert_eq!(
            find_block(c, "Resident libraries: none").range,
            ByteRange::new(4, 8)
        );
        assert_eq!(find_block(c, "Table size: 2").range, ByteRange::new(8, 12));
        assert_eq!(find_block(c, "Last hunk: 1").range, ByteRange::new(16, 20));
        let sizes = &find_block(c, "Hunk sizes (2)").children;
        assert_eq!(
            find_block(sizes, "Hunk 0: 8 bytes (ANY)").range,
            ByteRange::new(20, 24)
        );
        assert_eq!(
            find_block(sizes, "Hunk 1: 16 bytes (CHIP)").range,
            ByteRange::new(24, 28)
        );
    }

    #[test]
    fn dissects_exe_hunks() {
        let blocks = AmigaHunkDissector.dissect(&build_exe());
        assert_eq!(blocks.len(), 3);
        let h0 = find_block(&blocks, "Hunk 0: CODE (8 bytes, ANY)");
        assert_eq!(h0.range, ByteRange::new(28, 120));
        let code = find_block(&h0.children, "HUNK_CODE (8 bytes)");
        assert_eq!(
            find_block(&code.children, "Code").range,
            ByteRange::new(36, 44)
        );

        let reloc = find_block(&h0.children, "HUNK_RELOC32 (1 relocations)");
        assert_eq!(reloc.range, ByteRange::new(44, 64));
        let group = find_block(&reloc.children, "To hunk 1: 1 offsets");
        assert_eq!(group.range, ByteRange::new(48, 60));
        assert_eq!(
            find_block(&group.children, "Offset: 0x000004").range,
            ByteRange::new(56, 60)
        );

        let sym = find_block(&h0.children, "HUNK_SYMBOL (1 symbols)");
        assert_eq!(sym.range, ByteRange::new(64, 88));
        assert_eq!(
            find_block(&sym.children, "_main = 0x0").range,
            ByteRange::new(68, 84)
        );

        let dbg = find_block(&h0.children, "HUNK_DEBUG (LINE, 20 bytes)");
        assert_eq!(dbg.range, ByteRange::new(88, 116));
        assert_eq!(
            find_block(&dbg.children, "Source file: a.c").range,
            ByteRange::new(108, 112)
        );
        assert_eq!(
            find_block(&h0.children, "HUNK_END").range,
            ByteRange::new(116, 120)
        );

        let h1 = find_block(&blocks, "Hunk 1: BSS (16 bytes, CHIP)");
        assert_eq!(h1.range, ByteRange::new(120, 132));
    }

    #[test]
    fn dissects_unit() {
        let blocks = AmigaHunkDissector.dissect(&build_unit());
        let unit = find_block(&blocks, "HUNK_UNIT: test.o");
        assert_eq!(unit.range, ByteRange::new(0, 16));
        let h0 = find_block(&blocks, "Hunk 0: CODE (4 bytes, ANY)");
        assert_eq!(h0.range, ByteRange::new(16, 104));
        assert_eq!(
            find_block(&h0.children, "HUNK_NAME: CODE").range,
            ByteRange::new(16, 28)
        );
        let ext = find_block(&h0.children, "HUNK_EXT (2 entries)");
        assert_eq!(ext.range, ByteRange::new(40, 84));
        assert_eq!(
            find_block(&ext.children, "EXT_DEF _foo = 0x10").range,
            ByteRange::new(44, 60)
        );
        let r = find_block(&ext.children, "EXT_REF32 _bar (2 refs)");
        assert_eq!(r.range, ByteRange::new(60, 80));
        let short = find_block(&h0.children, "HUNK_RELOC32SHORT (2 relocations)");
        assert_eq!(short.range, ByteRange::new(84, 100));
        assert_eq!(
            find_block(&short.children, "Padding").range,
            ByteRange::new(98, 100)
        );
    }

    #[test]
    fn unknown_hunk_stops_gracefully() {
        let mut data = build_exe();
        push_u32(&mut data, 0x1234);
        push_u32(&mut data, 0);
        let blocks = AmigaHunkDissector.dissect(&data);
        let last = blocks.last().unwrap();
        assert_eq!(last.label, "Unparsed data (unknown hunk ID 0x00001234)");
        assert_eq!(last.range, ByteRange::new(132, 140));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let full = build_exe();
        let full_count = AmigaHunkDissector.dissect(&full).len();
        for len in 0..full.len() {
            let blocks = AmigaHunkDissector.dissect(&full[..len]);
            assert!(blocks.len() <= full_count + 1);
            for b in &blocks {
                assert!(b.range.end as usize <= len);
            }
        }
        let unit = build_unit();
        for len in 0..unit.len() {
            AmigaHunkDissector.dissect(&unit[..len]);
        }
        let blocks = AmigaHunkDissector.dissect(&full[..100]);
        assert_eq!(
            blocks.last().unwrap().label,
            "Unparsed data (truncated or malformed HUNK_DEBUG)"
        );
    }

    #[test]
    fn caps_long_lists() {
        let mut d = Vec::new();
        push_u32(&mut d, HUNK_UNIT);
        push_name(&mut d, "u");
        push_u32(&mut d, HUNK_CODE);
        push_u32(&mut d, 0);
        push_u32(&mut d, HUNK_RELOC32);
        push_u32(&mut d, 100);
        push_u32(&mut d, 0);
        for i in 0..100 {
            push_u32(&mut d, i * 4);
        }
        push_u32(&mut d, 0);
        push_u32(&mut d, HUNK_END);
        let blocks = AmigaHunkDissector.dissect(&d);
        let h0 = find_block(&blocks, "Hunk 0: CODE (0 bytes, ANY)");
        let reloc = find_block(&h0.children, "HUNK_RELOC32 (100 relocations)");
        let group = find_block(&reloc.children, "To hunk 0: 100 offsets");
        assert_eq!(group.children.len(), 2 + MAX_LIST + 1);
        assert_eq!(group.children.last().unwrap().label, "… 36 more offsets");
    }

    #[test]
    fn identify_returns_amiga_hunk() {
        assert_eq!(super::super::identify(&build_exe()), "Amiga Hunk");
        assert_eq!(super::super::identify(&build_unit()), "Amiga Hunk");
    }
}
