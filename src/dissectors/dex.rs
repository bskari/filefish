use super::{Block, ByteRange, Dissector};

const DEX_MAGIC_PREFIX: &[u8] = b"dex\n";
const HEADER_LEN: usize = 0x70;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
const NO_INDEX: u32 = 0xFFFF_FFFF;

/// Upper bound on entries shown per table, so a corrupt size field can't
/// make us build millions of blocks.
const MAX_ENTRIES: usize = 200_000;
/// Upper bound on parameters decoded from a single type_list.
const MAX_TYPE_LIST: usize = 255;
/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct DexDissector;

impl Dissector for DexDissector {
    fn name(&self) -> &'static str {
        "DEX"
    }

    fn matches(&self, data: &[u8]) -> bool {
        // "dex\n" followed by a three-digit version and a NUL, e.g. "dex\n035\0".
        match data.get(0..8) {
            Some(magic) => {
                magic.starts_with(DEX_MAGIC_PREFIX)
                    && magic[4..7].iter().all(u8::is_ascii_digit)
                    && magic[7] == 0
            }
            None => false,
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if !self.matches(data) {
            return blocks;
        }

        let dex = Dex::new(data);
        blocks.push(dex.header_block());

        if data.len() < HEADER_LEN {
            return blocks;
        }

        let h = dex.header();
        let strings = dex.decode_strings(&h);

        let ids = [
            dex.string_ids_block(&h, &strings),
            dex.type_ids_block(&h, &strings),
            dex.proto_ids_block(&h, &strings),
            dex.field_ids_block(&h, &strings),
            dex.method_ids_block(&h, &strings),
            dex.class_defs_block(&h, &strings),
        ];
        blocks.extend(ids.into_iter().flatten());

        let mut data_children: Vec<Block> = Vec::new();
        let mut loose: Vec<Block> = Vec::new();
        let data_range = dex.clamped(h.data_off, h.data_size as u64);
        let in_data = |b: &Block| {
            data_range.is_some_and(|r| b.range.start >= r.start && b.range.end <= r.end)
        };
        for b in [dex.string_data_block(&strings), dex.map_list_block(&h)]
            .into_iter()
            .flatten()
        {
            if in_data(&b) {
                data_children.push(b);
            } else {
                loose.push(b);
            }
        }
        if let Some(range) = data_range {
            data_children.sort_by_key(|b| b.range.start);
            let label = format!("Data ({} bytes)", range.end - range.start);
            if data_children.is_empty() {
                blocks.push(Block::leaf(label, range));
            } else {
                blocks.push(Block::node(label, range, data_children));
            }
        }
        blocks.extend(loose);

        if h.link_size > 0 {
            if let Some(range) = dex.clamped(h.link_off, h.link_size as u64) {
                blocks.push(Block::leaf(
                    format!("Link data ({} bytes)", range.end - range.start),
                    range,
                ));
            }
        }

        blocks
    }
}

#[derive(Default)]
struct Header {
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids: (u32, u32),
    type_ids: (u32, u32),
    proto_ids: (u32, u32),
    field_ids: (u32, u32),
    method_ids: (u32, u32),
    class_defs: (u32, u32),
    data_size: u32,
    data_off: u32,
}

struct Dex<'a> {
    data: &'a [u8],
    little_endian: bool,
}

impl<'a> Dex<'a> {
    fn new(data: &'a [u8]) -> Self {
        let tag = data
            .get(40..44)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])));
        Self {
            data,
            little_endian: tag != Some(REVERSE_ENDIAN_CONSTANT),
        }
    }

    fn u16(&self, offset: usize) -> Option<u16> {
        let b: [u8; 2] = self
            .data
            .get(offset..offset.checked_add(2)?)?
            .try_into()
            .ok()?;
        Some(if self.little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32(&self, offset: usize) -> Option<u32> {
        let b: [u8; 4] = self
            .data
            .get(offset..offset.checked_add(4)?)?
            .try_into()
            .ok()?;
        Some(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    /// Range `off..off+len` clamped to the file, or None if it starts past the end
    /// or is empty.
    fn clamped(&self, off: u32, len: u64) -> Option<ByteRange> {
        let file_len = self.data.len() as u64;
        let start = off as u64;
        if start >= file_len || len == 0 {
            return None;
        }
        Some(ByteRange::new(start, (start + len).min(file_len)))
    }

    fn header(&self) -> Header {
        let r = |o| self.u32(o).unwrap_or(0);
        Header {
            link_size: r(44),
            link_off: r(48),
            map_off: r(52),
            string_ids: (r(56), r(60)),
            type_ids: (r(64), r(68)),
            proto_ids: (r(72), r(76)),
            field_ids: (r(80), r(84)),
            method_ids: (r(88), r(92)),
            class_defs: (r(96), r(100)),
            data_size: r(104),
            data_off: r(108),
        }
    }

    fn header_block(&self) -> Block {
        let data = self.data;
        let mut children = Vec::new();

        let version = String::from_utf8_lossy(&data[4..7]).into_owned();
        children.push(Block::leaf(
            format!("Magic: dex\\n{version}\\0 (version {version})"),
            span(0, 8),
        ));
        if let Some(v) = self.u32(8) {
            children.push(Block::leaf(
                format!("Checksum (Adler-32): 0x{v:08X}"),
                span(8, 12),
            ));
        }
        if let Some(sig) = data.get(12..32) {
            let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
            children.push(Block::leaf(
                format!("Signature (SHA-1): {hex}"),
                span(12, 32),
            ));
        }

        let header_size = self.u32(36);
        let push_u32 = |children: &mut Vec<Block>, off: usize, label: &str| {
            if let Some(v) = self.u32(off) {
                children.push(Block::leaf(format!("{label}: {v}"), span(off, off + 4)));
            }
        };
        if let Some(v) = self.u32(32) {
            let note = if v as usize == data.len() {
                String::new()
            } else {
                format!(" (actual {})", data.len())
            };
            children.push(Block::leaf(format!("File size: {v}{note}"), span(32, 36)));
        }
        push_u32(&mut children, 36, "Header size");
        if let Some(v) = data.get(40..44) {
            let raw = u32::from_le_bytes(v.try_into().unwrap_or([0; 4]));
            let name = match raw {
                ENDIAN_CONSTANT => "little-endian",
                REVERSE_ENDIAN_CONSTANT => "big-endian (reverse)",
                _ => "unknown",
            };
            children.push(Block::leaf(
                format!("Endian tag: 0x{raw:08X} ({name})"),
                span(40, 44),
            ));
        }

        let pairs: [(usize, &str); 8] = [
            (44, "Link"),
            (56, "string_ids"),
            (64, "type_ids"),
            (72, "proto_ids"),
            (80, "field_ids"),
            (88, "method_ids"),
            (96, "class_defs"),
            (104, "Data"),
        ];
        for (off, name) in pairs {
            if off == 56 {
                if let Some(v) = self.u32(52) {
                    children.push(Block::leaf(format!("Map offset: 0x{v:X}"), span(52, 56)));
                }
            }
            push_u32(&mut children, off, &format!("{name} size"));
            if let Some(v) = self.u32(off + 4) {
                children.push(Block::leaf(
                    format!("{name} offset: 0x{v:X}"),
                    span(off + 4, off + 8),
                ));
            }
        }

        // DEX 041+ container format adds two more fields when the header is larger.
        if header_size.is_some_and(|s| s >= 0x78) {
            push_u32(&mut children, 0x70, "Container size");
            if let Some(v) = self.u32(0x74) {
                children.push(Block::leaf(
                    format!("Header offset: 0x{v:X}"),
                    span(0x74, 0x78),
                ));
            }
        }

        let declared = header_size.map_or(HEADER_LEN, |s| (s as usize).max(HEADER_LEN));
        let end = declared.min(data.len());
        Block::node("DEX header", span(0, end), children).expanded()
    }

    /// Decodes up to MAX_ENTRIES strings; returns (data range, text) per string id.
    fn decode_strings(&self, h: &Header) -> Vec<Option<(ByteRange, String)>> {
        let (size, off) = h.string_ids;
        let count = table_count(self.data.len(), size, off, 4);
        (0..count)
            .map(|i| {
                let data_off = self.u32(off as usize + i * 4)? as usize;
                let (_utf16_len, n) = read_uleb128(self.data, data_off)?;
                let start = data_off + n;
                let rest = self.data.get(start..)?;
                let nul = rest.iter().position(|&b| b == 0)?;
                let text = decode_mutf8(&rest[..nul]);
                Some((span(data_off, start + nul + 1), text))
            })
            .collect()
    }

    fn table(
        &self,
        name: &str,
        (size, off): (u32, u32),
        entry_size: usize,
        mut entry: impl FnMut(usize, usize) -> Block,
    ) -> Option<Block> {
        if size == 0 || off == 0 {
            return None;
        }
        let range = self.clamped(off, size as u64 * entry_size as u64)?;
        let count = table_count(self.data.len(), size, off, entry_size);
        let mut children: Vec<Block> = (0..count)
            .map(|i| entry(i, off as usize + i * entry_size))
            .collect();
        let shown_end = off as u64 + (count * entry_size) as u64;
        if (count as u64) < size as u64 && shown_end < range.end {
            children.push(Block::leaf(
                format!("({} more entries not shown)", size as usize - count),
                ByteRange::new(shown_end, range.end),
            ));
        }
        Some(Block::node(
            format!("{name} ({size} entries)"),
            range,
            children,
        ))
    }

    fn string_ids_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("string_ids", h.string_ids, 4, |i, o| {
            let target = self.u32(o).unwrap_or(0);
            let label = match strings.get(i).and_then(Option::as_ref) {
                Some((_, s)) => format!("string_ids[{i}]: 0x{target:X} {}", quote(s)),
                None => format!("string_ids[{i}]: 0x{target:X} (invalid)"),
            };
            Block::leaf(label, span(o, o + 4))
        })
    }

    fn type_ids_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("type_ids", h.type_ids, 4, |i, o| {
            let idx = self.u32(o).unwrap_or(NO_INDEX);
            Block::leaf(
                format!("type_ids[{i}]: string {idx} {}", string_label(strings, idx)),
                span(o, o + 4),
            )
        })
    }

    fn type_name(&self, h: &Header, strings: &Strings, type_idx: u32) -> String {
        let (size, off) = h.type_ids;
        if type_idx >= size {
            return format!("<type {type_idx}>");
        }
        self.u32(off as usize + type_idx as usize * 4)
            .and_then(|s| string(strings, s))
            .map_or_else(|| format!("<type {type_idx}>"), str::to_owned)
    }

    fn type_list(&self, h: &Header, strings: &Strings, off: u32) -> Option<String> {
        if off == 0 {
            return Some(String::new());
        }
        let off = off as usize;
        let n = self.u32(off)? as usize;
        let mut out = String::new();
        for i in 0..n.min(MAX_TYPE_LIST) {
            let t = self.u16(off + 4 + i * 2)?;
            out.push_str(&self.type_name(h, strings, t as u32));
        }
        if n > MAX_TYPE_LIST {
            out.push_str("...");
        }
        Some(out)
    }

    fn proto_signature(&self, h: &Header, strings: &Strings, proto_idx: u32) -> String {
        let (size, off) = h.proto_ids;
        if proto_idx >= size {
            return format!("<proto {proto_idx}>");
        }
        let o = off as usize + proto_idx as usize * 12;
        let (Some(ret), Some(params)) = (self.u32(o + 4), self.u32(o + 8)) else {
            return format!("<proto {proto_idx}>");
        };
        let params = self
            .type_list(h, strings, params)
            .unwrap_or_else(|| "?".into());
        format!("({params}){}", self.type_name(h, strings, ret))
    }

    fn proto_ids_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("proto_ids", h.proto_ids, 12, |i, o| {
            let shorty = self.u32(o).unwrap_or(NO_INDEX);
            let ret = self.u32(o + 4).unwrap_or(NO_INDEX);
            let params = self.u32(o + 8).unwrap_or(0);
            let sig = truncate(&self.proto_signature(h, strings, i as u32));
            Block::node(
                format!("proto_ids[{i}]: {sig}"),
                span(o, o + 12),
                vec![
                    Block::leaf(
                        format!("Shorty: string {shorty} {}", string_label(strings, shorty)),
                        span(o, o + 4),
                    ),
                    Block::leaf(
                        format!(
                            "Return type: type {ret} ({})",
                            self.type_name(h, strings, ret)
                        ),
                        span(o + 4, o + 8),
                    ),
                    Block::leaf(
                        format!("Parameters offset: 0x{params:X}"),
                        span(o + 8, o + 12),
                    ),
                ],
            )
        })
    }

    fn field_ids_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("field_ids", h.field_ids, 8, |i, o| {
            let class = self.u16(o).unwrap_or(0) as u32;
            let ty = self.u16(o + 2).unwrap_or(0) as u32;
            let name = self.u32(o + 4).unwrap_or(NO_INDEX);
            let class_s = self.type_name(h, strings, class);
            let ty_s = self.type_name(h, strings, ty);
            let name_s = string(strings, name).unwrap_or("?");
            Block::node(
                format!(
                    "field_ids[{i}]: {}",
                    truncate(&format!("{class_s}->{name_s}:{ty_s}"))
                ),
                span(o, o + 8),
                vec![
                    Block::leaf(format!("Class: type {class} ({class_s})"), span(o, o + 2)),
                    Block::leaf(format!("Type: type {ty} ({ty_s})"), span(o + 2, o + 4)),
                    Block::leaf(
                        format!("Name: string {name} {}", string_label(strings, name)),
                        span(o + 4, o + 8),
                    ),
                ],
            )
        })
    }

    fn method_ids_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("method_ids", h.method_ids, 8, |i, o| {
            let class = self.u16(o).unwrap_or(0) as u32;
            let proto = self.u16(o + 2).unwrap_or(0) as u32;
            let name = self.u32(o + 4).unwrap_or(NO_INDEX);
            let class_s = self.type_name(h, strings, class);
            let proto_s = self.proto_signature(h, strings, proto);
            let name_s = string(strings, name).unwrap_or("?");
            Block::node(
                format!(
                    "method_ids[{i}]: {}",
                    truncate(&format!("{class_s}->{name_s}{proto_s}"))
                ),
                span(o, o + 8),
                vec![
                    Block::leaf(format!("Class: type {class} ({class_s})"), span(o, o + 2)),
                    Block::leaf(
                        format!("Proto: proto {proto} {}", truncate(&proto_s)),
                        span(o + 2, o + 4),
                    ),
                    Block::leaf(
                        format!("Name: string {name} {}", string_label(strings, name)),
                        span(o + 4, o + 8),
                    ),
                ],
            )
        })
    }

    fn class_defs_block(&self, h: &Header, strings: &Strings) -> Option<Block> {
        self.table("class_defs", h.class_defs, 32, |i, o| {
            let f = |k: usize| self.u32(o + k * 4).unwrap_or(0);
            let class = f(0);
            let flags = f(1);
            let superclass = f(2);
            let source = f(4);
            let class_s = self.type_name(h, strings, class);
            let opt_type = |idx: u32| {
                if idx == NO_INDEX {
                    "NO_INDEX".to_owned()
                } else {
                    format!("type {idx} ({})", self.type_name(h, strings, idx))
                }
            };
            let source_s = if source == NO_INDEX {
                "NO_INDEX".to_owned()
            } else {
                format!("string {source} {}", string_label(strings, source))
            };
            let leaf = |k: usize, label: String| Block::leaf(label, span(o + k * 4, o + k * 4 + 4));
            Block::node(
                format!("class_defs[{i}]: {}", truncate(&class_s)),
                span(o, o + 32),
                vec![
                    leaf(0, format!("Class: type {class} ({class_s})")),
                    leaf(
                        1,
                        format!("Access flags: 0x{flags:X} ({})", access_flags(flags)),
                    ),
                    leaf(2, format!("Superclass: {}", opt_type(superclass))),
                    leaf(3, format!("Interfaces offset: 0x{:X}", f(3))),
                    leaf(4, format!("Source file: {source_s}")),
                    leaf(5, format!("Annotations offset: 0x{:X}", f(5))),
                    leaf(6, format!("Class data offset: 0x{:X}", f(6))),
                    leaf(7, format!("Static values offset: 0x{:X}", f(7))),
                ],
            )
        })
    }

    fn string_data_block(&self, strings: &Strings) -> Option<Block> {
        let mut items: Vec<(usize, ByteRange, &str)> = strings
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|(r, t)| (i, *r, t.as_str())))
            .collect();
        if items.is_empty() {
            return None;
        }
        items.sort_by_key(|(_, r, _)| r.start);
        items.dedup_by_key(|(_, r, _)| r.start);
        let start = items.iter().map(|(_, r, _)| r.start).min()?;
        let end = items.iter().map(|(_, r, _)| r.end).max()?;
        let children = items
            .into_iter()
            .map(|(i, r, t)| Block::leaf(format!("string_data[{i}]: {}", quote(t)), r))
            .collect();
        Some(Block::node(
            format!("String data ({} strings)", strings.len()),
            ByteRange::new(start, end),
            children,
        ))
    }

    fn map_list_block(&self, h: &Header) -> Option<Block> {
        if h.map_off == 0 {
            return None;
        }
        let off = h.map_off as usize;
        let size = self.u32(off)?;
        let count = table_count(self.data.len(), size, h.map_off.saturating_add(4), 12);
        let mut children = vec![Block::leaf(format!("Size: {size}"), span(off, off + 4))];
        for i in 0..count {
            let o = off + 4 + i * 12;
            let ty = self.u16(o).unwrap_or(0);
            let n = self.u32(o + 4).unwrap_or(0);
            let item_off = self.u32(o + 8).unwrap_or(0);
            children.push(Block::node(
                format!("{}: {n} at 0x{item_off:X}", map_type_name(ty)),
                span(o, o + 12),
                vec![
                    Block::leaf(
                        format!("Type: 0x{ty:04X} ({})", map_type_name(ty)),
                        span(o, o + 2),
                    ),
                    Block::leaf("Unused", span(o + 2, o + 4)),
                    Block::leaf(format!("Size: {n}"), span(o + 4, o + 8)),
                    Block::leaf(format!("Offset: 0x{item_off:X}"), span(o + 8, o + 12)),
                ],
            ));
        }
        let end = (off + 4 + count * 12).min(self.data.len());
        Some(Block::node("Map list", span(off, end), children).expanded())
    }
}

type Strings = Vec<Option<(ByteRange, String)>>;

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

/// Number of whole entries of a table that fit inside the file, capped.
fn table_count(file_len: usize, size: u32, off: u32, entry_size: usize) -> usize {
    let off = off as usize;
    if off >= file_len {
        return 0;
    }
    ((file_len - off) / entry_size)
        .min(size as usize)
        .min(MAX_ENTRIES)
}

fn string(strings: &Strings, idx: u32) -> Option<&str> {
    strings
        .get(idx as usize)
        .and_then(Option::as_ref)
        .map(|(_, s)| s.as_str())
}

fn string_label(strings: &Strings, idx: u32) -> String {
    match string(strings, idx) {
        Some(s) => quote(s),
        None => "(invalid)".to_owned(),
    }
}

fn truncate(s: &str) -> String {
    if s.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = s.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        s.to_owned()
    }
}

fn quote(s: &str) -> String {
    let escaped: String = s.escape_debug().collect();
    format!("\"{}\"", truncate(&escaped))
}

/// Reads an unsigned LEB128 value (at most 5 bytes, as DEX requires).
/// Returns the value and the number of bytes consumed.
fn read_uleb128(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    for i in 0..5 {
        let byte = *data.get(offset.checked_add(i)?)?;
        result |= ((byte & 0x7F) as u32) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Decodes Modified UTF-8 (Java/DEX flavor: NUL as C0 80, supplementary
/// characters as surrogate pairs). Malformed sequences become U+FFFD.
fn decode_mutf8(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let cont = |k: usize| bytes.get(i + k).copied().filter(|b| b & 0xC0 == 0x80);
        if b0 < 0x80 {
            units.push(b0 as u16);
            i += 1;
        } else if b0 & 0xE0 == 0xC0 {
            match cont(1) {
                Some(b1) => {
                    units.push((((b0 & 0x1F) as u16) << 6) | (b1 & 0x3F) as u16);
                    i += 2;
                }
                None => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else if b0 & 0xF0 == 0xE0 {
            match (cont(1), cont(2)) {
                (Some(b1), Some(b2)) => {
                    units.push(
                        (((b0 & 0x0F) as u16) << 12)
                            | (((b1 & 0x3F) as u16) << 6)
                            | (b2 & 0x3F) as u16,
                    );
                    i += 3;
                }
                _ => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else {
            units.push(0xFFFD);
            i += 1;
        }
    }
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

fn access_flags(flags: u32) -> String {
    const NAMES: [(u32, &str); 10] = [
        (0x1, "public"),
        (0x2, "private"),
        (0x4, "protected"),
        (0x8, "static"),
        (0x10, "final"),
        (0x200, "interface"),
        (0x400, "abstract"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(" ")
    }
}

fn map_type_name(ty: u16) -> &'static str {
    match ty {
        0x0000 => "header_item",
        0x0001 => "string_id_item",
        0x0002 => "type_id_item",
        0x0003 => "proto_id_item",
        0x0004 => "field_id_item",
        0x0005 => "method_id_item",
        0x0006 => "class_def_item",
        0x0007 => "call_site_id_item",
        0x0008 => "method_handle_item",
        0x1000 => "map_list",
        0x1001 => "type_list",
        0x1002 => "annotation_set_ref_list",
        0x1003 => "annotation_set_item",
        0x2000 => "class_data_item",
        0x2001 => "code_item",
        0x2002 => "string_data_item",
        0x2003 => "debug_info_item",
        0x2004 => "annotation_item",
        0x2005 => "encoded_array_item",
        0x2006 => "annotations_directory_item",
        0xF000 => "hiddenapi_class_data_item",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRINGS: [&str; 9] = [
        "I",
        "LFoo;",
        "Ljava/lang/Object;",
        "V",
        "VI",
        "bar",
        "caf\u{e9}",
        "count",
        "Foo.java",
    ];

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn encode_mutf8(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            match u {
                0x01..=0x7F => out.push(u as u8),
                0x00 | 0x80..=0x7FF => {
                    out.push(0xC0 | (u >> 6) as u8);
                    out.push(0x80 | (u & 0x3F) as u8);
                }
                _ => {
                    out.push(0xE0 | (u >> 12) as u8);
                    out.push(0x80 | ((u >> 6) & 0x3F) as u8);
                    out.push(0x80 | (u & 0x3F) as u8);
                }
            }
        }
        out
    }

    struct Layout {
        string_ids: usize,
        type_ids: usize,
        proto_ids: usize,
        field_ids: usize,
        method_ids: usize,
        class_defs: usize,
        data: usize,
        string_data: Vec<usize>,
        map: usize,
    }

    /// Builds a small DEX with one class `LFoo;` extending Object, one field
    /// `count:I` and one method `bar(I)V`.
    fn build_dex() -> (Vec<u8>, Layout) {
        let string_ids = HEADER_LEN;
        let type_ids = string_ids + STRINGS.len() * 4;
        let proto_ids = type_ids + 4 * 4;
        let field_ids = proto_ids + 12;
        let method_ids = field_ids + 8;
        let class_defs = method_ids + 8;
        let data_off = class_defs + 32;

        let mut d = vec![0u8; data_off];
        let mut string_data = Vec::new();
        for s in STRINGS {
            string_data.push(d.len());
            d.push(s.encode_utf16().count() as u8); // ULEB128, < 128
            d.extend(encode_mutf8(s));
            d.push(0);
        }
        while d.len() % 4 != 0 {
            d.push(0);
        }
        let type_list = d.len();
        d.extend(1u32.to_le_bytes());
        d.extend(0u16.to_le_bytes()); // I
        d.extend(0u16.to_le_bytes()); // padding
        let map = d.len();
        let map_items: [(u16, u32, usize); 4] = [
            (0x0000, 1, 0),
            (0x0001, STRINGS.len() as u32, string_ids),
            (0x2002, STRINGS.len() as u32, string_data[0]),
            (0x1000, 1, map),
        ];
        d.extend((map_items.len() as u32).to_le_bytes());
        for (ty, n, off) in map_items {
            d.extend(ty.to_le_bytes());
            d.extend(0u16.to_le_bytes());
            d.extend(n.to_le_bytes());
            d.extend((off as u32).to_le_bytes());
        }
        let file_size = d.len();

        d[0..8].copy_from_slice(b"dex\n035\0");
        put_u32(&mut d, 8, 0xDEADBEEF);
        for (k, b) in d[12..32].iter_mut().enumerate() {
            *b = k as u8;
        }
        put_u32(&mut d, 32, file_size as u32);
        put_u32(&mut d, 36, HEADER_LEN as u32);
        put_u32(&mut d, 40, ENDIAN_CONSTANT);
        put_u32(&mut d, 52, map as u32);
        let tables = [
            (56, STRINGS.len(), string_ids),
            (64, 4, type_ids),
            (72, 1, proto_ids),
            (80, 1, field_ids),
            (88, 1, method_ids),
            (96, 1, class_defs),
            (104, file_size - data_off, data_off),
        ];
        for (o, n, off) in tables {
            put_u32(&mut d, o, n as u32);
            put_u32(&mut d, o + 4, off as u32);
        }

        for (i, off) in string_data.iter().enumerate() {
            put_u32(&mut d, string_ids + i * 4, *off as u32);
        }
        // type_ids: I, LFoo;, Ljava/lang/Object;, V
        for (i, s) in [0u32, 1, 2, 3].iter().enumerate() {
            put_u32(&mut d, type_ids + i * 4, *s);
        }
        // proto: shorty "VI", return V (type 3), params type_list
        put_u32(&mut d, proto_ids, 4);
        put_u32(&mut d, proto_ids + 4, 3);
        put_u32(&mut d, proto_ids + 8, type_list as u32);
        // field: LFoo;->count:I
        d[field_ids..field_ids + 2].copy_from_slice(&1u16.to_le_bytes());
        d[field_ids + 2..field_ids + 4].copy_from_slice(&0u16.to_le_bytes());
        put_u32(&mut d, field_ids + 4, 7);
        // method: LFoo;->bar(I)V
        d[method_ids..method_ids + 2].copy_from_slice(&1u16.to_le_bytes());
        d[method_ids + 2..method_ids + 4].copy_from_slice(&0u16.to_le_bytes());
        put_u32(&mut d, method_ids + 4, 5);
        // class_def
        put_u32(&mut d, class_defs, 1);
        put_u32(&mut d, class_defs + 4, 0x1);
        put_u32(&mut d, class_defs + 8, 2);
        put_u32(&mut d, class_defs + 16, 8);

        (
            d,
            Layout {
                string_ids,
                type_ids,
                proto_ids,
                field_ids,
                method_ids,
                class_defs,
                data: data_off,
                string_data,
                map,
            },
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

    fn r(start: usize, end: usize) -> ByteRange {
        span(start, end)
    }

    fn assert_nested(blocks: &[Block], parent: Option<ByteRange>) {
        for b in blocks {
            assert!(b.range.start <= b.range.end, "{}", b.label);
            if let Some(p) = parent {
                assert!(
                    b.range.start >= p.start && b.range.end <= p.end,
                    "{} {:?} outside {:?}",
                    b.label,
                    b.range,
                    p
                );
            }
            assert_nested(&b.children, Some(b.range));
        }
    }

    #[test]
    fn matches_dex_magic() {
        let (data, _) = build_dex();
        assert!(DexDissector.matches(&data));
        assert!(DexDissector.matches(b"dex\n039\0"));
    }

    #[test]
    fn does_not_match_non_dex_data() {
        assert!(!DexDissector.matches(b""));
        assert!(!DexDissector.matches(b"dex\n"));
        assert!(!DexDissector.matches(b"dex\n03"));
        assert!(!DexDissector.matches(b"dex\nabc\0"));
        assert!(!DexDissector.matches(b"dex\n035\n"));
        assert!(!DexDissector.matches(b"dey\n035\0"));
        assert!(!DexDissector.matches(b"not a dex file"));
    }

    #[test]
    fn dissect_returns_empty_for_bad_magic() {
        assert!(DexDissector.dissect(b"dex\n").is_empty());
        assert!(DexDissector.dissect(b"").is_empty());
    }

    #[test]
    fn dissect_truncated_header_yields_partial_header_only() {
        let (data, _) = build_dex();
        let blocks = DexDissector.dissect(&data[..20]);
        assert_eq!(blocks.len(), 1);
        let header = find_block(&blocks, "DEX header");
        assert_eq!(header.range, r(0, 20));
        find_block(&header.children, "Checksum (Adler-32): 0xDEADBEEF");
        assert!(header.children.iter().all(|b| b.range.end <= 20));
    }

    #[test]
    fn dissect_never_panics_on_any_truncation() {
        let (data, _) = build_dex();
        for len in 0..data.len() {
            let blocks = DexDissector.dissect(&data[..len]);
            assert_nested(&blocks, Some(r(0, len)));
        }
    }

    #[test]
    fn dissect_survives_garbage_offsets() {
        let (mut data, l) = build_dex();
        put_u32(&mut data, 56, u32::MAX);
        put_u32(&mut data, 60, u32::MAX - 2);
        put_u32(&mut data, 88, u32::MAX);
        put_u32(&mut data, l.proto_ids + 8, u32::MAX);
        put_u32(&mut data, l.map, u32::MAX);
        put_u32(&mut data, l.string_ids, u32::MAX);
        let blocks = DexDissector.dissect(&data);
        assert_nested(&blocks, Some(r(0, data.len())));
    }

    #[test]
    fn dissect_parses_header() {
        let (data, l) = build_dex();
        let blocks = DexDissector.dissect(&data);
        let header = find_block(&blocks, "DEX header");
        assert_eq!(header.range, r(0, HEADER_LEN));
        assert!(header.default_expanded);
        let c = &header.children;
        assert_eq!(
            find_block(c, "Magic: dex\\n035\\0 (version 035)").range,
            r(0, 8)
        );
        assert_eq!(
            find_block(
                c,
                "Signature (SHA-1): 000102030405060708090a0b0c0d0e0f10111213"
            )
            .range,
            r(12, 32)
        );
        assert_eq!(
            find_block(c, &format!("File size: {}", data.len())).range,
            r(32, 36)
        );
        assert_eq!(find_block(c, "Header size: 112").range, r(36, 40));
        assert_eq!(
            find_block(c, "Endian tag: 0x12345678 (little-endian)").range,
            r(40, 44)
        );
        assert_eq!(
            find_block(c, &format!("Map offset: 0x{:X}", l.map)).range,
            r(52, 56)
        );
        assert_eq!(find_block(c, "string_ids size: 9").range, r(56, 60));
        assert_eq!(
            find_block(c, &format!("class_defs offset: 0x{:X}", l.class_defs)).range,
            r(100, 104)
        );
        assert_eq!(
            find_block(c, &format!("Data offset: 0x{:X}", l.data)).range,
            r(108, 112)
        );
    }

    #[test]
    fn dissect_parses_id_tables() {
        let (data, l) = build_dex();
        let blocks = DexDissector.dissect(&data);
        assert_nested(&blocks, None);

        let strings = find_block(&blocks, "string_ids (9 entries)");
        assert_eq!(strings.range, r(l.string_ids, l.string_ids + 36));
        let s6 = find_block(
            &strings.children,
            &format!("string_ids[6]: 0x{:X} \"café\"", l.string_data[6]),
        );
        assert_eq!(s6.range, r(l.string_ids + 24, l.string_ids + 28));

        let types = find_block(&blocks, "type_ids (4 entries)");
        assert_eq!(types.range, r(l.type_ids, l.type_ids + 16));
        find_block(&types.children, "type_ids[1]: string 1 \"LFoo;\"");

        let protos = find_block(&blocks, "proto_ids (1 entries)");
        assert_eq!(protos.range, r(l.proto_ids, l.proto_ids + 12));
        let p = find_block(&protos.children, "proto_ids[0]: (I)V");
        find_block(&p.children, "Shorty: string 4 \"VI\"");
        find_block(&p.children, "Return type: type 3 (V)");

        let fields = find_block(&blocks, "field_ids (1 entries)");
        let f = find_block(&fields.children, "field_ids[0]: LFoo;->count:I");
        assert_eq!(f.range, r(l.field_ids, l.field_ids + 8));
        assert_eq!(
            find_block(&f.children, "Name: string 7 \"count\"").range,
            r(l.field_ids + 4, l.field_ids + 8)
        );

        let methods = find_block(&blocks, "method_ids (1 entries)");
        let m = find_block(&methods.children, "method_ids[0]: LFoo;->bar(I)V");
        assert_eq!(m.range, r(l.method_ids, l.method_ids + 8));

        let classes = find_block(&blocks, "class_defs (1 entries)");
        let c = find_block(&classes.children, "class_defs[0]: LFoo;");
        assert_eq!(c.range, r(l.class_defs, l.class_defs + 32));
        find_block(&c.children, "Access flags: 0x1 (public)");
        find_block(&c.children, "Superclass: type 2 (Ljava/lang/Object;)");
        assert_eq!(
            find_block(&c.children, "Source file: string 8 \"Foo.java\"").range,
            r(l.class_defs + 16, l.class_defs + 20)
        );
    }

    #[test]
    fn dissect_parses_data_strings_and_map() {
        let (data, l) = build_dex();
        let blocks = DexDissector.dissect(&data);
        let data_block = find_block(&blocks, &format!("Data ({} bytes)", data.len() - l.data));
        assert_eq!(data_block.range, r(l.data, data.len()));

        let sd = find_block(&data_block.children, "String data (9 strings)");
        let cafe = find_block(&sd.children, "string_data[6]: \"café\"");
        // 1 length byte + "caf" + 2-byte é + NUL
        assert_eq!(cafe.range, r(l.string_data[6], l.string_data[6] + 7));

        let map = find_block(&data_block.children, "Map list");
        assert_eq!(map.range, r(l.map, l.map + 4 + 4 * 12));
        find_block(&map.children, "Size: 4");
        let item = find_block(
            &map.children,
            &format!("string_data_item: 9 at 0x{:X}", l.string_data[0]),
        );
        assert_eq!(item.range, r(l.map + 4 + 24, l.map + 4 + 36));
        find_block(&item.children, "Type: 0x2002 (string_data_item)");
    }

    #[test]
    fn decodes_uleb128() {
        assert_eq!(read_uleb128(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_uleb128(&[0x7F], 0), Some((127, 1)));
        assert_eq!(read_uleb128(&[0x80, 0x7F], 0), Some((16256, 2)));
        assert_eq!(read_uleb128(&[0x80], 0), None);
        assert_eq!(read_uleb128(&[0xFF; 6], 0), None);
    }

    #[test]
    fn decodes_mutf8() {
        assert_eq!(decode_mutf8(b"abc"), "abc");
        assert_eq!(decode_mutf8(&[0xC0, 0x80]), "\0");
        // U+1F600 as a surrogate pair, each half 3-byte encoded.
        assert_eq!(encode_mutf8("\u{1F600}").len(), 6);
        assert_eq!(decode_mutf8(&encode_mutf8("x\u{1F600}y")), "x\u{1F600}y");
        assert_eq!(decode_mutf8(&[0xE0, 0x80]), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn identify_returns_dex() {
        let (data, _) = build_dex();
        assert_eq!(super::super::identify(&data), "DEX");
    }
}
