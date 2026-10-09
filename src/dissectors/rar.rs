use super::{Block, ByteRange, Dissector};

const RAR4_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
const RAR5_SIGNATURE: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
/// Maximum number of top-level headers/blocks shown before giving up.
const MAX_ENTRIES: usize = 10_000;
/// Maximum number of extra-area records shown per RAR 5 header.
const MAX_EXTRA_RECORDS: usize = 256;
/// RAR 5 headers are limited to 2 MiB by the format specification.
const MAX_RAR5_HEADER_SIZE: u64 = 2 * 1024 * 1024;
const MAX_LABEL_CHARS: usize = 200;

pub struct RarDissector;

impl Dissector for RarDissector {
    fn name(&self) -> &'static str {
        "RAR"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(RAR5_SIGNATURE) || data.starts_with(RAR4_SIGNATURE)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        if data.starts_with(RAR5_SIGNATURE) {
            dissect_rar5(data)
        } else if data.starts_with(RAR4_SIGNATURE) {
            dissect_rar4(data)
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn leaf(label: impl Into<String>, start: usize, end: usize) -> Block {
    Block::leaf(label, range(start, end))
}

fn to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
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

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn display_name(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = text.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        text.into_owned()
    }
}

/// Formats `value` as hex followed by the names of the set bits in `table`.
fn flag_list(value: u64, width: usize, table: &[(u64, &str)]) -> String {
    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        format!("0x{value:0width$X}")
    } else {
        format!("0x{value:0width$X} ({})", names.join(", "))
    }
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

fn format_unix_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn format_filetime(ft: u64) -> String {
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    format_unix_time(secs)
}

fn format_dos_time(value: u32) -> String {
    let time = value & 0xFFFF;
    let date = value >> 16;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        1980 + (date >> 9),
        (date >> 5) & 0x0F,
        date & 0x1F,
        time >> 11,
        (time >> 5) & 0x3F,
        (time & 0x1F) * 2
    )
}

fn crc_status(stored: u32, computed: Option<u32>, width: usize) -> String {
    match computed {
        Some(c) if c == stored => "OK".to_string(),
        Some(c) => format!("mismatch, computed 0x{c:0width$X}"),
        None => "header truncated".to_string(),
    }
}

fn method_name(method: u64) -> &'static str {
    match method {
        0 => "store",
        1 => "fastest",
        2 => "fast",
        3 => "normal",
        4 => "good",
        5 => "best",
        _ => "unknown",
    }
}

fn format_bytes_size(size: u64) -> String {
    if size >= 1 << 30 && size.is_multiple_of(1 << 30) {
        format!("{} GiB", size >> 30)
    } else if size >= 1 << 20 && size.is_multiple_of(1 << 20) {
        format!("{} MiB", size >> 20)
    } else if size >= 1 << 10 && size.is_multiple_of(1 << 10) {
        format!("{} KiB", size >> 10)
    } else {
        format!("{size} bytes")
    }
}

/// Pushes trailing leaves after the archive structure has been walked.
fn push_tail(blocks: &mut Vec<Block>, label: &str, from: usize, len: usize) {
    if from < len {
        blocks.push(leaf(label, from, len));
    }
}

// ---------------------------------------------------------------------------
// RAR 4.x
// ---------------------------------------------------------------------------

const RAR4_MARK: u8 = 0x72;
const RAR4_MAIN: u8 = 0x73;
const RAR4_FILE: u8 = 0x74;
const RAR4_NEWSUB: u8 = 0x7A;
const RAR4_ENDARC: u8 = 0x7B;

const RAR4_LONG_BLOCK: u16 = 0x8000;
const RAR4_MAIN_PASSWORD: u16 = 0x0080;
const RAR4_FILE_LARGE: u16 = 0x0100;
const RAR4_FILE_UNICODE: u16 = 0x0200;
const RAR4_FILE_SALT: u16 = 0x0400;
const RAR4_FILE_EXTTIME: u16 = 0x1000;
const RAR4_END_DATACRC: u16 = 0x0002;
const RAR4_END_VOLNUMBER: u16 = 0x0008;

fn rar4_type_name(typ: u8) -> &'static str {
    match typ {
        RAR4_MARK => "MARK",
        RAR4_MAIN => "MAIN",
        RAR4_FILE => "FILE",
        0x75 => "COMMENT",
        0x76 => "AV",
        0x77 => "SUB",
        0x78 => "PROTECT",
        0x79 => "SIGN",
        RAR4_NEWSUB => "NEWSUB",
        RAR4_ENDARC => "ENDARC",
        _ => "unknown",
    }
}

fn rar4_flag_table(typ: u8) -> &'static [(u64, &'static str)] {
    match typ {
        RAR4_MAIN => &[
            (0x0001, "VOLUME"),
            (0x0002, "COMMENT"),
            (0x0004, "LOCK"),
            (0x0008, "SOLID"),
            (0x0010, "NEWNUMBERING"),
            (0x0020, "AV"),
            (0x0040, "PROTECT"),
            (0x0080, "PASSWORD"),
            (0x0100, "FIRSTVOLUME"),
            (0x4000, "SKIP_IF_UNKNOWN"),
            (0x8000, "LONG_BLOCK"),
        ],
        RAR4_FILE | RAR4_NEWSUB => &[
            (0x0001, "SPLIT_BEFORE"),
            (0x0002, "SPLIT_AFTER"),
            (0x0004, "PASSWORD"),
            (0x0008, "COMMENT"),
            (0x0010, "SOLID"),
            (0x0100, "LARGE"),
            (0x0200, "UNICODE"),
            (0x0400, "SALT"),
            (0x0800, "VERSION"),
            (0x1000, "EXTTIME"),
            (0x4000, "SKIP_IF_UNKNOWN"),
            (0x8000, "LONG_BLOCK"),
        ],
        RAR4_ENDARC => &[
            (0x0001, "NEXT_VOLUME"),
            (0x0002, "DATACRC"),
            (0x0004, "REVSPACE"),
            (0x0008, "VOLNUMBER"),
            (0x4000, "SKIP_IF_UNKNOWN"),
            (0x8000, "LONG_BLOCK"),
        ],
        _ => &[(0x4000, "SKIP_IF_UNKNOWN"), (0x8000, "LONG_BLOCK")],
    }
}

fn rar4_host_os(os: u8) -> &'static str {
    match os {
        0 => "MS-DOS",
        1 => "OS/2",
        2 => "Windows",
        3 => "Unix",
        4 => "Mac OS",
        5 => "BeOS",
        _ => "unknown",
    }
}

fn rar4_dictionary(flags: u16) -> String {
    match (flags >> 5) & 7 {
        7 => "directory".to_string(),
        n => format!("{} KiB", 64u32 << n),
    }
}

fn dissect_rar4(data: &[u8]) -> Vec<Block> {
    let len = data.len();
    let mut blocks = vec![
        Block::node(
            "Signature: RAR 4.x",
            range(0, 7),
            vec![
                leaf("Header CRC: 0x6152 (fixed)", 0, 2),
                leaf("Header type: 0x72 (MARK)", 2, 3),
                leaf("Header flags: 0x1A21 (fixed)", 3, 5),
                leaf("Header size: 7", 5, 7),
            ],
        )
        .expanded(),
    ];

    let mut offset = 7;
    let mut count = 0;
    while offset < len {
        if count >= MAX_ENTRIES {
            blocks.push(leaf(
                format!("Remaining data ({MAX_ENTRIES}-block limit reached)"),
                offset,
                len,
            ));
            break;
        }
        let Some(parsed) = rar4_block(data, offset) else {
            blocks.push(leaf("Unparsed data", offset, len));
            break;
        };
        count += 1;
        let next = parsed.next;
        blocks.push(parsed.block);
        match parsed.stop {
            Stop::Continue => {}
            Stop::EndOfArchive => {
                push_tail(&mut blocks, "Data after end of archive", next, len);
                break;
            }
            Stop::Encrypted => {
                push_tail(&mut blocks, "Encrypted headers", next, len);
                break;
            }
        }
        if next <= offset {
            break;
        }
        offset = next;
    }
    blocks
}

#[derive(Clone, Copy, PartialEq)]
enum Stop {
    Continue,
    EndOfArchive,
    Encrypted,
}

struct Parsed {
    block: Block,
    next: usize,
    stop: Stop,
}

struct Rar4Header {
    fields: Vec<Block>,
    label: String,
    data_size: u64,
    data_label: &'static str,
    stop: Stop,
}

fn rar4_block(data: &[u8], offset: usize) -> Option<Parsed> {
    let len = data.len();
    let crc = read_u16(data, offset)?;
    let typ = read_u8(data, offset + 2)?;
    let flags = read_u16(data, offset + 3)?;
    let size = read_u16(data, offset + 5)? as usize;
    if size < 7 {
        return None;
    }
    let declared_end = offset + size;
    let complete = declared_end <= len;
    let header_end = declared_end.min(len);
    // All field reads go through `hdr`, so they can never leave the header.
    let hdr = &data[..header_end];

    let computed = complete.then(|| crc32(&data[offset + 2..header_end]) & 0xFFFF);
    let mut info = Rar4Header {
        fields: vec![
            leaf(
                format!(
                    "Header CRC: 0x{crc:04X} ({})",
                    crc_status(crc as u32, computed, 4)
                ),
                offset,
                offset + 2,
            ),
            leaf(
                format!("Header type: 0x{typ:02X} ({})", rar4_type_name(typ)),
                offset + 2,
                offset + 3,
            ),
            leaf(
                format!(
                    "Header flags: {}",
                    flag_list(flags as u64, 4, rar4_flag_table(typ))
                ),
                offset + 3,
                offset + 5,
            ),
            leaf(format!("Header size: {size}"), offset + 5, offset + 7),
        ],
        label: match typ {
            RAR4_MAIN => "Main archive header".to_string(),
            0x75 => "Comment block".to_string(),
            0x76 => "Authenticity verification block".to_string(),
            0x77 => "Subblock".to_string(),
            0x78 => "Recovery record block".to_string(),
            0x79 => "Signature block".to_string(),
            RAR4_ENDARC => "End of archive".to_string(),
            _ => format!("Unknown block (0x{typ:02X})"),
        },
        data_size: 0,
        data_label: "Additional data",
        stop: Stop::Continue,
    };

    let mut pos = offset + 7;
    match typ {
        RAR4_FILE | RAR4_NEWSUB => {
            let _ = rar4_file_fields(hdr, typ, flags, &mut pos, &mut info);
        }
        RAR4_MAIN => {
            if let Some(v) = read_u16(hdr, pos) {
                info.fields
                    .push(leaf(format!("HighPosAV: {v}"), pos, pos + 2));
                pos += 2;
                if let Some(v) = read_u32(hdr, pos) {
                    info.fields.push(leaf(format!("PosAV: {v}"), pos, pos + 4));
                    pos += 4;
                }
            }
            if flags & RAR4_MAIN_PASSWORD != 0 {
                info.stop = Stop::Encrypted;
            }
        }
        RAR4_ENDARC => {
            info.stop = Stop::EndOfArchive;
            if flags & RAR4_LONG_BLOCK != 0 {
                rar4_add_size(hdr, &mut pos, &mut info);
            }
            if flags & RAR4_END_DATACRC != 0
                && let Some(v) = read_u32(hdr, pos)
            {
                info.fields
                    .push(leaf(format!("Archive data CRC32: 0x{v:08X}"), pos, pos + 4));
                pos += 4;
            }
            if flags & RAR4_END_VOLNUMBER != 0
                && let Some(v) = read_u16(hdr, pos)
            {
                info.fields
                    .push(leaf(format!("Volume number: {v}"), pos, pos + 2));
                pos += 2;
            }
        }
        _ => {
            if flags & RAR4_LONG_BLOCK != 0 {
                rar4_add_size(hdr, &mut pos, &mut info);
            }
        }
    }
    if pos < header_end {
        info.fields.push(leaf("Header data", pos, header_end));
    }

    let mut children =
        vec![Block::node("Header", range(offset, header_end), info.fields).expanded()];
    let next = if complete {
        let data_end = (declared_end as u64).saturating_add(info.data_size);
        let data_end = to_usize(data_end.min(len as u64));
        if data_end > declared_end {
            children.push(leaf(info.data_label, declared_end, data_end));
        }
        data_end
    } else {
        len
    };

    Some(Parsed {
        block: Block::node(info.label, range(offset, next), children),
        next,
        stop: info.stop,
    })
}

fn rar4_add_size(hdr: &[u8], pos: &mut usize, info: &mut Rar4Header) {
    if let Some(v) = read_u32(hdr, *pos) {
        info.fields
            .push(leaf(format!("ADD_SIZE: {v}"), *pos, *pos + 4));
        info.data_size = v as u64;
        *pos += 4;
    }
}

fn rar4_file_fields(
    hdr: &[u8],
    typ: u8,
    flags: u16,
    pos: &mut usize,
    info: &mut Rar4Header,
) -> Option<()> {
    let is_file = typ == RAR4_FILE;
    info.label = if is_file {
        "File".into()
    } else {
        "Service".into()
    };
    info.data_label = if is_file {
        "Packed data"
    } else {
        "Service data"
    };
    let fields = &mut info.fields;
    let mut p = *pos;

    let pack = read_u32(hdr, p)?;
    fields.push(leaf(format!("Packed size: {pack}"), p, p + 4));
    info.data_size = pack as u64;
    p += 4;
    let unp = read_u32(hdr, p)?;
    fields.push(leaf(format!("Unpacked size: {unp}"), p, p + 4));
    p += 4;
    let os = read_u8(hdr, p)?;
    fields.push(leaf(
        format!("Host OS: {os} ({})", rar4_host_os(os)),
        p,
        p + 1,
    ));
    p += 1;
    let file_crc = read_u32(hdr, p)?;
    fields.push(leaf(format!("File CRC32: 0x{file_crc:08X}"), p, p + 4));
    p += 4;
    let ftime = read_u32(hdr, p)?;
    fields.push(leaf(
        format!("Modified time: {}", format_dos_time(ftime)),
        p,
        p + 4,
    ));
    p += 4;
    let ver = read_u8(hdr, p)?;
    fields.push(leaf(
        format!("Unpack version: {ver} ({}.{})", ver / 10, ver % 10),
        p,
        p + 1,
    ));
    p += 1;
    let method = read_u8(hdr, p)?;
    fields.push(leaf(
        format!(
            "Method: 0x{method:02X} ({})",
            method_name(method.wrapping_sub(0x30) as u64)
        ),
        p,
        p + 1,
    ));
    p += 1;
    let name_size = read_u16(hdr, p)? as usize;
    fields.push(leaf(format!("Name size: {name_size}"), p, p + 2));
    p += 2;
    let attr = read_u32(hdr, p)?;
    fields.push(leaf(format!("Attributes: 0x{attr:08X}"), p, p + 4));
    p += 4;
    fields.push(leaf(
        format!("Dictionary: {}", rar4_dictionary(flags)),
        *pos - 4,
        *pos - 2,
    ));
    *pos = p;

    if flags & RAR4_FILE_LARGE != 0 {
        let high_pack = read_u32(hdr, p)?;
        fields.push(leaf(format!("High packed size: {high_pack}"), p, p + 4));
        info.data_size |= (high_pack as u64) << 32;
        p += 4;
        let high_unp = read_u32(hdr, p)?;
        fields.push(leaf(format!("High unpacked size: {high_unp}"), p, p + 4));
        p += 4;
        *pos = p;
    }

    let name_bytes = hdr.get(p..p.checked_add(name_size)?)?;
    let (name, note) = if flags & RAR4_FILE_UNICODE != 0 {
        match name_bytes.iter().position(|&b| b == 0) {
            Some(nul) => (display_name(&name_bytes[..nul]), " (plus Unicode encoding)"),
            None => (display_name(name_bytes), ""),
        }
    } else {
        (display_name(name_bytes), "")
    };
    fields.push(leaf(format!("File name: {name}{note}"), p, p + name_size));
    p += name_size;
    *pos = p;
    info.label = if !is_file {
        format!("Service: {name}")
    } else if (flags >> 5) & 7 == 7 {
        format!("Directory: {name}")
    } else {
        format!("File: {name}")
    };

    if flags & RAR4_FILE_SALT != 0 {
        let salt = hdr.get(p..p + 8)?;
        fields.push(leaf(format!("Salt: {}", hex_bytes(salt)), p, p + 8));
        p += 8;
        *pos = p;
    }
    if flags & RAR4_FILE_EXTTIME != 0 && p < hdr.len() {
        fields.push(leaf("Extended time", p, hdr.len()));
        *pos = hdr.len();
    }
    Some(())
}

// ---------------------------------------------------------------------------
// RAR 5.0
// ---------------------------------------------------------------------------

const RAR5_MAIN: u64 = 1;
const RAR5_FILE: u64 = 2;
const RAR5_SERVICE: u64 = 3;
const RAR5_ENCRYPTION: u64 = 4;
const RAR5_END: u64 = 5;

const RAR5_HFL_EXTRA: u64 = 0x0001;
const RAR5_HFL_DATA: u64 = 0x0002;

const RAR5_HEADER_FLAGS: &[(u64, &str)] = &[
    (0x0001, "extra area"),
    (0x0002, "data area"),
    (0x0004, "skip if unknown"),
    (0x0008, "split before"),
    (0x0010, "split after"),
    (0x0020, "child"),
    (0x0040, "inherited"),
];

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn vint(&mut self) -> Option<(u64, usize, usize)> {
        let start = self.pos;
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            if shift < 64 {
                value |= ((b & 0x7F) as u64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some((value, start, self.pos));
            }
            if self.pos - start >= 10 {
                return None;
            }
        }
    }

    fn bytes(&mut self, n: usize) -> Option<(&[u8], usize, usize)> {
        let start = self.pos;
        let end = start.checked_add(n)?;
        let slice = self.data.get(start..end)?;
        self.pos = end;
        Some((slice, start, end))
    }

    fn u8(&mut self) -> Option<(u8, usize, usize)> {
        let (b, s, e) = self.bytes(1)?;
        Some((b[0], s, e))
    }

    fn u32(&mut self) -> Option<(u32, usize, usize)> {
        let v = read_u32(self.data, self.pos)?;
        self.pos += 4;
        Some((v, self.pos - 4, self.pos))
    }

    fn u64(&mut self) -> Option<(u64, usize, usize)> {
        let v = read_u64(self.data, self.pos)?;
        self.pos += 8;
        Some((v, self.pos - 8, self.pos))
    }

    /// Reads a vint and pushes a leaf labeled by `label(value)`.
    fn vint_field(
        &mut self,
        fields: &mut Vec<Block>,
        label: impl FnOnce(u64) -> String,
    ) -> Option<u64> {
        let (v, s, e) = self.vint()?;
        fields.push(leaf(label(v), s, e));
        Some(v)
    }
}

fn rar5_type_name(typ: u64) -> &'static str {
    match typ {
        RAR5_MAIN => "main archive",
        RAR5_FILE => "file",
        RAR5_SERVICE => "service",
        RAR5_ENCRYPTION => "archive encryption",
        RAR5_END => "end of archive",
        _ => "unknown",
    }
}

fn dissect_rar5(data: &[u8]) -> Vec<Block> {
    let len = data.len();
    let mut blocks = vec![leaf("Signature: RAR 5.0", 0, RAR5_SIGNATURE.len())];
    let mut offset = RAR5_SIGNATURE.len();
    let mut count = 0;
    while offset < len {
        if count >= MAX_ENTRIES {
            blocks.push(leaf(
                format!("Remaining data ({MAX_ENTRIES}-header limit reached)"),
                offset,
                len,
            ));
            break;
        }
        let Some(parsed) = rar5_header(data, offset) else {
            blocks.push(leaf("Unparsed data", offset, len));
            break;
        };
        count += 1;
        let next = parsed.next;
        blocks.push(parsed.block);
        match parsed.stop {
            Stop::Continue => {}
            Stop::EndOfArchive => {
                push_tail(&mut blocks, "Data after end of archive", next, len);
                break;
            }
            Stop::Encrypted => {
                push_tail(&mut blocks, "Encrypted headers and data", next, len);
                break;
            }
        }
        if next <= offset {
            break;
        }
        offset = next;
    }
    blocks
}

fn rar5_header(data: &[u8], offset: usize) -> Option<Parsed> {
    let len = data.len();
    let crc = read_u32(data, offset)?;
    let mut c = Cursor {
        data,
        pos: offset + 4,
    };
    let (size, size_start, size_end) = c.vint()?;
    if size == 0 || size > MAX_RAR5_HEADER_SIZE {
        return None;
    }
    let declared_end = size_end + size as usize;
    let complete = declared_end <= len;
    let header_end = declared_end.min(len);
    let computed = complete.then(|| crc32(&data[offset + 4..header_end]));

    let mut fields = vec![
        leaf(
            format!(
                "Header CRC32: 0x{crc:08X} ({})",
                crc_status(crc, computed, 8)
            ),
            offset,
            offset + 4,
        ),
        leaf(format!("Header size: {size}"), size_start, size_end),
    ];

    let mut c = Cursor {
        data: &data[..header_end],
        pos: size_end,
    };
    let mut label = "Header".to_string();
    let mut stop = Stop::Continue;
    let mut extra_size = 0u64;
    let mut data_size = 0u64;
    let mut typ = 0u64;
    let mut parsed_common = false;

    if let Some(t) = c.vint_field(&mut fields, |t| {
        format!("Header type: {t} ({})", rar5_type_name(t))
    }) {
        typ = t;
        label = match typ {
            RAR5_MAIN => "Main archive header".to_string(),
            RAR5_FILE => "File header".to_string(),
            RAR5_SERVICE => "Service header".to_string(),
            RAR5_ENCRYPTION => "Archive encryption header".to_string(),
            RAR5_END => "End of archive header".to_string(),
            _ => format!("Unknown header (type {typ})"),
        };
        if let Some(flags) = c.vint_field(&mut fields, |f| {
            format!("Header flags: {}", flag_list(f, 4, RAR5_HEADER_FLAGS))
        }) {
            parsed_common = true;
            if flags & RAR5_HFL_EXTRA != 0 {
                match c.vint_field(&mut fields, |v| format!("Extra area size: {v}")) {
                    Some(v) => extra_size = v,
                    None => parsed_common = false,
                }
            }
            if parsed_common && flags & RAR5_HFL_DATA != 0 {
                match c.vint_field(&mut fields, |v| format!("Data size: {v}")) {
                    Some(v) => data_size = v,
                    None => parsed_common = false,
                }
            }
        }
    }

    // The extra area occupies the last `extra_size` bytes of the header.
    let extra_start = if extra_size > 0 && extra_size <= (declared_end - c.pos) as u64 {
        declared_end - extra_size as usize
    } else {
        declared_end
    };

    if parsed_common {
        let mut tc = Cursor {
            data: &data[..extra_start.min(len)],
            pos: c.pos,
        };
        match typ {
            RAR5_MAIN => {
                let _ = rar5_main_fields(&mut tc, &mut fields);
            }
            RAR5_FILE | RAR5_SERVICE => {
                if let Some(name) = rar5_file_fields(&mut tc, &mut fields) {
                    label = name;
                }
                if typ == RAR5_SERVICE {
                    label = format!("Service: {label}");
                }
            }
            RAR5_ENCRYPTION => {
                let _ = rar5_encryption_fields(&mut tc, &mut fields);
                stop = Stop::Encrypted;
            }
            RAR5_END => {
                let _ = tc.vint_field(&mut fields, |f| {
                    format!(
                        "End of archive flags: {}",
                        flag_list(f, 2, &[(0x01, "not last volume")])
                    )
                });
                stop = Stop::EndOfArchive;
            }
            _ => {}
        }
        c.pos = tc.pos;
    }
    let body_end = extra_start.min(header_end);
    if c.pos < body_end {
        fields.push(leaf(
            if parsed_common && (1..=5).contains(&typ) {
                "Unparsed header bytes"
            } else {
                "Header data"
            },
            c.pos,
            body_end,
        ));
    }
    if extra_start < header_end {
        let records = rar5_extra_records(data, extra_start, header_end, typ);
        fields.push(
            Block::node(
                format!("Extra area ({extra_size} bytes)"),
                range(extra_start, header_end),
                records,
            )
            .expanded(),
        );
    }

    let mut children = vec![Block::node("Header", range(offset, header_end), fields).expanded()];
    let next = if complete {
        let data_end = to_usize(
            (declared_end as u64)
                .saturating_add(data_size)
                .min(len as u64),
        );
        if data_end > declared_end {
            let data_label = match typ {
                RAR5_FILE => "Packed data",
                RAR5_SERVICE => "Service data",
                _ => "Data area",
            };
            children.push(leaf(data_label, declared_end, data_end));
        }
        data_end
    } else {
        len
    };

    Some(Parsed {
        block: Block::node(label, range(offset, next), children)
            .expanded_if(typ == RAR5_ENCRYPTION),
        next,
        stop,
    })
}

fn rar5_main_fields(c: &mut Cursor, fields: &mut Vec<Block>) -> Option<()> {
    let flags = c.vint_field(fields, |f| {
        format!(
            "Archive flags: {}",
            flag_list(
                f,
                2,
                &[
                    (0x01, "volume"),
                    (0x02, "volume number"),
                    (0x04, "solid"),
                    (0x08, "recovery record"),
                    (0x10, "locked"),
                ],
            )
        )
    })?;
    if flags & 0x02 != 0 {
        c.vint_field(fields, |v| format!("Volume number: {v}"))?;
    }
    Some(())
}

/// Parses file/service header fields and returns the block label.
fn rar5_file_fields(c: &mut Cursor, fields: &mut Vec<Block>) -> Option<String> {
    let flags = c.vint_field(fields, |f| {
        format!(
            "File flags: {}",
            flag_list(
                f,
                2,
                &[
                    (0x01, "directory"),
                    (0x02, "mtime"),
                    (0x04, "CRC32"),
                    (0x08, "unknown size"),
                ],
            )
        )
    })?;
    c.vint_field(fields, |v| {
        if flags & 0x08 != 0 {
            format!("Unpacked size: {v} (unknown)")
        } else {
            format!("Unpacked size: {v}")
        }
    })?;
    c.vint_field(fields, |v| format!("Attributes: 0x{v:X}"))?;
    if flags & 0x02 != 0 {
        let (t, s, e) = c.u32()?;
        fields.push(leaf(
            format!("Modified time: {}", format_unix_time(t as i64)),
            s,
            e,
        ));
    }
    if flags & 0x04 != 0 {
        let (v, s, e) = c.u32()?;
        fields.push(leaf(format!("Data CRC32: 0x{v:08X}"), s, e));
    }
    let (ci, s, e) = c.vint()?;
    let version = ci & 0x3F;
    let solid = ci & 0x40 != 0;
    let method = (ci >> 7) & 0x07;
    let dict_base = (128u64 * 1024) << ((ci >> 10) & 0x1F);
    let dict = if version >= 1 {
        dict_base + dict_base / 32 * ((ci >> 15) & 0x1F)
    } else {
        dict_base
    };
    let version_name = match version {
        0 => "RAR 5.0",
        1 => "RAR 7.0",
        _ => "unknown",
    };
    let dict_label = if flags & 0x01 != 0 {
        format!(
            "Dictionary size: {} (unused for directories)",
            format_bytes_size(dict)
        )
    } else {
        format!("Dictionary size: {}", format_bytes_size(dict))
    };
    fields.push(Block::node(
        format!("Compression info: 0x{ci:X}"),
        range(s, e),
        vec![
            leaf(
                format!("Algorithm version: {version} ({version_name})"),
                s,
                e,
            ),
            leaf(format!("Solid: {}", if solid { "yes" } else { "no" }), s, e),
            leaf(format!("Method: {method} ({})", method_name(method)), s, e),
            leaf(dict_label, s, e),
        ],
    ));
    c.vint_field(fields, |v| {
        let os = match v {
            0 => "Windows",
            1 => "Unix",
            _ => "unknown",
        };
        format!("Host OS: {v} ({os})")
    })?;
    let name_len = c.vint_field(fields, |v| format!("Name length: {v}"))?;
    let (name, s, e) = c.bytes(to_usize(name_len))?;
    let name = display_name(name);
    fields.push(leaf(format!("Name: {name}"), s, e));
    Some(if flags & 0x01 != 0 {
        format!("Directory: {name}")
    } else {
        format!("File: {name}")
    })
}

fn rar5_encryption_fields(c: &mut Cursor, fields: &mut Vec<Block>) -> Option<()> {
    c.vint_field(fields, |v| {
        let name = if v == 0 { "AES-256" } else { "unknown" };
        format!("Encryption version: {v} ({name})")
    })?;
    let flags = c.vint_field(fields, |f| {
        format!(
            "Encryption flags: {}",
            flag_list(f, 2, &[(0x01, "password check")])
        )
    })?;
    let (kdf, s, e) = c.u8()?;
    fields.push(leaf(format!("KDF count: {kdf} (2^{kdf} iterations)"), s, e));
    let (salt, s, e) = c.bytes(16)?;
    fields.push(leaf(format!("Salt: {}", hex_bytes(salt)), s, e));
    if flags & 0x01 != 0 {
        let (check, s, e) = c.bytes(12)?;
        fields.push(leaf(format!("Check value: {}", hex_bytes(check)), s, e));
    }
    Some(())
}

fn rar5_extra_type_name(header_type: u64, typ: u64) -> &'static str {
    if header_type == RAR5_MAIN {
        return match typ {
            1 => "Locator",
            2 => "Metadata",
            _ => "Unknown",
        };
    }
    match typ {
        1 => "Encryption",
        2 => "File hash",
        3 => "File time",
        4 => "File version",
        5 => "Redirection",
        6 => "Unix owner",
        7 => "Service data",
        _ => "Unknown",
    }
}

fn rar5_extra_records(data: &[u8], start: usize, end: usize, header_type: u64) -> Vec<Block> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        if out.len() >= MAX_EXTRA_RECORDS {
            out.push(leaf("Remaining records (limit reached)", pos, end));
            break;
        }
        let mut c = Cursor {
            data: &data[..end],
            pos,
        };
        let record_end = c
            .vint()
            .filter(|&(size, _, _)| size > 0)
            .and_then(|(size, _, e)| e.checked_add(to_usize(size)))
            .filter(|&re| re <= end);
        let Some(record_end) = record_end else {
            out.push(leaf("Malformed extra record", pos, end));
            break;
        };
        let mut fields = Vec::new();
        let mut rc = Cursor {
            data: &data[..record_end],
            pos,
        };
        let _ = rc.vint_field(&mut fields, |v| format!("Record size: {v}"));
        let name = match rc.vint_field(&mut fields, |t| {
            format!(
                "Record type: {t} ({})",
                rar5_extra_type_name(header_type, t)
            )
        }) {
            Some(t) => {
                let _ = rar5_extra_fields(&mut rc, header_type, t, &mut fields);
                rar5_extra_type_name(header_type, t)
            }
            None => "Unknown",
        };
        if rc.pos < record_end {
            fields.push(leaf("Record data", rc.pos, record_end));
        }
        out.push(Block::node(
            format!("Extra record: {name}"),
            range(pos, record_end),
            fields,
        ));
        pos = record_end;
    }
    out
}

fn rar5_extra_fields(
    c: &mut Cursor,
    header_type: u64,
    typ: u64,
    fields: &mut Vec<Block>,
) -> Option<()> {
    if header_type == RAR5_MAIN {
        if typ == 1 {
            let flags = c.vint_field(fields, |f| {
                format!(
                    "Locator flags: {}",
                    flag_list(f, 2, &[(0x01, "quick open"), (0x02, "recovery record")])
                )
            })?;
            if flags & 0x01 != 0 {
                c.vint_field(fields, |v| format!("Quick open offset: {v}"))?;
            }
            if flags & 0x02 != 0 {
                c.vint_field(fields, |v| format!("Recovery record offset: {v}"))?;
            }
        }
        return Some(());
    }
    match typ {
        1 => {
            c.vint_field(fields, |v| format!("Encryption version: {v}"))?;
            let flags = c.vint_field(fields, |f| {
                format!(
                    "Encryption flags: {}",
                    flag_list(
                        f,
                        2,
                        &[(0x01, "password check"), (0x02, "tweaked checksums")]
                    )
                )
            })?;
            let (kdf, s, e) = c.u8()?;
            fields.push(leaf(format!("KDF count: {kdf} (2^{kdf} iterations)"), s, e));
            let (salt, s, e) = c.bytes(16)?;
            fields.push(leaf(format!("Salt: {}", hex_bytes(salt)), s, e));
            let (iv, s, e) = c.bytes(16)?;
            fields.push(leaf(format!("IV: {}", hex_bytes(iv)), s, e));
            if flags & 0x01 != 0 {
                let (check, s, e) = c.bytes(12)?;
                fields.push(leaf(format!("Check value: {}", hex_bytes(check)), s, e));
            }
        }
        2 => {
            let hash_type = c.vint_field(fields, |v| {
                let name = if v == 0 { "BLAKE2sp" } else { "unknown" };
                format!("Hash type: {v} ({name})")
            })?;
            if hash_type == 0 {
                let (hash, s, e) = c.bytes(32)?;
                fields.push(leaf(format!("Hash: {}", hex_bytes(hash)), s, e));
            }
        }
        3 => {
            let flags = c.vint_field(fields, |f| {
                format!(
                    "Time flags: {}",
                    flag_list(
                        f,
                        2,
                        &[
                            (0x01, "Unix time"),
                            (0x02, "mtime"),
                            (0x04, "ctime"),
                            (0x08, "atime"),
                            (0x10, "nanoseconds"),
                        ],
                    )
                )
            })?;
            let unix = flags & 0x01 != 0;
            let names = [(0x02, "Modified"), (0x04, "Created"), (0x08, "Accessed")];
            for (bit, name) in names {
                if flags & bit == 0 {
                    continue;
                }
                if unix {
                    let (t, s, e) = c.u32()?;
                    fields.push(leaf(
                        format!("{name} time: {}", format_unix_time(t as i64)),
                        s,
                        e,
                    ));
                } else {
                    let (t, s, e) = c.u64()?;
                    fields.push(leaf(format!("{name} time: {}", format_filetime(t)), s, e));
                }
            }
            if unix && flags & 0x10 != 0 {
                for (bit, name) in names {
                    if flags & bit != 0 {
                        let (ns, s, e) = c.u32()?;
                        fields.push(leaf(format!("{name} time nanoseconds: {ns}"), s, e));
                    }
                }
            }
        }
        4 => {
            c.vint_field(fields, |v| format!("Version flags: 0x{v:X}"))?;
            c.vint_field(fields, |v| format!("Version number: {v}"))?;
        }
        5 => {
            c.vint_field(fields, |v| {
                let name = match v {
                    1 => "Unix symlink",
                    2 => "Windows symlink",
                    3 => "Windows junction",
                    4 => "hard link",
                    5 => "file copy",
                    _ => "unknown",
                };
                format!("Redirection type: {v} ({name})")
            })?;
            c.vint_field(fields, |f| {
                format!(
                    "Redirection flags: {}",
                    flag_list(f, 2, &[(0x01, "target is directory")])
                )
            })?;
            let n = c.vint_field(fields, |v| format!("Target name length: {v}"))?;
            let (name, s, e) = c.bytes(to_usize(n))?;
            fields.push(leaf(format!("Target name: {}", display_name(name)), s, e));
        }
        6 => {
            let flags = c.vint_field(fields, |f| {
                format!(
                    "Owner flags: {}",
                    flag_list(
                        f,
                        2,
                        &[
                            (0x01, "user name"),
                            (0x02, "group name"),
                            (0x04, "user ID"),
                            (0x08, "group ID"),
                        ],
                    )
                )
            })?;
            for (bit, what) in [(0x01, "User name"), (0x02, "Group name")] {
                if flags & bit != 0 {
                    let n = c.vint_field(fields, |v| format!("{what} length: {v}"))?;
                    let (name, s, e) = c.bytes(to_usize(n))?;
                    fields.push(leaf(format!("{what}: {}", display_name(name)), s, e));
                }
            }
            if flags & 0x04 != 0 {
                c.vint_field(fields, |v| format!("User ID: {v}"))?;
            }
            if flags & 0x08 != 0 {
                c.vint_field(fields, |v| format!("Group ID: {v}"))?;
            }
        }
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn has_label(blocks: &[Block], label: &str) -> bool {
        blocks.iter().any(|b| b.label == label)
    }

    // ----- RAR 4 builders -----

    fn rar4_header(typ: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let size = (7 + body.len()) as u16;
        let mut h = vec![0, 0, typ];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(body);
        let crc = (crc32(&h[2..]) & 0xFFFF) as u16;
        h[0..2].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn rar4_file(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(contents.len() as u32).to_le_bytes()); // PACK_SIZE
        body.extend_from_slice(&(contents.len() as u32).to_le_bytes()); // UNP_SIZE
        body.push(3); // HOST_OS: Unix
        body.extend_from_slice(&crc32(contents).to_le_bytes());
        // 2024-03-15 10:20:30
        let date: u32 = ((2024 - 1980) << 9) | (3 << 5) | 15;
        let time: u32 = (10 << 11) | (20 << 5) | 15;
        body.extend_from_slice(&((date << 16) | time).to_le_bytes());
        body.push(29); // UNP_VER
        body.push(0x30); // METHOD: store
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0x81A4u32.to_le_bytes()); // ATTR
        body.extend_from_slice(name.as_bytes());
        let mut out = rar4_header(RAR4_FILE, 0x8000, &body);
        out.extend_from_slice(contents);
        out
    }

    fn build_rar4(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data = RAR4_SIGNATURE.to_vec();
        data.extend(rar4_header(RAR4_MAIN, 0, &[0; 6]));
        for (name, contents) in files {
            data.extend(rar4_file(name, contents));
        }
        data.extend(rar4_header(RAR4_ENDARC, 0x4000, &[]));
        data
    }

    // ----- RAR 5 builders -----

    fn vint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn rar5_header(typ: u64, extra: &[u8], data_size: Option<u64>, body: &[u8]) -> Vec<u8> {
        let mut flags = 0;
        if !extra.is_empty() {
            flags |= RAR5_HFL_EXTRA;
        }
        if data_size.is_some() {
            flags |= RAR5_HFL_DATA;
        }
        let mut inner = vint(typ);
        inner.extend(vint(flags));
        if !extra.is_empty() {
            inner.extend(vint(extra.len() as u64));
        }
        if let Some(ds) = data_size {
            inner.extend(vint(ds));
        }
        inner.extend_from_slice(body);
        inner.extend_from_slice(extra);
        let mut out = vec![0; 4];
        out.extend(vint(inner.len() as u64));
        out.extend(inner);
        let crc = crc32(&out[4..]);
        out[0..4].copy_from_slice(&crc.to_le_bytes());
        out
    }

    fn rar5_file(name: &str, contents: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut body = vint(0x02 | 0x04); // mtime + CRC32
        body.extend(vint(contents.len() as u64));
        body.extend(vint(0x20)); // attributes
        body.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        body.extend_from_slice(&crc32(contents).to_le_bytes());
        body.extend(vint((3 << 7) | (2 << 10))); // method 3, 512 KiB dictionary
        body.extend(vint(1)); // Unix
        body.extend(vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        let mut out = rar5_header(RAR5_FILE, extra, Some(contents.len() as u64), &body);
        out.extend_from_slice(contents);
        out
    }

    fn hash_record() -> Vec<u8> {
        let mut rec = vint(2); // type: hash
        rec.extend(vint(0)); // BLAKE2sp
        rec.extend_from_slice(&[0xAB; 32]);
        let mut out = vint(rec.len() as u64);
        out.extend(rec);
        out
    }

    fn build_rar5(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data = RAR5_SIGNATURE.to_vec();
        data.extend(rar5_header(RAR5_MAIN, &[], None, &vint(0)));
        for (name, contents) in files {
            data.extend(rar5_file(name, contents, &hash_record()));
        }
        data.extend(rar5_header(RAR5_END, &[], None, &vint(0)));
        data
    }

    fn position(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
    }

    // ----- matching -----

    #[test]
    fn matches_both_versions() {
        assert!(RarDissector.matches(&build_rar4(&[("a", b"x")])));
        assert!(RarDissector.matches(&build_rar5(&[("a", b"x")])));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!RarDissector.matches(b""));
        assert!(!RarDissector.matches(b"not a rar archive"));
        assert!(!RarDissector.matches(b"Rar!\x1A\x07"));
        assert!(!RarDissector.matches(b"Rar!\x1A\x07\x02\x00"));
        assert!(!RarDissector.matches(b"PK\x03\x04"));
    }

    // ----- RAR 4 -----

    #[test]
    fn dissects_rar4_archive() {
        let data = build_rar4(&[("a.txt", b"hello"), ("dir/b.bin", b"0123456789")]);
        let blocks = RarDissector.dissect(&data);

        let sig = find_block(&blocks, "Signature: RAR 4.x");
        assert_eq!(sig.range, ByteRange::new(0, 7));

        let main = find_block(&blocks, "Main archive header");
        assert_eq!(main.range, ByteRange::new(7, 20));
        assert!(main.children[0].children[0].label.ends_with("(OK)"));

        let file = find_block(&blocks, "File: a.txt");
        // header 7 + 25 fixed + 5 name = 37 bytes, then 5 bytes of data
        assert_eq!(file.range, ByteRange::new(20, 62));
        let header = find_block(&file.children, "Header");
        assert_eq!(header.range, ByteRange::new(20, 57));
        let f = &header.children;
        assert!(f[0].label.ends_with("(OK)"), "{}", f[0].label);
        assert!(has_label(f, "Header type: 0x74 (FILE)"));
        assert!(has_label(f, "Header flags: 0x8000 (LONG_BLOCK)"));
        assert!(has_label(f, "Header size: 37"));
        assert!(has_label(f, "Packed size: 5"));
        assert!(has_label(f, "Unpacked size: 5"));
        assert!(has_label(f, "Host OS: 3 (Unix)"));
        assert!(has_label(
            f,
            &format!("File CRC32: 0x{:08X}", crc32(b"hello"))
        ));
        assert!(has_label(f, "Modified time: 2024-03-15 10:20:30"));
        assert!(has_label(f, "Unpack version: 29 (2.9)"));
        assert!(has_label(f, "Method: 0x30 (store)"));
        assert!(has_label(f, "Attributes: 0x000081A4"));
        assert!(has_label(f, "Dictionary: 64 KiB"));
        let name = find_block(f, "File name: a.txt");
        assert_eq!(name.range, ByteRange::new(52, 57));
        let packed = find_block(&file.children, "Packed data");
        assert_eq!(packed.range, ByteRange::new(57, 62));

        let second = find_block(&blocks, "File: dir/b.bin");
        assert_eq!(second.range.start, 62);
        let end = find_block(&blocks, "End of archive");
        assert_eq!(end.range.end, data.len() as u64);
        assert_eq!(blocks.len(), 5);
    }

    #[test]
    fn reports_rar4_crc_mismatch() {
        let mut data = build_rar4(&[("a.txt", b"hello")]);
        data[7] ^= 0xFF;
        let blocks = RarDissector.dissect(&data);
        let main = find_block(&blocks, "Main archive header");
        assert!(main.children[0].children[0].label.contains("mismatch"));
    }

    #[test]
    fn stops_at_rar4_encrypted_headers() {
        let mut data = RAR4_SIGNATURE.to_vec();
        data.extend(rar4_header(RAR4_MAIN, RAR4_MAIN_PASSWORD, &[0; 6]));
        data.extend_from_slice(&[0x55; 32]);
        let blocks = RarDissector.dissect(&data);
        let enc = find_block(&blocks, "Encrypted headers");
        assert_eq!(enc.range, ByteRange::new(20, 52));
    }

    #[test]
    fn truncated_rar4_does_not_panic() {
        let data = build_rar4(&[("a.txt", b"hello")]);
        let full = RarDissector.dissect(&data).len();
        for cut in 0..data.len() {
            let blocks = RarDissector.dissect(&data[..cut]);
            assert!(blocks.len() <= full);
        }
        assert_eq!(RarDissector.dissect(RAR4_SIGNATURE).len(), 1);
    }

    // ----- RAR 5 -----

    #[test]
    fn dissects_rar5_archive() {
        let data = build_rar5(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
        let blocks = RarDissector.dissect(&data);

        let sig = find_block(&blocks, "Signature: RAR 5.0");
        assert_eq!(sig.range, ByteRange::new(0, 8));

        let main = find_block(&blocks, "Main archive header");
        assert_eq!(main.range.start, 8);
        let mf = &main.children[0].children;
        assert!(mf[0].label.ends_with("(OK)"), "{}", mf[0].label);
        assert!(has_label(mf, "Header type: 1 (main archive)"));
        assert!(has_label(mf, "Archive flags: 0x00"));

        let file = find_block(&blocks, "File: a.txt");
        let header = find_block(&file.children, "Header");
        let f = &header.children;
        assert!(f[0].label.ends_with("(OK)"), "{}", f[0].label);
        assert!(has_label(f, "Header type: 2 (file)"));
        assert!(has_label(f, "Header flags: 0x0003 (extra area, data area)"));
        assert!(has_label(f, "Extra area size: 35"));
        assert!(has_label(f, "Data size: 5"));
        assert!(has_label(f, "File flags: 0x06 (mtime, CRC32)"));
        assert!(has_label(f, "Unpacked size: 5"));
        assert!(has_label(f, "Attributes: 0x20"));
        assert!(has_label(f, "Modified time: 2023-11-14 22:13:20 UTC"));
        assert!(has_label(
            f,
            &format!("Data CRC32: 0x{:08X}", crc32(b"hello"))
        ));
        assert!(has_label(f, "Host OS: 1 (Unix)"));
        assert!(has_label(f, "Name: a.txt"));

        let ci = find_block(f, "Compression info: 0x980");
        assert!(has_label(&ci.children, "Algorithm version: 0 (RAR 5.0)"));
        assert!(has_label(&ci.children, "Solid: no"));
        assert!(has_label(&ci.children, "Method: 3 (normal)"));
        assert!(has_label(&ci.children, "Dictionary size: 512 KiB"));

        let extra = find_block(f, "Extra area (35 bytes)");
        let rec = find_block(&extra.children, "Extra record: File hash");
        assert_eq!(rec.range, extra.range);
        assert!(has_label(&rec.children, "Hash type: 0 (BLAKE2sp)"));
        assert!(has_label(
            &rec.children,
            &format!("Hash: {}", "ab".repeat(32))
        ));

        let hello = position(&data, b"hello") as u64;
        assert_eq!(extra.range.end, hello);
        assert_eq!(header.range.end, hello);
        let packed = find_block(&file.children, "Packed data");
        assert_eq!(packed.range, ByteRange::new(hello, hello + 5));
        assert_eq!(file.range.end, hello + 5);

        let second = find_block(&blocks, "File: b.txt");
        assert_eq!(second.range.start, hello + 5);
        let end = find_block(&blocks, "End of archive header");
        assert_eq!(end.range.end, data.len() as u64);
        assert_eq!(blocks.len(), 5);
    }

    #[test]
    fn decodes_rar5_time_and_owner_records() {
        let mut htime = vint(3);
        htime.extend(vint(0x01 | 0x02)); // Unix time, mtime
        htime.extend_from_slice(&0u32.to_le_bytes());
        let mut owner = vint(6);
        owner.extend(vint(0x01 | 0x08));
        owner.extend(vint(4));
        owner.extend_from_slice(b"root");
        owner.extend(vint(1000));
        let mut extra = vint(htime.len() as u64);
        extra.extend(htime);
        extra.extend(vint(owner.len() as u64));
        extra.extend(owner);

        let mut data = RAR5_SIGNATURE.to_vec();
        data.extend(rar5_file("x", b"data", &extra));
        let blocks = RarDissector.dissect(&data);
        let file = find_block(&blocks, "File: x");
        let extra = find_block(
            &file.children[0].children,
            &format!("Extra area ({} bytes)", extra.len()),
        );
        let time = find_block(&extra.children, "Extra record: File time");
        assert!(has_label(
            &time.children,
            "Modified time: 1970-01-01 00:00:00 UTC"
        ));
        let owner = find_block(&extra.children, "Extra record: Unix owner");
        assert!(has_label(&owner.children, "User name: root"));
        assert!(has_label(&owner.children, "Group ID: 1000"));
    }

    #[test]
    fn stops_at_rar5_encryption_header() {
        let mut body = vint(0);
        body.extend(vint(1));
        body.push(15);
        body.extend_from_slice(&[0x11; 16]);
        body.extend_from_slice(&[0x22; 12]);
        let mut data = RAR5_SIGNATURE.to_vec();
        data.extend(rar5_header(RAR5_ENCRYPTION, &[], None, &body));
        let enc_end = data.len() as u64;
        data.extend_from_slice(&[0x99; 40]);

        let blocks = RarDissector.dissect(&data);
        let enc = find_block(&blocks, "Archive encryption header");
        let f = &enc.children[0].children;
        assert!(has_label(f, "Encryption version: 0 (AES-256)"));
        assert!(has_label(f, "KDF count: 15 (2^15 iterations)"));
        assert!(has_label(f, &format!("Salt: {}", "11".repeat(16))));
        assert!(has_label(f, &format!("Check value: {}", "22".repeat(12))));
        let rest = find_block(&blocks, "Encrypted headers and data");
        assert_eq!(rest.range, ByteRange::new(enc_end, enc_end + 40));
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn truncated_rar5_does_not_panic() {
        let data = build_rar5(&[("a.txt", b"hello")]);
        let full = RarDissector.dissect(&data).len();
        for cut in 0..data.len() {
            let blocks = RarDissector.dissect(&data[..cut]);
            assert!(blocks.len() <= full);
        }
        assert_eq!(RarDissector.dissect(RAR5_SIGNATURE).len(), 1);
    }

    #[test]
    fn garbage_after_signature_does_not_panic() {
        for fill in [0x00u8, 0x7F, 0x80, 0xFF] {
            let mut data = RAR5_SIGNATURE.to_vec();
            data.extend_from_slice(&[fill; 64]);
            let _ = RarDissector.dissect(&data);
            let mut data = RAR4_SIGNATURE.to_vec();
            data.extend_from_slice(&[fill; 64]);
            let _ = RarDissector.dissect(&data);
        }
    }

    #[test]
    fn identify_reports_rar() {
        assert_eq!(super::super::identify(&build_rar4(&[("a", b"x")])), "RAR");
        assert_eq!(super::super::identify(&build_rar5(&[("a", b"x")])), "RAR");
    }
}
