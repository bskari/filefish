use super::{Block, ByteRange, Dissector};

/// Bit set on a marshal type byte when the object is stored in the reference
/// table so later `r` entries can point back at it.
const FLAG_REF: u8 = 0x80;

/// Marshal type byte of a code object.
const TYPE_CODE: u8 = b'c';

/// Deepest object nesting followed before giving up, so hostile input can't
/// overflow the stack.
const MAX_DEPTH: usize = 64;

/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

/// Ranges of `.pyc` magic numbers (the little-endian u16 before `\r\n`) and
/// the Python version that wrote them, from CPython's
/// `Lib/importlib/_bootstrap_external.py` and Python 2's `import.c`.
/// Development-cycle values are included; the last value is the release.
const MAGIC_VERSIONS: &[(u16, u16, Version)] = &[
    (62011, 62021, Version(2, 3)),
    (62041, 62061, Version(2, 4)),
    (62071, 62131, Version(2, 5)),
    (62151, 62161, Version(2, 6)),
    (62171, 62211, Version(2, 7)),
    (3000, 3131, Version(3, 0)),
    (3141, 3151, Version(3, 1)),
    (3160, 3180, Version(3, 2)),
    (3190, 3230, Version(3, 3)),
    (3250, 3310, Version(3, 4)),
    (3320, 3351, Version(3, 5)),
    (3360, 3379, Version(3, 6)),
    (3390, 3394, Version(3, 7)),
    (3400, 3413, Version(3, 8)),
    (3420, 3425, Version(3, 9)),
    (3430, 3439, Version(3, 10)),
    (3450, 3495, Version(3, 11)),
    (3500, 3531, Version(3, 12)),
    (3550, 3571, Version(3, 13)),
    (3600, 3627, Version(3, 14)),
];

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
struct Version(u8, u8);

impl Version {
    /// Size of the header before the marshalled code object.
    fn header_len(self) -> usize {
        if self >= Version(3, 7) {
            16
        } else if self >= Version(3, 3) {
            12
        } else {
            8
        }
    }
}

pub struct PycDissector;

impl Dissector for PycDissector {
    fn name(&self) -> &'static str {
        "Python bytecode"
    }

    fn matches(&self, data: &[u8]) -> bool {
        let Some((_, version)) = magic_version(data) else {
            return false;
        };
        let header_len = version.header_len();
        if version >= Version(3, 7) && read_u32(data, 4).is_none_or(|flags| flags > 3) {
            return false;
        }
        // Every .pyc holds a single marshalled code object after the header.
        data.get(header_len)
            .is_some_and(|&b| b & !FLAG_REF == TYPE_CODE)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let Some((magic, version)) = magic_version(data) else {
            return blocks;
        };
        let header_len = version.header_len();
        if data.len() < header_len {
            return blocks;
        }
        blocks.push(header_block(data, magic, version).expanded());

        let mut parser = Marshal {
            data,
            version,
            refs: Vec::new(),
        };
        let parsed = parser.object(header_len, 0);
        let end = parsed.end;
        let mut code = parsed.block;
        code.label = format!("Marshalled {}", code.label);
        blocks.push(code.expanded());

        if end < data.len() {
            let label = if parsed.ok {
                "Trailing data"
            } else {
                "Unparsed data"
            };
            blocks.push(Block::leaf(
                format!("{label} ({} bytes)", data.len() - end),
                span(end, data.len()),
            ));
        }
        blocks
    }
}

fn magic_version(data: &[u8]) -> Option<(u16, Version)> {
    if data.get(2..4)? != b"\r\n" {
        return None;
    }
    let magic = read_u16(data, 0)?;
    MAGIC_VERSIONS
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&magic))
        .map(|&(_, _, version)| (magic, version))
}

fn header_block(data: &[u8], magic: u16, version: Version) -> Block {
    let Version(major, minor) = version;
    let mut children = vec![Block::leaf(
        format!("Magic: {magic} (Python {major}.{minor})"),
        span(0, 4),
    )];
    let header_len = version.header_len();
    if version >= Version(3, 7) {
        let flags = read_u32(data, 4).unwrap_or(0);
        let kind = if flags & 1 == 0 {
            "timestamp-based"
        } else if flags & 2 != 0 {
            "hash-based, checked"
        } else {
            "hash-based, unchecked"
        };
        children.push(Block::leaf(
            format!("Flags: 0x{flags:X} ({kind})"),
            span(4, 8),
        ));
        if flags & 1 != 0 {
            let hash = data[8..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            children.push(Block::leaf(format!("Source hash: {hash}"), span(8, 16)));
        } else {
            children.push(mtime_leaf(data, 8));
            children.push(source_size_leaf(data, 12));
        }
    } else {
        children.push(mtime_leaf(data, 4));
        if header_len == 12 {
            children.push(source_size_leaf(data, 8));
        }
    }
    Block::node("Header", span(0, header_len), children)
}

fn mtime_leaf(data: &[u8], off: usize) -> Block {
    let mtime = read_u32(data, off).unwrap_or(0);
    Block::leaf(
        format!(
            "Source mtime: {mtime} ({})",
            format_unix_timestamp(mtime as i64)
        ),
        span(off, off + 4),
    )
}

fn source_size_leaf(data: &[u8], off: usize) -> Block {
    let size = read_u32(data, off).unwrap_or(0);
    Block::leaf(format!("Source size: {size} bytes"), span(off, off + 4))
}

/// Result of parsing one marshalled object. When `ok` is false, parsing
/// stopped inside it (unknown type, truncation or excessive nesting) and
/// `block` holds whatever was understood up to `end`.
struct Parsed {
    block: Block,
    end: usize,
    ok: bool,
}

impl Parsed {
    fn leaf(label: String, start: usize, end: usize) -> Self {
        Self {
            block: Block::leaf(label, span(start, end)),
            end,
            ok: true,
        }
    }

    fn fail(label: String, start: usize, end: usize) -> Self {
        Self {
            block: Block::leaf(label, span(start, end)),
            end,
            ok: false,
        }
    }
}

enum CodeField {
    /// A raw little-endian i32 written directly by marshal.
    Int(&'static str),
    /// A nested marshalled object.
    Object(&'static str),
}

use CodeField::{Int, Object};

fn code_layout(version: Version) -> &'static [CodeField] {
    if version >= Version(3, 11) {
        &[
            Int("co_argcount"),
            Int("co_posonlyargcount"),
            Int("co_kwonlyargcount"),
            Int("co_stacksize"),
            Int("co_flags"),
            Object("co_code"),
            Object("co_consts"),
            Object("co_names"),
            Object("co_localsplusnames"),
            Object("co_localspluskinds"),
            Object("co_filename"),
            Object("co_name"),
            Object("co_qualname"),
            Int("co_firstlineno"),
            Object("co_linetable"),
            Object("co_exceptiontable"),
        ]
    } else if version >= Version(3, 8) {
        &[
            Int("co_argcount"),
            Int("co_posonlyargcount"),
            Int("co_kwonlyargcount"),
            Int("co_nlocals"),
            Int("co_stacksize"),
            Int("co_flags"),
            Object("co_code"),
            Object("co_consts"),
            Object("co_names"),
            Object("co_varnames"),
            Object("co_freevars"),
            Object("co_cellvars"),
            Object("co_filename"),
            Object("co_name"),
            Int("co_firstlineno"),
            // Renamed co_linetable (new encoding) in 3.10; see `code`.
            Object("co_lnotab"),
        ]
    } else if version >= Version(3, 0) {
        &[
            Int("co_argcount"),
            Int("co_kwonlyargcount"),
            Int("co_nlocals"),
            Int("co_stacksize"),
            Int("co_flags"),
            Object("co_code"),
            Object("co_consts"),
            Object("co_names"),
            Object("co_varnames"),
            Object("co_freevars"),
            Object("co_cellvars"),
            Object("co_filename"),
            Object("co_name"),
            Int("co_firstlineno"),
            Object("co_lnotab"),
        ]
    } else {
        &[
            Int("co_argcount"),
            Int("co_nlocals"),
            Int("co_stacksize"),
            Int("co_flags"),
            Object("co_code"),
            Object("co_consts"),
            Object("co_names"),
            Object("co_varnames"),
            Object("co_freevars"),
            Object("co_cellvars"),
            Object("co_filename"),
            Object("co_name"),
            Int("co_firstlineno"),
            Object("co_lnotab"),
        ]
    }
}

const CODE_FLAG_NAMES: &[(u32, &str)] = &[
    (0x1, "OPTIMIZED"),
    (0x2, "NEWLOCALS"),
    (0x4, "VARARGS"),
    (0x8, "VARKEYWORDS"),
    (0x10, "NESTED"),
    (0x20, "GENERATOR"),
    (0x40, "NOFREE"),
    (0x80, "COROUTINE"),
    (0x100, "ITERABLE_COROUTINE"),
    (0x200, "ASYNC_GENERATOR"),
    (0x0400_0000, "HAS_DOCSTRING"),
    (0x0800_0000, "METHOD"),
];

fn code_flags_label(flags: u32) -> String {
    let mut names: Vec<String> = CODE_FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    let known = CODE_FLAG_NAMES.iter().fold(0, |acc, (bit, _)| acc | bit);
    if flags & !known != 0 {
        names.push(format!("0x{:X}", flags & !known));
    }
    if names.is_empty() {
        format!("co_flags: 0x{flags:08X}")
    } else {
        format!("co_flags: 0x{flags:08X} ({})", names.join(" | "))
    }
}

/// Walks a marshal stream, building a block per object.
struct Marshal<'a> {
    data: &'a [u8],
    version: Version,
    /// Short descriptions of objects stored with FLAG_REF, by ref index.
    refs: Vec<String>,
}

impl Marshal<'_> {
    fn object(&mut self, off: usize, depth: usize) -> Parsed {
        let data = self.data;
        let Some(&type_byte) = data.get(off) else {
            return Parsed::fail("Truncated (missing object)".to_string(), off, off);
        };
        if depth > MAX_DEPTH {
            return Parsed::fail(
                "Nesting too deep (parsing stopped)".to_string(),
                off,
                data.len(),
            );
        }
        let t = type_byte & !FLAG_REF;
        let flagged = type_byte & FLAG_REF != 0;
        let body = off + 1;

        // Singletons and back-references never take a ref slot.
        let singleton = match t {
            b'0' => Some("NULL"),
            b'N' => Some("None"),
            b'F' => Some("False"),
            b'T' => Some("True"),
            b'S' => Some("StopIteration"),
            b'.' => Some("Ellipsis"),
            _ => None,
        };
        if let Some(name) = singleton {
            return Parsed::leaf(name.to_string(), off, body);
        }
        if t == b'r' {
            return match read_u32(data, body) {
                Some(index) => {
                    let target = self
                        .refs
                        .get(index as usize)
                        .map(|desc| format!(" → {desc}"))
                        .unwrap_or_default();
                    Parsed::leaf(format!("Ref #{index}{target}"), off, body + 4)
                }
                None => Parsed::fail("Truncated ref".to_string(), off, data.len()),
            };
        }

        // Every other known type reserves its ref slot before its contents.
        let ref_slot = flagged.then(|| {
            self.refs.push(String::new());
            self.refs.len() - 1
        });
        let mut parsed = match t {
            b'c' => self.code(off, depth),
            b'(' | b')' | b'[' | b'<' | b'>' => self.sequence(off, t, depth),
            b'{' => self.dict(off, depth),
            b':' => self.slice(off, depth),
            _ => self.scalar(off, t),
        };
        if let Some(slot) = ref_slot {
            self.refs[slot] = parsed.block.label.clone();
            parsed.block.label = format!("{} [ref #{slot}]", parsed.block.label);
        }
        parsed
    }

    fn scalar(&mut self, off: usize, t: u8) -> Parsed {
        let data = self.data;
        let body = off + 1;
        let truncated = || Parsed::fail("Truncated object".to_string(), off, data.len());
        match t {
            b'i' => match read_u32(data, body) {
                Some(v) => Parsed::leaf(format!("Int: {}", v as i32), off, body + 4),
                None => truncated(),
            },
            b'I' => match read_u64(data, body) {
                Some(v) => Parsed::leaf(format!("Int64: {}", v as i64), off, body + 8),
                None => truncated(),
            },
            b'g' => match read_u64(data, body) {
                Some(v) => Parsed::leaf(format!("Float: {}", f64::from_bits(v)), off, body + 8),
                None => truncated(),
            },
            b'y' => match (read_u64(data, body), read_u64(data, body + 8)) {
                (Some(re), Some(im)) => Parsed::leaf(
                    format!("Complex: ({}+{}j)", f64::from_bits(re), f64::from_bits(im)),
                    off,
                    body + 16,
                ),
                _ => truncated(),
            },
            b'f' => match short_text(data, body) {
                Some((text, end)) => Parsed::leaf(format!("Float: {text}"), off, end),
                None => truncated(),
            },
            b'x' => match short_text(data, body)
                .and_then(|(re, mid)| short_text(data, mid).map(|(im, end)| (re, im, end)))
            {
                Some((re, im, end)) => Parsed::leaf(format!("Complex: ({re}+{im}j)"), off, end),
                None => truncated(),
            },
            b'l' => {
                let Some(n) = read_u32(data, body).map(|n| n as i32) else {
                    return truncated();
                };
                let digits = n.unsigned_abs() as usize;
                let end = body + 4 + digits * 2;
                let Some(bytes) = data.get(body + 4..end) else {
                    return truncated();
                };
                let label = if digits <= 8 {
                    // 15-bit digits, least significant first.
                    let magnitude = bytes.chunks_exact(2).rev().fold(0i128, |acc, d| {
                        (acc << 15) | (u16::from_le_bytes([d[0], d[1]]) & 0x7FFF) as i128
                    });
                    let value = if n < 0 { -magnitude } else { magnitude };
                    format!("Long: {value}")
                } else {
                    format!("Long: ({digits} digits)")
                };
                Parsed::leaf(label, off, end)
            }
            b's' | b't' | b'u' | b'a' | b'A' | b'z' | b'Z' => {
                let short = matches!(t, b'z' | b'Z');
                let (len, start) = if short {
                    match data.get(body) {
                        Some(&len) => (len as usize, body + 1),
                        None => return truncated(),
                    }
                } else {
                    match read_u32(data, body) {
                        Some(len) => (len as usize, body + 4),
                        None => return truncated(),
                    }
                };
                let Some(bytes) = start.checked_add(len).and_then(|end| data.get(start..end))
                else {
                    return truncated();
                };
                let end = start + len;
                let py2 = self.version < Version(3, 0);
                let kind = match t {
                    b's' if py2 => "Str",
                    b's' => "Bytes",
                    b't' => "Str (interned)",
                    b'u' => "Unicode",
                    b'a' => "Str (ASCII)",
                    b'A' => "Str (ASCII, interned)",
                    b'z' => "Str (short ASCII)",
                    _ => "Str (short ASCII, interned)",
                };
                // Python 2 `str` holds both names and bytecode; quote it only
                // when it looks like text. Python 3 `bytes` is always binary.
                let is_text = t != b's' || (py2 && bytes.iter().all(|b| (0x20..0x7F).contains(b)));
                let label = if is_text && bytes.len() <= MAX_LABEL_CHARS {
                    format!("{kind}: {}", quote(&String::from_utf8_lossy(bytes)))
                } else if is_text {
                    format!(
                        "{kind}: {} ({len} bytes)",
                        quote(&String::from_utf8_lossy(bytes))
                    )
                } else {
                    format!("{kind}: {len} bytes")
                };
                Parsed::leaf(label, off, end)
            }
            b'R' => match read_u32(data, body) {
                Some(index) => Parsed::leaf(format!("Interned string ref #{index}"), off, body + 4),
                None => truncated(),
            },
            _ => {
                let printable = if (0x20..0x7F).contains(&t) {
                    format!(" '{}'", t as char)
                } else {
                    String::new()
                };
                Parsed::fail(
                    format!("Unknown marshal type 0x{t:02X}{printable} (parsing stopped)"),
                    off,
                    body,
                )
            }
        }
    }

    /// Parses `count` consecutive objects starting at `off`, labelling each
    /// with `label_for(i)`. Stops at the first failure.
    fn children(
        &mut self,
        mut off: usize,
        count: usize,
        depth: usize,
        children: &mut Vec<Block>,
        label_for: impl Fn(usize) -> String,
    ) -> (usize, bool) {
        for i in 0..count {
            let item = self.object(off, depth + 1);
            off = item.end;
            let mut block = item.block;
            block.label = format!("{}{}", label_for(i), block.label);
            children.push(block);
            if !item.ok {
                return (off, false);
            }
        }
        (off, true)
    }

    fn sequence(&mut self, off: usize, t: u8, depth: usize) -> Parsed {
        let data = self.data;
        let body = off + 1;
        let (count, items_start) = if t == b')' {
            match data.get(body) {
                Some(&n) => (n as usize, body + 1),
                None => return Parsed::fail("Truncated tuple".to_string(), off, data.len()),
            }
        } else {
            match read_u32(data, body) {
                Some(n) => (n as usize, body + 4),
                None => return Parsed::fail("Truncated container".to_string(), off, data.len()),
            }
        };
        let kind = match t {
            b'(' | b')' => "Tuple",
            b'[' => "List",
            b'<' => "Set",
            _ => "Frozenset",
        };
        let mut children = Vec::new();
        let (end, ok) = self.children(items_start, count, depth, &mut children, |i| {
            format!("[{i}] ")
        });
        let label = format!("{kind} ({count} items)");
        Parsed {
            block: Block::node(label, span(off, end), children),
            end,
            ok,
        }
    }

    fn dict(&mut self, off: usize, depth: usize) -> Parsed {
        let mut children = Vec::new();
        let mut pos = off + 1;
        let mut pairs = 0;
        let ok = loop {
            if self.data.get(pos) == Some(&b'0') {
                children.push(Block::leaf("NULL (end of dict)", span(pos, pos + 1)));
                pos += 1;
                break true;
            }
            let (end, ok) = self.children(pos, 2, depth, &mut children, |i| {
                if i == 0 { "Key: " } else { "Value: " }.to_string()
            });
            pos = end;
            if !ok {
                break false;
            }
            pairs += 1;
        };
        Parsed {
            block: Block::node(format!("Dict ({pairs} items)"), span(off, pos), children),
            end: pos,
            ok,
        }
    }

    fn slice(&mut self, off: usize, depth: usize) -> Parsed {
        let mut children = Vec::new();
        let (end, ok) = self.children(off + 1, 3, depth, &mut children, |i| {
            ["start: ", "stop: ", "step: "][i].to_string()
        });
        Parsed {
            block: Block::node("Slice", span(off, end), children),
            end,
            ok,
        }
    }

    fn code(&mut self, off: usize, depth: usize) -> Parsed {
        let data = self.data;
        let type_byte = data[off];
        let ref_note = if type_byte & FLAG_REF != 0 {
            " | FLAG_REF"
        } else {
            ""
        };
        let mut children = vec![Block::leaf(
            format!("Type: 0x{type_byte:02X} ('c' code object{ref_note})"),
            span(off, off + 1),
        )];
        let mut pos = off + 1;
        let mut name = None;
        let mut ok = true;
        for field in code_layout(self.version) {
            match *field {
                Int(field_name) => {
                    let Some(value) = read_u32(data, pos) else {
                        children.push(Block::leaf(
                            format!("{field_name}: truncated"),
                            span(pos, data.len()),
                        ));
                        pos = data.len();
                        ok = false;
                        break;
                    };
                    let label = if field_name == "co_flags" {
                        code_flags_label(value)
                    } else {
                        format!("{field_name}: {}", value as i32)
                    };
                    children.push(Block::leaf(label, span(pos, pos + 4)));
                    pos += 4;
                }
                Object(field_name) => {
                    let field_name = if field_name == "co_lnotab" && self.version >= Version(3, 10)
                    {
                        "co_linetable"
                    } else {
                        field_name
                    };
                    let item = self.object(pos, depth + 1);
                    pos = item.end;
                    let mut block = item.block;
                    if field_name == "co_name" {
                        name = Some(block.label.clone());
                    }
                    block.label = format!("{field_name}: {}", block.label);
                    children.push(block);
                    if !item.ok {
                        ok = false;
                        break;
                    }
                }
            }
        }
        // Drop any " [ref #n]" suffix the name string picked up.
        let name = name
            .as_deref()
            .map(|n| n.split(" [ref #").next().unwrap_or(n));
        let label = match name.and_then(|n| n.split_once(": ")) {
            Some((_, quoted)) => format!("Code object {quoted}"),
            None => "Code object".to_string(),
        };
        Parsed {
            block: Block::node(label, span(off, pos), children),
            end: pos,
            ok,
        }
    }
}

/// Reads a u8-length-prefixed text field (old-style float/complex parts).
fn short_text(data: &[u8], off: usize) -> Option<(String, usize)> {
    let len = *data.get(off)? as usize;
    let bytes = data.get(off + 1..off + 1 + len)?;
    Some((String::from_utf8_lossy(bytes).into_owned(), off + 1 + len))
}

/// Quotes `text` for a single-line label, escaping control characters and
/// truncating long values with an ellipsis.
fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for (i, c) in text.chars().enumerate() {
        if i == MAX_LABEL_CHARS {
            out.push('…');
            break;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Converts a day count relative to the Unix epoch to a proleptic Gregorian
/// (year, month, day). This is Howard Hinnant's public-domain
/// `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Formats a count of seconds since the Unix epoch as a UTC date/time.
fn format_unix_timestamp(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86400);
    let secs_of_day = unix_seconds.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn push_short_str(buf: &mut Vec<u8>, s: &str) {
        buf.push(b'z');
        buf.push(s.len() as u8);
        push_bytes(buf, s.as_bytes());
    }

    /// Builds a minimal Python 3.12 module code object for `x = 1`.
    fn build_code_312() -> Vec<u8> {
        let mut code = Vec::new();
        code.push(TYPE_CODE | FLAG_REF);
        for value in [0u32, 0, 0, 1, 0] {
            // argcount, posonlyargcount, kwonlyargcount, stacksize, flags
            push_bytes(&mut code, &value.to_le_bytes());
        }
        // co_code
        code.push(b's');
        push_bytes(&mut code, &4u32.to_le_bytes());
        push_bytes(&mut code, &[0x97, 0x00, 0x64, 0x00]);
        // co_consts: (1, None)
        code.push(b')');
        code.push(2);
        code.push(b'i');
        push_bytes(&mut code, &1u32.to_le_bytes());
        code.push(b'N');
        // co_names: ("x",) with the name stored as a ref
        code.push(b')');
        code.push(1);
        code.push(b'Z' | FLAG_REF);
        code.push(1);
        code.push(b'x');
        // co_localsplusnames, co_localspluskinds
        code.push(b')');
        code.push(0);
        code.push(b's');
        push_bytes(&mut code, &0u32.to_le_bytes());
        // co_filename, co_name, co_qualname
        push_short_str(&mut code, "m.py");
        push_short_str(&mut code, "<module>");
        code.push(b'r');
        push_bytes(&mut code, &1u32.to_le_bytes()); // ref #1 -> "x"
        // co_firstlineno, co_linetable, co_exceptiontable
        push_bytes(&mut code, &1u32.to_le_bytes());
        code.push(b's');
        push_bytes(&mut code, &0u32.to_le_bytes());
        code.push(b's');
        push_bytes(&mut code, &0u32.to_le_bytes());
        code
    }

    fn build_pyc_312(flags: u32) -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, &3531u16.to_le_bytes());
        push_bytes(&mut data, b"\r\n");
        push_bytes(&mut data, &flags.to_le_bytes());
        if flags & 1 != 0 {
            push_bytes(&mut data, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        } else {
            push_bytes(&mut data, &86400u32.to_le_bytes()); // mtime
            push_bytes(&mut data, &6u32.to_le_bytes()); // source size
        }
        push_bytes(&mut data, &build_code_312());
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
    fn matches_pyc() {
        assert!(PycDissector.matches(&build_pyc_312(0)));
        assert!(PycDissector.matches(&build_pyc_312(3)));
    }

    #[test]
    fn does_not_match_non_pyc_data() {
        assert!(!PycDissector.matches(b""));
        assert!(!PycDissector.matches(b"not a pyc file at all"));
        // Unknown magic number with \r\n.
        let mut data = build_pyc_312(0);
        data[0..2].copy_from_slice(&1234u16.to_le_bytes());
        assert!(!PycDissector.matches(&data));
        // Bad PEP 552 flags.
        let mut data = build_pyc_312(0);
        data[4] = 8;
        assert!(!PycDissector.matches(&data));
        // Truncated header.
        assert!(!PycDissector.matches(&build_pyc_312(0)[..12]));
        // Not followed by a code object.
        let mut data = build_pyc_312(0);
        data[16] = b'N';
        assert!(!PycDissector.matches(&data));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        assert!(PycDissector.dissect(&build_pyc_312(0)[..10]).is_empty());
    }

    #[test]
    fn dissect_truncated_code_object_does_not_panic() {
        let data = build_pyc_312(0);
        for len in 16..data.len() {
            let blocks = PycDissector.dissect(&data[..len]);
            assert_eq!(blocks.len(), 2, "len {len}");
            let code = &blocks[1];
            assert!(code.range.end as usize <= len);
        }
    }

    #[test]
    fn dissect_parses_timestamp_header_and_code_object() {
        let data = build_pyc_312(0);
        let blocks = PycDissector.dissect(&data);
        assert_eq!(blocks.len(), 2);

        let header = find_block(&blocks, "Header");
        assert_eq!(header.range, ByteRange::new(0, 16));
        assert_eq!(
            find_block(&header.children, "Magic: 3531 (Python 3.12)").range,
            ByteRange::new(0, 4)
        );
        find_block(&header.children, "Flags: 0x0 (timestamp-based)");
        assert_eq!(
            find_block(
                &header.children,
                "Source mtime: 86400 (1970-01-02 00:00:00 UTC)"
            )
            .range,
            ByteRange::new(8, 12)
        );
        assert_eq!(
            find_block(&header.children, "Source size: 6 bytes").range,
            ByteRange::new(12, 16)
        );

        let code = find_block(&blocks, "Marshalled Code object \"<module>\" [ref #0]");
        assert_eq!(code.range, ByteRange::new(16, data.len() as u64));
        let fields = &code.children;
        assert_eq!(
            find_block(fields, "Type: 0xE3 ('c' code object | FLAG_REF)").range,
            ByteRange::new(16, 17)
        );
        assert_eq!(
            find_block(fields, "co_argcount: 0").range,
            ByteRange::new(17, 21)
        );
        find_block(fields, "co_stacksize: 1");
        find_block(fields, "co_flags: 0x00000000");
        assert_eq!(
            find_block(fields, "co_code: Bytes: 4 bytes").range,
            ByteRange::new(37, 46)
        );
        let consts = find_block(fields, "co_consts: Tuple (2 items)");
        assert_eq!(consts.range, ByteRange::new(46, 54));
        assert_eq!(
            find_block(&consts.children, "[0] Int: 1").range,
            ByteRange::new(48, 53)
        );
        find_block(&consts.children, "[1] None");
        let names = find_block(fields, "co_names: Tuple (1 items)");
        find_block(
            &names.children,
            "[0] Str (short ASCII, interned): \"x\" [ref #1]",
        );
        find_block(fields, "co_filename: Str (short ASCII): \"m.py\"");
        find_block(fields, "co_name: Str (short ASCII): \"<module>\"");
        find_block(
            fields,
            "co_qualname: Ref #1 → Str (short ASCII, interned): \"x\"",
        );
        find_block(fields, "co_firstlineno: 1");
        find_block(fields, "co_exceptiontable: Bytes: 0 bytes");
    }

    #[test]
    fn dissect_parses_hash_based_header() {
        let blocks = PycDissector.dissect(&build_pyc_312(3));
        let header = find_block(&blocks, "Header");
        find_block(&header.children, "Flags: 0x3 (hash-based, checked)");
        assert_eq!(
            find_block(&header.children, "Source hash: 1122334455667788").range,
            ByteRange::new(8, 16)
        );
    }

    #[test]
    fn dissect_parses_old_header_layouts() {
        // Python 2.7: magic + mtime, then a code object.
        let mut data = Vec::new();
        push_bytes(&mut data, &62211u16.to_le_bytes());
        push_bytes(&mut data, b"\r\n");
        push_bytes(&mut data, &0u32.to_le_bytes());
        data.push(TYPE_CODE);
        assert!(PycDissector.matches(&data));
        let blocks = PycDissector.dissect(&data);
        let header = find_block(&blocks, "Header");
        assert_eq!(header.range, ByteRange::new(0, 8));
        find_block(&header.children, "Magic: 62211 (Python 2.7)");

        // Python 3.6: magic + mtime + source size.
        let mut data = Vec::new();
        push_bytes(&mut data, &3379u16.to_le_bytes());
        push_bytes(&mut data, b"\r\n");
        push_bytes(&mut data, &0u32.to_le_bytes());
        push_bytes(&mut data, &42u32.to_le_bytes());
        data.push(TYPE_CODE);
        let blocks = PycDissector.dissect(&data);
        let header = find_block(&blocks, "Header");
        assert_eq!(header.range, ByteRange::new(0, 12));
        find_block(&header.children, "Source size: 42 bytes");
    }

    #[test]
    fn dissect_stops_on_unknown_marshal_type() {
        let mut data = build_pyc_312(0);
        // Replace the None const with an unknown type byte.
        assert_eq!(data[53], b'N');
        data[53] = b'?';
        let blocks = PycDissector.dissect(&data);
        let code = &blocks[1];
        let consts = find_block(&code.children, "co_consts: Tuple (2 items)");
        let unknown = find_block(
            &consts.children,
            "[1] Unknown marshal type 0x3F '?' (parsing stopped)",
        );
        assert_eq!(unknown.range, ByteRange::new(53, 54));
        let rest = find_block(
            &blocks,
            &format!("Unparsed data ({} bytes)", data.len() - 54),
        );
        assert_eq!(rest.range, ByteRange::new(54, data.len() as u64));
    }

    #[test]
    fn identify_reports_pyc() {
        assert_eq!(super::super::identify(&build_pyc_312(0)), "Python bytecode");
    }
}
