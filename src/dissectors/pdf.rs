use super::{Block, ByteRange, Dissector};

const PDF_MAGIC: &[u8] = b"%PDF-";
/// The spec allows the header anywhere in the first 1024 bytes.
const HEADER_SEARCH_LIMIT: usize = 1024;
const MAX_OBJECTS_SHOWN: usize = 1000;
const MAX_DICT_ENTRIES_SHOWN: usize = 64;
const MAX_XREF_ENTRIES_SHOWN: usize = 1000;
const MAX_VALUE_CHARS: usize = 60;

pub struct PdfDissector;

impl Dissector for PdfDissector {
    fn name(&self) -> &'static str {
        "PDF"
    }

    fn matches(&self, data: &[u8]) -> bool {
        find_header(data).is_some()
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let Some(header_start) = find_header(data) else {
            return blocks;
        };

        if header_start > 0 {
            blocks.push(Block::leaf(
                format!("Leading data ({header_start} bytes)"),
                range(0, header_start),
            ));
        }

        let mut pos = header_block(data, header_start, &mut blocks);
        if let Some(end) = binary_comment_end(data, pos) {
            blocks.push(Block::leaf("Binary marker comment", range(pos, end)));
            pos = end;
        }

        let revisions = parse_body(data, pos);
        if revisions.len() == 1 {
            blocks.extend(revisions.into_iter().flatten());
        } else {
            for (i, revision) in revisions.into_iter().enumerate() {
                let (Some(first), Some(last)) = (revision.first(), revision.last()) else {
                    continue;
                };
                let r = ByteRange::new(first.range.start, last.range.end);
                blocks.push(Block::node(format!("Revision {}", i + 1), r, revision).expanded());
            }
        }

        blocks
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

/// Finds "%PDF-<digit>" at offset 0, or at the start of a line within the
/// first 1024 bytes (requiring a line start keeps stray mentions in text
/// files from matching).
fn find_header(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(HEADER_SEARCH_LIMIT);
    (0..limit).find(|&i| {
        (i == 0 || matches!(data[i - 1], b'\n' | b'\r'))
            && data[i..].starts_with(PDF_MAGIC)
            && data
                .get(i + PDF_MAGIC.len())
                .is_some_and(u8::is_ascii_digit)
    })
}

fn header_block(data: &[u8], start: usize, blocks: &mut Vec<Block>) -> usize {
    let magic_end = start + PDF_MAGIC.len();
    let version_end = magic_end
        + data[magic_end..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit() || b == b'.')
            .count();
    let line_end = eol_end(data, line_end(data, start));
    let version = String::from_utf8_lossy(&data[magic_end..version_end]);
    blocks.push(
        Block::node(
            format!("Header (PDF {version})"),
            range(start, line_end),
            vec![
                Block::leaf("Magic: %PDF-", range(start, magic_end)),
                Block::leaf(format!("Version: {version}"), range(magic_end, version_end)),
            ],
        )
        .expanded(),
    );
    line_end
}

/// The optional second-line comment containing high-bit bytes that marks
/// the file as binary.
fn binary_comment_end(data: &[u8], pos: usize) -> Option<usize> {
    if data.get(pos) != Some(&b'%') || data[pos..].starts_with(b"%%EOF") {
        return None;
    }
    let end = line_end(data, pos);
    data[pos..end]
        .iter()
        .any(|&b| b >= 0x80)
        .then(|| eol_end(data, end))
}

// ---------------------------------------------------------------------------
// Lexing

fn is_ws(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// Position of the first CR or LF at or after `pos`, or the end of data.
fn line_end(data: &[u8], pos: usize) -> usize {
    data[pos.min(data.len())..]
        .iter()
        .position(|&b| b == b'\n' || b == b'\r')
        .map_or(data.len(), |i| pos + i)
}

/// Consumes a single EOL marker (CRLF, LF or CR) at `pos`.
fn eol_end(data: &[u8], pos: usize) -> usize {
    match data.get(pos) {
        Some(b'\r') if data.get(pos + 1) == Some(&b'\n') => pos + 2,
        Some(b'\r' | b'\n') => pos + 1,
        _ => pos,
    }
}

fn skip_ws(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && is_ws(data[pos]) {
        pos += 1;
    }
    pos
}

fn skip_ws_and_comments(data: &[u8], mut pos: usize) -> usize {
    loop {
        pos = skip_ws(data, pos);
        if data.get(pos) == Some(&b'%') {
            pos = line_end(data, pos);
        } else {
            return pos;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Regular,
    Name,
    LitString,
    HexString,
    DictOpen,
    DictClose,
    ArrayOpen,
    ArrayClose,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
}

impl Token {
    fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.start..self.end]
    }

    fn is_keyword(&self, data: &[u8], keyword: &[u8]) -> bool {
        self.kind == Kind::Regular && self.bytes(data) == keyword
    }

    fn uint(&self, data: &[u8]) -> Option<u64> {
        if self.kind == Kind::Regular {
            parse_uint(self.bytes(data))
        } else {
            None
        }
    }

    /// Keywords that end the current object; containers stop at these so a
    /// malformed object can't swallow the rest of the file.
    fn is_structural(&self, data: &[u8]) -> bool {
        self.kind == Kind::Regular
            && matches!(
                self.bytes(data),
                b"endobj" | b"stream" | b"endstream" | b"obj" | b"xref" | b"trailer" | b"startxref"
            )
    }
}

fn parse_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 19 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &b| {
        acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

fn regular_end(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && !is_ws(data[pos]) && !is_delim(data[pos]) {
        pos += 1;
    }
    pos
}

fn literal_string_end(data: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut pos = start;
    while pos < data.len() {
        match data[pos] {
            b'\\' => pos += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return pos + 1;
                }
            }
            _ => {}
        }
        pos += 1;
    }
    data.len()
}

/// Returns the next token at or after `pos`, skipping whitespace and comments.
fn next_token(data: &[u8], pos: usize) -> Option<Token> {
    let start = skip_ws_and_comments(data, pos);
    let b = *data.get(start)?;
    let next = data.get(start + 1).copied();
    let (kind, end) = match b {
        b'(' => (Kind::LitString, literal_string_end(data, start)),
        b'<' if next == Some(b'<') => (Kind::DictOpen, start + 2),
        b'<' => (
            Kind::HexString,
            data[start..]
                .iter()
                .position(|&c| c == b'>')
                .map_or(data.len(), |i| start + i + 1),
        ),
        b'>' if next == Some(b'>') => (Kind::DictClose, start + 2),
        b'[' => (Kind::ArrayOpen, start + 1),
        b']' => (Kind::ArrayClose, start + 1),
        b'/' => (Kind::Name, regular_end(data, start + 1)),
        b')' | b'>' | b'{' | b'}' => (Kind::Other, start + 1),
        _ => (Kind::Regular, regular_end(data, start)),
    };
    Some(Token { kind, start, end })
}

/// Parses one value starting at or after `pos`, returning its byte span.
/// Containers are skipped iteratively (no recursion) and stop early at a
/// structural keyword. Returns None at EOF, a closing delimiter, or a
/// structural keyword.
fn parse_value(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let t = next_token(data, pos)?;
    match t.kind {
        Kind::DictOpen | Kind::ArrayOpen => {
            let mut depth = 1usize;
            let mut end = t.end;
            while let Some(u) = next_token(data, end) {
                if u.is_structural(data) {
                    break;
                }
                end = u.end;
                match u.kind {
                    Kind::DictOpen | Kind::ArrayOpen => depth += 1,
                    Kind::DictClose | Kind::ArrayClose => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            Some((t.start, end))
        }
        Kind::DictClose | Kind::ArrayClose => None,
        Kind::Regular if t.is_structural(data) => None,
        Kind::Regular if t.uint(data).is_some() => {
            // Indirect reference "N G R"?
            if let Some(g) = next_token(data, t.end)
                && g.uint(data).is_some()
                && let Some(r) = next_token(data, g.end)
                && r.is_keyword(data, b"R")
            {
                return Some((t.start, r.end));
            }
            Some((t.start, t.end))
        }
        _ => Some((t.start, t.end)),
    }
}

// ---------------------------------------------------------------------------
// Dictionaries

struct Entry {
    key: (usize, usize),
    value: (usize, usize),
}

struct Dict {
    start: usize,
    end: usize,
    closed: bool,
    entries: Vec<Entry>,
}

impl Dict {
    fn get<'a>(&self, data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|e| &data[e.key.0..e.key.1] == key)
            .map(|e| &data[e.value.0..e.value.1])
    }

    fn name(&self, data: &[u8], key: &[u8]) -> Option<String> {
        let value = self.get(data, key)?;
        value
            .starts_with(b"/")
            .then(|| String::from_utf8_lossy(&value[1..]).into_owned())
    }

    fn uint(&self, data: &[u8], key: &[u8]) -> Option<u64> {
        parse_uint(self.get(data, key)?)
    }

    /// /Filter as a single name or an array of names.
    fn filters(&self, data: &[u8]) -> Vec<String> {
        let Some(value) = self.get(data, b"/Filter") else {
            return Vec::new();
        };
        let mut names = Vec::new();
        let mut pos = 0;
        while let Some(t) = next_token(value, pos) {
            if t.kind == Kind::Name {
                names.push(String::from_utf8_lossy(&value[t.start + 1..t.end]).into_owned());
            }
            pos = t.end;
        }
        names
    }
}

fn parse_dict(data: &[u8], open: Token) -> Dict {
    let mut dict = Dict {
        start: open.start,
        end: open.end,
        closed: false,
        entries: Vec::new(),
    };
    while let Some(t) = next_token(data, dict.end) {
        match t.kind {
            Kind::DictClose => {
                dict.end = t.end;
                dict.closed = true;
                break;
            }
            _ if t.is_structural(data) => break,
            Kind::Name => {
                dict.end = t.end;
                if let Some(value) = parse_value(data, t.end) {
                    dict.entries.push(Entry {
                        key: (t.start, t.end),
                        value,
                    });
                    dict.end = value.1;
                }
            }
            // Malformed: a value without a key. Skip it whole.
            _ => dict.end = parse_value(data, dict.end).map_or(t.end, |v| v.1),
        }
    }
    dict
}

/// Renders raw PDF syntax for a label: whitespace runs collapse to one
/// space, non-printable bytes become '.', and long values are truncated.
fn render(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut chars = 0;
    let mut last_ws = false;
    for &b in bytes {
        if chars >= MAX_VALUE_CHARS {
            out.push_str("...");
            break;
        }
        if is_ws(b) {
            if !last_ws {
                out.push(' ');
                chars += 1;
            }
            last_ws = true;
            continue;
        }
        last_ws = false;
        out.push(if b.is_ascii_graphic() { b as char } else { '.' });
        chars += 1;
    }
    out
}

fn dict_block(data: &[u8], dict: &Dict) -> Block {
    let mut children: Vec<Block> = dict
        .entries
        .iter()
        .take(MAX_DICT_ENTRIES_SHOWN)
        .map(|e| {
            Block::leaf(
                format!(
                    "{} {}",
                    render(&data[e.key.0..e.key.1]),
                    render(&data[e.value.0..e.value.1])
                ),
                range(e.key.0, e.value.1),
            )
        })
        .collect();
    let hidden = &dict.entries[dict.entries.len().min(MAX_DICT_ENTRIES_SHOWN)..];
    if let (Some(first), Some(last)) = (hidden.first(), hidden.last()) {
        children.push(Block::leaf(
            format!("({} more entries not shown)", hidden.len()),
            range(first.key.0, last.value.1),
        ));
    }
    let n = dict.entries.len();
    let mut label = format!(
        "Dictionary ({n} {})",
        if n == 1 { "entry" } else { "entries" }
    );
    if !dict.closed {
        label.push_str(", unterminated");
    }
    Block::node(label, range(dict.start, dict.end), children)
}

// ---------------------------------------------------------------------------
// File body

#[derive(Default)]
struct Body {
    start: usize,
    end: usize,
    count: usize,
    children: Vec<Block>,
    hidden: usize,
    hidden_start: usize,
    hidden_end: usize,
}

impl Body {
    fn add(&mut self, block: Block, shown: &mut usize) {
        let (start, end) = (block.range.start as usize, block.range.end as usize);
        if self.count == 0 {
            self.start = start;
        }
        self.end = end;
        self.count += 1;
        if *shown < MAX_OBJECTS_SHOWN {
            *shown += 1;
            self.children.push(block);
        } else {
            if self.hidden == 0 {
                self.hidden_start = start;
            }
            self.hidden += 1;
            self.hidden_end = end;
        }
    }

    fn flush(&mut self, out: &mut Vec<Block>) {
        let body = std::mem::take(self);
        if body.count == 0 {
            return;
        }
        let mut children = body.children;
        if body.hidden > 0 {
            children.push(Block::leaf(
                format!("({} more objects not shown)", body.hidden),
                range(body.hidden_start, body.hidden_end),
            ));
        }
        let noun = if body.count == 1 { "object" } else { "objects" };
        out.push(Block::node(
            format!("Body ({} {noun})", body.count),
            range(body.start, body.end),
            children,
        ));
    }
}

/// Scans everything after the header, splitting at each "%%EOF" into
/// revisions (the original file plus any incremental updates).
fn parse_body(data: &[u8], mut pos: usize) -> Vec<Vec<Block>> {
    let mut revisions = Vec::new();
    let mut current = Vec::new();
    let mut body = Body::default();
    let mut shown = 0usize;

    loop {
        pos = skip_ws(data, pos);
        if pos >= data.len() {
            break;
        }
        if data[pos] == b'%' {
            if data[pos..].starts_with(b"%%EOF") {
                body.flush(&mut current);
                current.push(Block::leaf("%%EOF", range(pos, pos + 5)));
                revisions.push(std::mem::take(&mut current));
            }
            pos = line_end(data, pos);
            continue;
        }
        let Some(t) = next_token(data, pos) else {
            break;
        };
        if t.kind == Kind::Regular {
            if let Some((num, generation, obj)) = object_header(data, t) {
                let (block, end) = object_block(data, t.start, num, generation, obj.end);
                body.add(block, &mut shown);
                pos = end;
                continue;
            }
            let keyword_block = match t.bytes(data) {
                b"xref" => Some(xref_block(data, t)),
                b"trailer" => Some(trailer_block(data, t)),
                b"startxref" => Some(startxref_block(data, t)),
                _ => None,
            };
            if let Some((block, end)) = keyword_block {
                body.flush(&mut current);
                current.push(block);
                pos = end;
                continue;
            }
        }
        // Unrecognized token: skip it.
        pos = t.end;
    }
    body.flush(&mut current);
    if !current.is_empty() {
        revisions.push(current);
    }
    revisions
}

/// Matches "N G obj" starting at `t`.
fn object_header(data: &[u8], t: Token) -> Option<(u64, u64, Token)> {
    let num = t.uint(data)?;
    let g = next_token(data, t.end)?;
    let generation = g.uint(data)?;
    let obj = next_token(data, g.end)?;
    obj.is_keyword(data, b"obj")
        .then_some((num, generation, obj))
}

fn object_block(
    data: &[u8],
    start: usize,
    num: u64,
    generation: u64,
    header_end: usize,
) -> (Block, usize) {
    let mut children = vec![Block::leaf(
        format!("Object header: {num} {generation} obj"),
        range(start, header_end),
    )];
    let mut pos = header_end;
    let mut dict = None;

    match next_token(data, pos) {
        Some(t) if t.kind == Kind::DictOpen => {
            let d = parse_dict(data, t);
            children.push(dict_block(data, &d));
            pos = d.end;
            dict = Some(d);
        }
        Some(t) if t.is_structural(data) => {}
        Some(_) => {
            if let Some((vs, ve)) = parse_value(data, pos) {
                children.push(Block::leaf(
                    format!("Value: {}", render(&data[vs..ve])),
                    range(vs, ve),
                ));
                pos = ve;
            }
        }
        None => {}
    }

    let mut has_stream = false;
    // Starts of the last two tokens, to back up over "N G" if we run into
    // the next object's "obj" because this one lacks "endobj".
    let mut recent: [Option<Token>; 2] = [None, None];
    let end = loop {
        let Some(t) = next_token(data, pos) else {
            break pos;
        };
        if t.kind == Kind::Regular {
            match t.bytes(data) {
                b"endobj" => {
                    children.push(Block::leaf("endobj", range(t.start, t.end)));
                    break t.end;
                }
                b"stream" if !has_stream => {
                    has_stream = true;
                    pos = stream_blocks(data, t, dict.as_ref(), &mut children);
                    recent = [None, None];
                    continue;
                }
                b"obj" => {
                    if let [Some(a), Some(b)] = recent
                        && a.uint(data).is_some()
                        && b.uint(data).is_some()
                    {
                        break a.start;
                    }
                    break pos;
                }
                b"xref" | b"trailer" | b"startxref" => break pos,
                _ => {}
            }
        }
        recent = [recent[1], Some(t)];
        pos = t.end;
    };

    let mut parts = Vec::new();
    if let Some(d) = &dict {
        if let Some(ty) = d.name(data, b"/Type") {
            parts.push(format!("/Type /{ty}"));
        }
        if let Some(sub) = d.name(data, b"/Subtype") {
            parts.push(format!("/Subtype /{sub}"));
        }
    }
    if parts.is_empty() && has_stream {
        parts.push("stream".to_string());
    }
    let mut label = format!("Object {num} {generation}");
    if !parts.is_empty() {
        label.push_str(&format!(" ({})", parts.join(" ")));
    }
    (Block::node(label, range(start, end), children), end)
}

fn find(data: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}

/// Adds the "stream", data and "endstream" blocks and returns the position
/// after "endstream" (or the end of data if it's missing).
fn stream_blocks(
    data: &[u8],
    keyword: Token,
    dict: Option<&Dict>,
    children: &mut Vec<Block>,
) -> usize {
    let data_start = eol_end(data, keyword.end);
    children.push(Block::leaf("stream", range(keyword.start, data_start)));

    let declared = dict.and_then(|d| d.uint(data, b"/Length"));
    let from_length = declared
        .and_then(|len| usize::try_from(len).ok())
        .and_then(|len| data_start.checked_add(len))
        .filter(|&end| end <= data.len())
        .and_then(|end| {
            let kw = skip_ws(data, end);
            data[kw..].starts_with(b"endstream").then_some((end, kw))
        });
    let (data_end, endstream) = match from_length {
        Some((end, kw)) => (end, Some(kw)),
        None => match find(data, data_start, b"endstream") {
            Some(kw) => {
                // The EOL before "endstream" isn't part of the data.
                let mut end = kw;
                if end > data_start && data[end - 1] == b'\n' {
                    end -= 1;
                }
                if end > data_start && data[end - 1] == b'\r' {
                    end -= 1;
                }
                (end, Some(kw))
            }
            None => (data.len(), None),
        },
    };

    let mut label = format!("Stream data ({} bytes", data_end - data_start);
    let filters = dict.map(|d| d.filters(data)).unwrap_or_default();
    if !filters.is_empty() {
        label.push_str(&format!(", {}", filters.join(", ")));
    }
    if let Some(len) = declared
        && from_length.is_none()
    {
        label.push_str(&format!(", /Length {len} inconsistent"));
    }
    label.push(')');
    if data_end > data_start {
        children.push(Block::leaf(label, range(data_start, data_end)));
    }

    match endstream {
        Some(kw) => {
            let end = kw + b"endstream".len();
            children.push(Block::leaf("endstream", range(kw, end)));
            end
        }
        None => data.len(),
    }
}

// ---------------------------------------------------------------------------
// Cross-reference table and trailer

/// Parses a 20-byte xref entry "oooooooooo ggggg n\r\n", tolerating a
/// single-byte EOL. Returns (end, offset, generation, in_use).
fn xref_entry(data: &[u8], pos: usize) -> Option<(usize, u64, u64, bool)> {
    let line = data.get(pos..pos + 18)?;
    if line[10] != b' ' || line[16] != b' ' {
        return None;
    }
    let offset = parse_uint(&line[..10])?;
    let generation = parse_uint(&line[11..16])?;
    let in_use = match line[17] {
        b'n' => true,
        b'f' => false,
        _ => return None,
    };
    let mut end = pos + 18;
    while end < pos + 20 && matches!(data.get(end), Some(b' ' | b'\r' | b'\n')) {
        end += 1;
    }
    Some((end, offset, generation, in_use))
}

fn xref_block(data: &[u8], keyword: Token) -> (Block, usize) {
    let mut children = vec![Block::leaf("xref", range(keyword.start, keyword.end))];
    let mut end = keyword.end;
    let mut shown = 0usize;

    loop {
        let Some(a) = next_token(data, end) else {
            break;
        };
        let Some(first) = a.uint(data) else { break };
        let Some(b) = next_token(data, a.end) else {
            break;
        };
        let Some(count) = b.uint(data) else { break };
        // "N G obj" after a table with no trailer is an object, not a subsection.
        if next_token(data, b.end).is_some_and(|t| t.is_keyword(data, b"obj")) {
            break;
        }

        let mut sub = vec![Block::leaf(
            format!("Subsection header: {first} {count}"),
            range(a.start, b.end),
        )];
        let mut pos = skip_ws(data, b.end);
        let mut parsed = 0u64;
        let mut entries_end = b.end;
        let (mut hidden, mut hidden_start) = (0u64, 0usize);
        while parsed < count {
            let Some((entry_end, offset, generation, in_use)) = xref_entry(data, pos) else {
                break;
            };
            let num = first.saturating_add(parsed);
            if shown < MAX_XREF_ENTRIES_SHOWN {
                shown += 1;
                let label = if in_use {
                    format!("Object {num}: offset {offset}, gen {generation}")
                } else {
                    format!("Object {num}: free, next {offset}, gen {generation}")
                };
                sub.push(Block::leaf(label, range(pos, entry_end)));
            } else {
                if hidden == 0 {
                    hidden_start = pos;
                }
                hidden += 1;
            }
            parsed += 1;
            pos = entry_end;
            entries_end = entry_end;
        }
        if hidden > 0 {
            sub.push(Block::leaf(
                format!("({hidden} more entries not shown)"),
                range(hidden_start, entries_end),
            ));
        }
        let label = if parsed == 0 {
            format!("Subsection (first {first}, 0 entries)")
        } else {
            format!(
                "Subsection (objects {first}-{}, {parsed} entries)",
                first.saturating_add(parsed - 1)
            )
        };
        children.push(Block::node(label, range(a.start, entries_end), sub));
        end = entries_end;
        if parsed < count {
            break;
        }
    }

    (
        Block::node("Cross-reference table", range(keyword.start, end), children),
        end,
    )
}

fn trailer_block(data: &[u8], keyword: Token) -> (Block, usize) {
    let mut children = vec![Block::leaf("trailer", range(keyword.start, keyword.end))];
    let mut end = keyword.end;
    if let Some(t) = next_token(data, end)
        && t.kind == Kind::DictOpen
    {
        let dict = parse_dict(data, t);
        children.push(dict_block(data, &dict).expanded());
        end = dict.end;
    }
    (
        Block::node("Trailer", range(keyword.start, end), children).expanded(),
        end,
    )
}

fn startxref_block(data: &[u8], keyword: Token) -> (Block, usize) {
    if let Some(t) = next_token(data, keyword.end)
        && let Some(offset) = t.uint(data)
    {
        return (
            Block::leaf(format!("startxref: {offset}"), range(keyword.start, t.end)),
            t.end,
        );
    }
    (
        Block::leaf("startxref", range(keyword.start, keyword.end)),
        keyword.end,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a PDF from object bodies (the text between "N 0 obj" and
    /// "endobj"), with a correct xref table. Returns the data and each
    /// object's offset.
    fn build_pdf(objects: &[&[u8]]) -> (Vec<u8>, Vec<usize>) {
        let mut data = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objects.iter().enumerate() {
            offsets.push(data.len());
            data.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            data.extend_from_slice(body);
            data.extend_from_slice(b"\nendobj\n");
        }
        let xref = data.len();
        data.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        data.extend_from_slice(b"0000000000 65535 f\r\n");
        for off in &offsets {
            data.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }
        data.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        (data, offsets)
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn find_prefix<'a>(blocks: &'a [Block], prefix: &str) -> &'a Block {
        blocks
            .iter()
            .find(|b| b.label.starts_with(prefix))
            .unwrap_or_else(|| {
                panic!(
                    "block starting {prefix:?} not found; have {:?}",
                    blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
                )
            })
    }

    fn sample() -> (Vec<u8>, Vec<usize>) {
        build_pdf(&[
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
            // Stream data containing fake keywords; /Length must win.
            b"<< /Length 21 /Filter /FlateDecode >>\nstream\nendstream endobj xref\nendstream",
        ])
    }

    #[test]
    fn matches_pdf_magic() {
        assert!(PdfDissector.matches(&sample().0));
        assert!(PdfDissector.matches(b"%PDF-2.0\n"));
        assert!(PdfDissector.matches(b"junk\r\n%PDF-1.4\n"));
    }

    #[test]
    fn does_not_match_non_pdf_data() {
        assert!(!PdfDissector.matches(b""));
        assert!(!PdfDissector.matches(b"%PDF"));
        assert!(!PdfDissector.matches(b"%PDF-"));
        assert!(!PdfDissector.matches(b"%PDF-x"));
        assert!(!PdfDissector.matches(b"not a pdf file"));
        assert!(!PdfDissector.matches(b"see %PDF-1.4 for details"));
        let mut late = vec![b'\n'; 1100];
        late.extend_from_slice(b"%PDF-1.4\n");
        assert!(!PdfDissector.matches(&late));
    }

    #[test]
    fn dissect_parses_header() {
        let (data, _) = sample();
        let blocks = PdfDissector.dissect(&data);
        let header = find_block(&blocks, "Header (PDF 1.7)");
        assert_eq!(header.range, ByteRange::new(0, 9));
        assert_eq!(
            find_block(&header.children, "Version: 1.7").range,
            ByteRange::new(5, 8)
        );
        let binary = find_block(&blocks, "Binary marker comment");
        assert_eq!(binary.range, ByteRange::new(9, 15));
    }

    #[test]
    fn dissect_parses_objects() {
        let (data, offsets) = sample();
        let blocks = PdfDissector.dissect(&data);
        let body = find_block(&blocks, "Body (4 objects)");
        assert_eq!(body.range.start, offsets[0] as u64);

        let catalog = find_block(&body.children, "Object 1 0 (/Type /Catalog)");
        assert_eq!(
            catalog.range,
            ByteRange::new(offsets[0] as u64, (offsets[1] - 1) as u64)
        );
        let dict = find_block(&catalog.children, "Dictionary (2 entries)");
        assert!(dict.children.iter().any(|b| b.label == "/Pages 2 0 R"));
        find_block(&catalog.children, "endobj");
        find_block(&body.children, "Object 2 0 (/Type /Pages)");
        let page = find_block(&body.children, "Object 3 0 (/Type /Page)");
        find_block(&page.children, "Dictionary (3 entries)");
    }

    #[test]
    fn dissect_uses_stream_length() {
        let (data, offsets) = sample();
        let blocks = PdfDissector.dissect(&data);
        let body = find_block(&blocks, "Body (4 objects)");
        let obj = find_block(&body.children, "Object 4 0 (stream)");
        let stream_kw = find_block(&obj.children, "stream");
        let stream_data = find_block(&obj.children, "Stream data (21 bytes, FlateDecode)");
        assert_eq!(stream_data.range.start, stream_kw.range.end);
        assert_eq!(stream_data.range.end - stream_data.range.start, 21);
        let endstream = find_block(&obj.children, "endstream");
        assert_eq!(endstream.range.start, stream_data.range.end + 1);
        assert_eq!(obj.range.start, offsets[3] as u64);
        // The fake "xref" inside the stream must not produce a table.
        let xrefs = blocks
            .iter()
            .filter(|b| b.label == "Cross-reference table")
            .count();
        assert_eq!(xrefs, 1);
    }

    #[test]
    fn dissect_scans_for_endstream_when_length_is_wrong() {
        let (data, _) = build_pdf(&[
            b"<< /Length 999 /Filter [/ASCIIHexDecode /DCTDecode] >>\nstream\r\nABCD\r\nendstream",
            b"<< /Length 5 0 R >>\nstream\nxyz\nendstream",
        ]);
        let blocks = PdfDissector.dissect(&data);
        let body = find_block(&blocks, "Body (2 objects)");
        let obj1 = find_block(&body.children, "Object 1 0 (stream)");
        let s = find_block(
            &obj1.children,
            "Stream data (4 bytes, ASCIIHexDecode, DCTDecode, /Length 999 inconsistent)",
        );
        assert_eq!(&data[s.range.start as usize..s.range.end as usize], b"ABCD");
        let obj2 = find_block(&body.children, "Object 2 0 (stream)");
        let s = find_block(&obj2.children, "Stream data (3 bytes)");
        assert_eq!(&data[s.range.start as usize..s.range.end as usize], b"xyz");
    }

    #[test]
    fn dissect_parses_xref_trailer_and_eof() {
        let (data, offsets) = sample();
        let blocks = PdfDissector.dissect(&data);
        let xref = find_block(&blocks, "Cross-reference table");
        let sub = find_block(&xref.children, "Subsection (objects 0-4, 5 entries)");
        find_block(&sub.children, "Subsection header: 0 5");
        let free = find_block(&sub.children, "Object 0: free, next 0, gen 65535");
        assert_eq!(free.range.end - free.range.start, 20);
        find_block(
            &sub.children,
            &format!("Object 3: offset {}, gen 0", offsets[2]),
        );

        let trailer = find_block(&blocks, "Trailer");
        let dict = find_block(&trailer.children, "Dictionary (2 entries)");
        assert!(dict.children.iter().any(|b| b.label == "/Size 5"));
        assert!(dict.children.iter().any(|b| b.label == "/Root 1 0 R"));

        find_block(&blocks, &format!("startxref: {}", xref.range.start));
        let eof = find_block(&blocks, "%%EOF");
        assert_eq!(eof.range.end as usize, data.len() - 1);
    }

    #[test]
    fn dissect_shows_incremental_updates_as_revisions() {
        let (mut data, _) = sample();
        let off = data.len();
        data.extend_from_slice(b"3 0 obj\n<< /Type /Page /Subtype /Odd >>\nendobj\n");
        let xref = data.len();
        data.extend_from_slice(b"xref\n0 1\n0000000000 65535 f\r\n3 1\n");
        data.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        data.extend_from_slice(
            format!("trailer\n<< /Size 5 /Root 1 0 R /Prev 1 >>\nstartxref\n{xref}\n%%EOF\n")
                .as_bytes(),
        );
        let blocks = PdfDissector.dissect(&data);
        let r1 = find_block(&blocks, "Revision 1");
        find_block(&r1.children, "Body (4 objects)");
        let r2 = find_block(&blocks, "Revision 2");
        assert_eq!(r2.range.start, off as u64);
        let body = find_block(&r2.children, "Body (1 object)");
        find_block(&body.children, "Object 3 0 (/Type /Page /Subtype /Odd)");
        let xref_block = find_block(&r2.children, "Cross-reference table");
        assert_eq!(xref_block.children.len(), 3);
        find_block(&r2.children, "Trailer");
        find_block(&r2.children, "%%EOF");
    }

    #[test]
    fn dissect_caps_objects_shown() {
        let bodies: Vec<&[u8]> = vec![b"42" as &[u8]; MAX_OBJECTS_SHOWN + 5];
        let (data, _) = build_pdf(&bodies);
        let blocks = PdfDissector.dissect(&data);
        let body = find_block(
            &blocks,
            &format!("Body ({} objects)", MAX_OBJECTS_SHOWN + 5),
        );
        assert_eq!(body.children.len(), MAX_OBJECTS_SHOWN + 1);
        find_block(&body.children, "(5 more objects not shown)");
        find_block(&body.children[0].children, "Value: 42");
    }

    #[test]
    fn dissect_recovers_from_missing_endobj() {
        let data =
            b"%PDF-1.4\n1 0 obj\n<< /A (str with endobj inside) >>\n2 0 obj\n[1 2]\nendobj\n";
        let blocks = PdfDissector.dissect(data);
        let body = find_block(&blocks, "Body (2 objects)");
        let first = find_prefix(&body.children, "Object 1 0");
        assert!(first.children.iter().all(|b| b.label != "endobj"));
        let second = find_prefix(&body.children, "Object 2 0");
        assert_eq!(second.range.start, first.range.end);
        find_block(&second.children, "Value: [1 2]");
    }

    #[test]
    fn dissect_handles_leading_junk() {
        let data = b"junk\n%PDF-1.3\n%%EOF";
        let blocks = PdfDissector.dissect(data);
        assert_eq!(
            find_block(&blocks, "Leading data (5 bytes)").range,
            ByteRange::new(0, 5)
        );
        assert_eq!(
            find_block(&blocks, "Header (PDF 1.3)").range,
            ByteRange::new(5, 14)
        );
        find_block(&blocks, "%%EOF");
    }

    #[test]
    fn dissect_truncated_input_returns_fewer_blocks() {
        assert!(PdfDissector.dissect(b"").is_empty());
        assert!(PdfDissector.dissect(b"%PDF").is_empty());
        let (data, _) = sample();
        let full = PdfDissector.dissect(&data).len();
        for cut in 0..data.len() {
            let blocks = PdfDissector.dissect(&data[..cut]);
            assert!(blocks.len() <= full);
        }
        assert_eq!(PdfDissector.dissect(b"%PDF-1.5").len(), 1);
    }

    #[test]
    fn identify_reports_pdf() {
        let (data, _) = sample();
        assert_eq!(super::super::identify(&data), "PDF");
    }
}
