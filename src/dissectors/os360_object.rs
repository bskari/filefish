//! IBM OS/360 (OS/VS, MVS, z/OS) object module ("object deck").
//!
//! An object deck is a sequence of 80-byte EBCDIC card images. Each card
//! starts with X'02' (the 12-2-9 punch) followed by a 3-character record type
//! (ESD, TXT, RLD, END, SYM, XSD); columns 73-80 hold a deck ID / sequence
//! number. Linkage editor control statements (NAME, ENTRY, ...) may be mixed
//! in as plain EBCDIC text cards.

use std::collections::HashMap;

use super::{Block, ByteRange, Dissector};

const CARD_LEN: usize = 80;
/// Column 1 of every object module record: the 12-2-9 punch.
const CARD_FLAG: u8 = 0x02;
/// Columns 17-72 hold the variable data of ESD, TXT, RLD and SYM records.
const DATA_START: usize = 16;
const DATA_END: usize = 72;
const ESD_ITEM_LEN: usize = 16;
const IDR_ITEM_LEN: usize = 19;
/// EBCDIC blank, used to mark absent fields.
const BLANK: u8 = 0x40;

/// Most cards shown individually before the rest are summarized.
const MAX_CARDS: usize = 4096;
/// Most RLD entries decoded per card (a full card holds at most 14).
const MAX_RLD_ENTRIES: usize = 16;

#[derive(Clone, Copy, PartialEq, Debug)]
enum RecordType {
    Esd,
    Txt,
    Rld,
    End,
    Sym,
    Xsd,
}

impl RecordType {
    fn from_ebcdic(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0xC5, 0xE2, 0xC4] => Some(Self::Esd),
            [0xE3, 0xE7, 0xE3] => Some(Self::Txt),
            [0xD9, 0xD3, 0xC4] => Some(Self::Rld),
            [0xC5, 0xD5, 0xC4] => Some(Self::End),
            [0xE2, 0xE8, 0xD4] => Some(Self::Sym),
            [0xE7, 0xE2, 0xC4] => Some(Self::Xsd),
            _ => None,
        }
    }
}

pub struct Os360ObjectDissector;

impl Dissector for Os360ObjectDissector {
    fn name(&self) -> &'static str {
        "OS/360 Object Module"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < CARD_LEN || !is_object_record(data, 0) {
            return false;
        }
        // If a second card is present, it must also be an object record.
        data.len() < CARD_LEN + 4 || is_object_record(data, CARD_LEN)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut names: HashMap<u16, String> = HashMap::new();
        let mut start = 0;
        let mut index = 0;
        while start < data.len() {
            if index == MAX_CARDS {
                let remaining = (data.len() - start).div_ceil(CARD_LEN);
                blocks.push(Block::leaf(
                    format!("… {remaining} more cards"),
                    span(start, data.len()),
                ));
                break;
            }
            let end = (start + CARD_LEN).min(data.len());
            blocks.push(card_block(data, start, end, index + 1, &mut names));
            start = end;
            index += 1;
        }
        blocks
    }
}

fn is_object_record(data: &[u8], offset: usize) -> bool {
    data.get(offset) == Some(&CARD_FLAG)
        && data
            .get(offset + 1..offset + 4)
            .and_then(RecordType::from_ebcdic)
            .is_some()
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u24_be(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 3)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == BLANK)
}

/// Builds the EBCDIC (code page 037) to ASCII table. Characters with no ASCII
/// equivalent, and control characters, map to '.'.
const fn build_ebcdic_table() -> [u8; 256] {
    let mut t = [b'.'; 256];
    t[0x40] = b' ';
    t[0x4B] = b'.';
    t[0x4C] = b'<';
    t[0x4D] = b'(';
    t[0x4E] = b'+';
    t[0x4F] = b'|';
    t[0x50] = b'&';
    t[0x5A] = b'!';
    t[0x5B] = b'$';
    t[0x5C] = b'*';
    t[0x5D] = b')';
    t[0x5E] = b';';
    t[0x60] = b'-';
    t[0x61] = b'/';
    t[0x6B] = b',';
    t[0x6C] = b'%';
    t[0x6D] = b'_';
    t[0x6E] = b'>';
    t[0x6F] = b'?';
    t[0x79] = b'`';
    t[0x7A] = b':';
    t[0x7B] = b'#';
    t[0x7C] = b'@';
    t[0x7D] = b'\'';
    t[0x7E] = b'=';
    t[0x7F] = b'"';
    t[0xA1] = b'~';
    t[0xB0] = b'^';
    t[0xBA] = b'[';
    t[0xBB] = b']';
    t[0xC0] = b'{';
    t[0xD0] = b'}';
    t[0xE0] = b'\\';
    let mut i = 0;
    while i < 9 {
        t[0x81 + i] = b'a' + i as u8;
        t[0x91 + i] = b'j' + i as u8;
        t[0xC1 + i] = b'A' + i as u8;
        t[0xD1 + i] = b'J' + i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 8 {
        t[0xA2 + i] = b's' + i as u8;
        t[0xE2 + i] = b'S' + i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 10 {
        t[0xF0 + i] = b'0' + i as u8;
        i += 1;
    }
    t
}

const EBCDIC_TO_ASCII: [u8; 256] = build_ebcdic_table();

fn ebcdic(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| EBCDIC_TO_ASCII[b as usize] as char)
        .collect()
}

/// EBCDIC text with trailing blanks removed.
fn ebcdic_trimmed(bytes: &[u8]) -> String {
    ebcdic(bytes).trim_end().to_string()
}

/// Accumulates leaves for one card, clamping each field to the card's
/// (possibly truncated) extent.
struct Fields<'a> {
    data: &'a [u8],
    base: usize,
    end: usize,
    children: Vec<Block>,
}

impl<'a> Fields<'a> {
    /// Bytes of the field at card columns `rel..rel + len` (0-based), only if
    /// the whole field is present.
    fn bytes(&self, rel: usize, len: usize) -> Option<&'a [u8]> {
        let start = self.base + rel;
        if start + len > self.end {
            return None;
        }
        self.data.get(start..start + len)
    }

    fn range(&self, rel: usize, len: usize) -> ByteRange {
        span(self.base + rel, self.base + rel + len)
    }

    fn leaf(&mut self, label: String, rel: usize, len: usize) {
        if self.bytes(rel, len).is_some() {
            self.children.push(Block::leaf(label, self.range(rel, len)));
        }
    }
}

fn esdid_text(id: u16, names: &HashMap<u16, String>) -> String {
    match names.get(&id) {
        Some(name) if !name.is_empty() => format!("{id} ({name})"),
        _ => id.to_string(),
    }
}

fn card_block(
    data: &[u8],
    start: usize,
    end: usize,
    number: usize,
    names: &mut HashMap<u16, String>,
) -> Block {
    let card = &data[start..end];
    let truncated = card.len() < CARD_LEN;
    let mut f = Fields {
        data,
        base: start,
        end,
        children: Vec::new(),
    };

    let record_type = if card.first() == Some(&CARD_FLAG) {
        card.get(1..4).and_then(RecordType::from_ebcdic)
    } else {
        None
    };

    let summary = if card.first() != Some(&CARD_FLAG) {
        let text = ebcdic_trimmed(card.get(..DATA_END).unwrap_or(card));
        let text = text.trim();
        f.leaf(
            format!("Statement: \"{text}\""),
            0,
            card.len().min(DATA_END),
        );
        format!("control statement \"{text}\"")
    } else {
        f.leaf("Flag: 0x02 (12-2-9 punch)".to_string(), 0, 1);
        let type_text = card.get(1..4).map(ebcdic).unwrap_or_default();
        f.leaf(format!("Record type: {type_text}"), 1, 3);
        match record_type {
            Some(RecordType::Esd) => esd_fields(&mut f, names),
            Some(RecordType::Txt) => txt_fields(&mut f, names),
            Some(RecordType::Rld) => rld_fields(&mut f, names),
            Some(RecordType::End) => end_fields(&mut f, names),
            Some(RecordType::Sym) => counted_data_fields(&mut f, "SYM", false),
            Some(RecordType::Xsd) => counted_data_fields(&mut f, "XSD", true),
            None => {
                let len = card.len().min(DATA_END).saturating_sub(4);
                f.leaf("Data (unknown record type)".to_string(), 4, len);
                format!("unknown record type \"{type_text}\"")
            }
        }
    };

    if let Some(seq) = f.bytes(DATA_END, CARD_LEN - DATA_END) {
        f.leaf(
            format!("Deck ID / sequence: \"{}\"", ebcdic(seq)),
            DATA_END,
            CARD_LEN - DATA_END,
        );
    }

    let mut label = format!("Card {number}: {summary}");
    if truncated {
        label.push_str(&format!(" (truncated, {} bytes)", card.len()));
    }
    Block::node(label, span(start, end), f.children)
}

/// Columns 11-12: byte count of the variable field, clamped to columns 17-72.
fn data_count(f: &mut Fields) -> Option<usize> {
    let count = read_u16_be(f.bytes(10, 2)?, 0)?;
    f.leaf(format!("Byte count: {count}"), 10, 2);
    Some((count as usize).min(DATA_END - DATA_START))
}

/// Columns 15-16: ESDID, or `None` when blank.
fn esdid_field(f: &mut Fields, what: &str, names: &HashMap<u16, String>) -> Option<u16> {
    let bytes = f.bytes(14, 2)?;
    if is_blank(bytes) || bytes == [0, 0] {
        f.leaf(format!("{what}: (blank)"), 14, 2);
        return None;
    }
    let id = read_u16_be(bytes, 0)?;
    f.leaf(format!("{what}: {}", esdid_text(id, names)), 14, 2);
    Some(id)
}

fn esd_type_name(code: u8) -> &'static str {
    match code {
        0x00 => "SD",
        0x01 => "LD",
        0x02 => "ER",
        0x04 => "PC",
        0x05 => "CM",
        0x06 => "XD/PR",
        0x0A => "WX",
        0x0D => "SD (quad-aligned)",
        0x0E => "PC (quad-aligned)",
        0x0F => "CM (quad-aligned)",
        _ => "unknown",
    }
}

fn esd_short_type(code: u8) -> &'static str {
    match code {
        0x0D => "SD",
        0x0E => "PC",
        0x0F => "CM",
        _ => esd_type_name(code),
    }
}

fn amode_rmode(flag: u8) -> String {
    let amode = match flag & 0x03 {
        0x02 => "31",
        0x03 => "ANY",
        _ => "24",
    };
    let rmode = if flag & 0x04 != 0 { "ANY" } else { "24" };
    format!("AMODE {amode}, RMODE {rmode}")
}

fn alignment_text(flag: u8) -> String {
    match flag {
        0x00 => "byte".to_string(),
        0x01 => "halfword".to_string(),
        0x03 => "fullword".to_string(),
        0x07 => "doubleword".to_string(),
        0x0F => "quadword".to_string(),
        _ => format!("0x{flag:02X}"),
    }
}

fn esd_fields(f: &mut Fields, names: &mut HashMap<u16, String>) -> String {
    let count = data_count(f);
    let mut next_id = esdid_field(f, "ESDID of first item", names);
    let Some(count) = count else {
        return "ESD".to_string();
    };

    let mut summaries = Vec::new();
    let mut item_rel = DATA_START;
    while item_rel + ESD_ITEM_LEN <= DATA_START + count {
        let Some(item) = f.bytes(item_rel, ESD_ITEM_LEN) else {
            break;
        };
        let name = ebcdic_trimmed(&item[..8]);
        let code = item[8];
        let address = read_u24_be(item, 9).unwrap_or(0);
        let flag = item[12];
        let tail = read_u24_be(item, 13).unwrap_or(0);
        let tail_blank = is_blank(&item[13..16]);
        let is_ld = code == 0x01;

        // LD items have no ESDID of their own; every other type takes the
        // next one in sequence.
        let id = if is_ld {
            None
        } else {
            let id = next_id;
            next_id = next_id.map(|n| n.wrapping_add(1));
            id
        };
        if let Some(id) = id {
            names.insert(id, name.clone());
        }

        let short = esd_short_type(code);
        let mut label = format!("{short} {name}");
        if let Some(id) = id {
            label.push_str(&format!(" (ESDID {id})"));
        }
        let mut children = vec![
            Block::leaf(format!("Name: \"{name}\""), f.range(item_rel, 8)),
            Block::leaf(
                format!("Type: 0x{code:02X} ({})", esd_type_name(code)),
                f.range(item_rel + 8, 1),
            ),
        ];
        let addr_label = if matches!(code, 0x02 | 0x0A) {
            "Address: (unused)".to_string()
        } else {
            label.push_str(&format!(" addr 0x{address:06X}"));
            format!("Address: 0x{address:06X}")
        };
        children.push(Block::leaf(addr_label, f.range(item_rel + 9, 3)));
        let flag_label = match code {
            0x00 | 0x04 | 0x05 | 0x0D | 0x0E | 0x0F => {
                format!("Flags: 0x{flag:02X} ({})", amode_rmode(flag))
            }
            0x06 => format!("Alignment: {}", alignment_text(flag)),
            _ => format!("Flags: 0x{flag:02X}"),
        };
        children.push(Block::leaf(flag_label, f.range(item_rel + 12, 1)));
        let tail_label = if is_ld {
            let owner = read_u16_be(item, 14).unwrap_or(0);
            label.push_str(&format!(" in ESDID {owner}"));
            format!("Owning ESDID: {}", esdid_text(owner, names))
        } else if matches!(code, 0x02 | 0x0A) || tail_blank {
            "Length: (unused)".to_string()
        } else {
            label.push_str(&format!(" len 0x{tail:06X}"));
            format!("Length: 0x{tail:06X} ({tail})")
        };
        children.push(Block::leaf(tail_label, f.range(item_rel + 13, 3)));

        f.children.push(Block::node(
            label,
            f.range(item_rel, ESD_ITEM_LEN),
            children,
        ));
        summaries.push(format!("{short} {name}"));
        item_rel += ESD_ITEM_LEN;
    }

    if summaries.is_empty() {
        "ESD, no items".to_string()
    } else {
        format!(
            "ESD, {} item{} ({})",
            summaries.len(),
            if summaries.len() == 1 { "" } else { "s" },
            summaries.join(", ")
        )
    }
}

fn txt_fields(f: &mut Fields, names: &HashMap<u16, String>) -> String {
    let address = f.bytes(5, 3).and_then(|b| read_u24_be(b, 0));
    if let Some(address) = address {
        f.leaf(format!("Address: 0x{address:06X}"), 5, 3);
    }
    let count = data_count(f);
    let id = esdid_field(f, "ESDID", names);
    if let Some(count) = count {
        let available = f.end.saturating_sub(f.base + DATA_START).min(count);
        if available > 0 {
            f.leaf(format!("Text ({available} bytes)"), DATA_START, available);
        }
    }
    let mut summary = "TXT".to_string();
    if let Some(address) = address {
        summary.push_str(&format!(" addr 0x{address:06X}"));
    }
    if let Some(count) = count {
        summary.push_str(&format!(", {count} bytes"));
    }
    if let Some(id) = id {
        summary.push_str(&format!(", ESDID {}", esdid_text(id, names)));
    }
    summary
}

fn rld_type_name(code: u8) -> &'static str {
    match code {
        0x0 => "A",
        0x1 => "V",
        0x2 => "Q",
        0x3 => "CXD",
        _ => "?",
    }
}

fn rld_fields(f: &mut Fields, names: &HashMap<u16, String>) -> String {
    let Some(count) = data_count(f) else {
        return "RLD".to_string();
    };
    let limit = (DATA_START + count).min(f.end - f.base);
    let mut rel = DATA_START;
    let mut same_rp = false;
    let mut rp = (0u16, 0u16);
    let mut entries = 0;
    while rel < limit {
        if entries == MAX_RLD_ENTRIES {
            f.children
                .push(Block::leaf("… more entries", f.range(rel, limit - rel)));
            break;
        }
        let entry_start = rel;
        let mut children = Vec::new();
        if !same_rp {
            let Some(b) = f.bytes(rel, 4).filter(|_| rel + 4 <= limit) else {
                break;
            };
            rp = (
                read_u16_be(b, 0).unwrap_or(0),
                read_u16_be(b, 2).unwrap_or(0),
            );
            children.push(Block::leaf(
                format!("R pointer (ESDID): {}", esdid_text(rp.0, names)),
                f.range(rel, 2),
            ));
            children.push(Block::leaf(
                format!("P pointer (ESDID): {}", esdid_text(rp.1, names)),
                f.range(rel + 2, 2),
            ));
            rel += 4;
        }
        let Some(b) = f.bytes(rel, 4).filter(|_| rel + 4 <= limit) else {
            break;
        };
        let flag = b[0];
        let address = read_u24_be(b, 1).unwrap_or(0);
        let kind = rld_type_name(flag >> 4);
        let length = ((flag >> 2) & 0x03) + 1;
        let sign = if flag & 0x02 != 0 { '-' } else { '+' };
        let next_same = flag & 0x01 != 0;
        children.push(Block::leaf(
            format!(
                "Flags: 0x{flag:02X} (type {kind}, length {length}, {sign}{})",
                if next_same {
                    ", next entry same R/P"
                } else {
                    ""
                }
            ),
            f.range(rel, 1),
        ));
        children.push(Block::leaf(
            format!("Address: 0x{address:06X}"),
            f.range(rel + 1, 3),
        ));
        rel += 4;
        entries += 1;
        let label = format!(
            "Entry {entries}: {kind}({length}) {sign}, R {} P {}, addr 0x{address:06X}{}",
            rp.0,
            rp.1,
            if same_rp { " (same R/P)" } else { "" }
        );
        f.children.push(Block::node(
            label,
            f.range(entry_start, rel - entry_start),
            children,
        ));
        same_rp = next_same;
    }
    format!(
        "RLD, {entries} entr{}",
        if entries == 1 { "y" } else { "ies" }
    )
}

fn end_fields(f: &mut Fields, names: &HashMap<u16, String>) -> String {
    let mut summary = "END".to_string();
    let entry = f
        .bytes(5, 3)
        .filter(|b| !is_blank(b))
        .and_then(|b| read_u24_be(b, 0));
    if let Some(address) = entry {
        f.leaf(format!("Entry address: 0x{address:06X}"), 5, 3);
        summary.push_str(&format!(" entry 0x{address:06X}"));
    }
    if let Some(id) = esdid_field(f, "Entry ESDID", names) {
        summary.push_str(&format!(" ESDID {}", esdid_text(id, names)));
    } else if let Some(name) = f.bytes(16, 8).filter(|b| !is_blank(b)) {
        // Type 2 END: the entry point is given by name instead.
        let name = ebcdic_trimmed(name);
        f.leaf(format!("Entry name: \"{name}\""), 16, 8);
        summary.push_str(&format!(" entry {name}"));
    }
    if let Some(len) = f
        .bytes(28, 4)
        .filter(|b| !is_blank(b) && b.iter().any(|&x| x != 0))
    {
        let len = read_u32_be(len, 0).unwrap_or(0);
        f.leaf(format!("Control section length: 0x{len:X} ({len})"), 28, 4);
        summary.push_str(&format!(", length 0x{len:X}"));
    }
    let idr_count = match f.bytes(32, 1) {
        Some([0xF1]) => 1,
        Some([0xF2]) => 2,
        _ => 0,
    };
    if idr_count > 0 {
        f.leaf(format!("IDR item count: {idr_count}"), 32, 1);
        for i in 0..idr_count {
            let rel = 33 + i * IDR_ITEM_LEN;
            let Some(item) = f.bytes(rel, IDR_ITEM_LEN) else {
                break;
            };
            let translator = ebcdic_trimmed(&item[..10]);
            let version = ebcdic(&item[10..12]);
            let modlevel = ebcdic(&item[12..14]);
            let date = ebcdic(&item[14..19]);
            let children = vec![
                Block::leaf(format!("Translator ID: \"{translator}\""), f.range(rel, 10)),
                Block::leaf(format!("Version: {version}"), f.range(rel + 10, 2)),
                Block::leaf(
                    format!("Modification level: {modlevel}"),
                    f.range(rel + 12, 2),
                ),
                Block::leaf(format!("Date (yyddd): {date}"), f.range(rel + 14, 5)),
            ];
            f.children.push(Block::node(
                format!("IDR {}: {translator} V{version} M{modlevel}, {date}", i + 1),
                f.range(rel, IDR_ITEM_LEN),
                children,
            ));
        }
        summary.push_str(&format!(
            ", {idr_count} IDR item{}",
            if idr_count == 1 { "" } else { "s" }
        ));
    }
    summary
}

fn counted_data_fields(f: &mut Fields, name: &str, has_esdid: bool) -> String {
    let count = data_count(f);
    if has_esdid {
        esdid_field(f, "ESDID", &HashMap::new());
    }
    let Some(count) = count else {
        return name.to_string();
    };
    let available = f.end.saturating_sub(f.base + DATA_START).min(count);
    if available > 0 {
        f.leaf(format!("Data ({available} bytes)"), DATA_START, available);
    }
    format!("{name}, {count} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESD: [u8; 3] = [0xC5, 0xE2, 0xC4];
    const TXT: [u8; 3] = [0xE3, 0xE7, 0xE3];
    const RLD: [u8; 3] = [0xD9, 0xD3, 0xC4];
    const END: [u8; 3] = [0xC5, 0xD5, 0xC4];
    const SYM: [u8; 3] = [0xE2, 0xE8, 0xD4];

    fn to_ebcdic(s: &str) -> Vec<u8> {
        s.bytes()
            .map(|c| {
                EBCDIC_TO_ASCII
                    .iter()
                    .position(|&a| a == c)
                    .expect("char in table") as u8
            })
            .collect()
    }

    fn name8(s: &str) -> Vec<u8> {
        to_ebcdic(&format!("{s:<8}"))
    }

    /// One card with the given type, columns 5-72 from `body` (0-based offset
    /// 4 onward), and a sequence number.
    fn card(kind: [u8; 3], body: &[(usize, &[u8])], seq: u32) -> Vec<u8> {
        let mut c = vec![BLANK; CARD_LEN];
        c[0] = CARD_FLAG;
        c[1..4].copy_from_slice(&kind);
        for (off, bytes) in body {
            c[*off..*off + bytes.len()].copy_from_slice(bytes);
        }
        c[72..80].copy_from_slice(&to_ebcdic(&format!("TEST{seq:04}")));
        c
    }

    fn esd_item(name: &str, code: u8, addr: u32, flag: u8, tail: u32) -> Vec<u8> {
        let mut v = name8(name);
        v.push(code);
        v.extend_from_slice(&addr.to_be_bytes()[1..]);
        v.push(flag);
        v.extend_from_slice(&tail.to_be_bytes()[1..]);
        v
    }

    fn build_deck() -> Vec<u8> {
        let mut items = esd_item("MAIN", 0x00, 0, 0x02, 0x120);
        items.extend(esd_item("ENTRY1", 0x01, 0x10, 0x00, 1));
        items.extend(esd_item("SUB", 0x02, 0, 0x00, 0));
        let esd = card(
            ESD,
            &[
                (10, &48u16.to_be_bytes()),
                (14, &1u16.to_be_bytes()),
                (16, &items),
            ],
            1,
        );

        let text: Vec<u8> = (0..56).collect();
        let txt = card(
            TXT,
            &[
                (5, &[0x00, 0x01, 0x20]),
                (10, &56u16.to_be_bytes()),
                (14, &1u16.to_be_bytes()),
                (16, &text),
            ],
            2,
        );

        // Entry 1: R=2 P=1, V(4) with "same R/P" set; entry 2 reuses them;
        // entry 3: R=1 P=1, A(4) -.
        let rld_data = [
            0x00, 0x02, 0x00, 0x01, 0x1D, 0x00, 0x00, 0x40, //
            0x0C, 0x00, 0x00, 0x44, //
            0x00, 0x01, 0x00, 0x01, 0x0E, 0x00, 0x00, 0x48,
        ];
        let rld = card(
            RLD,
            &[
                (10, &(rld_data.len() as u16).to_be_bytes()),
                (16, &rld_data),
            ],
            3,
        );

        let sym = card(SYM, &[(10, &4u16.to_be_bytes()), (16, &[1, 2, 3, 4])], 4);

        let mut idr = vec![0xF1];
        idr.extend(to_ebcdic("569623400 0106"));
        idr.extend(to_ebcdic("26123"));
        let end = card(
            END,
            &[(5, &[0, 0, 0]), (14, &1u16.to_be_bytes()), (32, &idr)],
            5,
        );

        [esd, txt, rld, sym, end].concat()
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
    fn matches_deck() {
        assert!(Os360ObjectDissector.matches(&build_deck()));
        assert!(Os360ObjectDissector.matches(&build_deck()[..CARD_LEN]));
    }

    #[test]
    fn rejects_non_decks() {
        assert!(!Os360ObjectDissector.matches(&[]));
        assert!(!Os360ObjectDissector.matches(&[0u8; 200]));
        assert!(!Os360ObjectDissector.matches(
            b"\x02ESD plus some ascii text padding padding padding padding padding padding pad"
        ));
        let deck = build_deck();
        assert!(!Os360ObjectDissector.matches(&deck[..40]));
        let mut bad_second = deck.clone();
        bad_second[CARD_LEN] = 0x00;
        assert!(!Os360ObjectDissector.matches(&bad_second));
    }

    #[test]
    fn identify_returns_name() {
        assert_eq!(
            super::super::identify(&build_deck()),
            "OS/360 Object Module"
        );
    }

    #[test]
    fn dissects_esd() {
        let blocks = Os360ObjectDissector.dissect(&build_deck());
        assert_eq!(blocks.len(), 5);
        let esd = find_block(&blocks, "Card 1: ESD, 3 items (SD MAIN, LD ENTRY1, ER SUB)");
        assert_eq!(esd.range, ByteRange::new(0, 80));
        let sd = find_block(
            &esd.children,
            "SD MAIN (ESDID 1) addr 0x000000 len 0x000120",
        );
        assert_eq!(sd.range, ByteRange::new(16, 32));
        find_block(&sd.children, "Flags: 0x02 (AMODE 31, RMODE 24)");
        let ld = find_block(&esd.children, "LD ENTRY1 addr 0x000010 in ESDID 1");
        find_block(&ld.children, "Owning ESDID: 1 (MAIN)");
        let er = find_block(&esd.children, "ER SUB (ESDID 2)");
        assert_eq!(er.range, ByteRange::new(48, 64));
        let seq = find_block(&esd.children, "Deck ID / sequence: \"TEST0001\"");
        assert_eq!(seq.range, ByteRange::new(72, 80));
    }

    #[test]
    fn dissects_txt_rld_sym_end() {
        let blocks = Os360ObjectDissector.dissect(&build_deck());
        let txt = find_block(
            &blocks,
            "Card 2: TXT addr 0x000120, 56 bytes, ESDID 1 (MAIN)",
        );
        let text = find_block(&txt.children, "Text (56 bytes)");
        assert_eq!(text.range, ByteRange::new(96, 152));

        let rld = find_block(&blocks, "Card 3: RLD, 3 entries");
        let e1 = find_block(&rld.children, "Entry 1: V(4) +, R 2 P 1, addr 0x000040");
        assert_eq!(e1.range, ByteRange::new(176, 184));
        find_block(&e1.children, "R pointer (ESDID): 2 (SUB)");
        let e2 = find_block(
            &rld.children,
            "Entry 2: A(4) +, R 2 P 1, addr 0x000044 (same R/P)",
        );
        assert_eq!(e2.range, ByteRange::new(184, 188));
        let e3 = find_block(&rld.children, "Entry 3: A(4) -, R 1 P 1, addr 0x000048");
        assert_eq!(e3.range, ByteRange::new(188, 196));

        let sym = find_block(&blocks, "Card 4: SYM, 4 bytes");
        let data = find_block(&sym.children, "Data (4 bytes)");
        assert_eq!(data.range, ByteRange::new(256, 260));

        let end = find_block(
            &blocks,
            "Card 5: END entry 0x000000 ESDID 1 (MAIN), 1 IDR item",
        );
        let idr = find_block(&end.children, "IDR 1: 569623400 V01 M06, 26123");
        assert_eq!(idr.range, ByteRange::new(320 + 33, 320 + 52));
    }

    #[test]
    fn handles_truncated_and_control_cards() {
        let mut deck = build_deck();
        let mut name = vec![BLANK; CARD_LEN];
        let stmt = to_ebcdic(" NAME MAIN(R)");
        name[..stmt.len()].copy_from_slice(&stmt);
        deck.extend(name);
        let blocks = Os360ObjectDissector.dissect(&deck);
        find_block(&blocks, "Card 6: control statement \"NAME MAIN(R)\"");

        let truncated = &build_deck()[..80 + 30];
        let blocks = Os360ObjectDissector.dissect(truncated);
        assert_eq!(blocks.len(), 2);
        let txt = find_block(
            &blocks,
            "Card 2: TXT addr 0x000120, 56 bytes, ESDID 1 (MAIN) (truncated, 30 bytes)",
        );
        let text = find_block(&txt.children, "Text (14 bytes)");
        assert_eq!(text.range, ByteRange::new(96, 110));

        for len in 0..build_deck().len() {
            Os360ObjectDissector.dissect(&build_deck()[..len]);
        }
    }
}
