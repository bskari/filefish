use super::{Block, ByteRange, Dissector};

const HEADER_MAGIC: &[u8] = &[0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: &[u8] = b"YZ";
const STREAM_HEADER_SIZE: u64 = 12;
const STREAM_FOOTER_SIZE: u64 = 12;

const FLAG_COMPRESSED_SIZE: u8 = 0x40;
const FLAG_UNCOMPRESSED_SIZE: u8 = 0x80;

pub struct XzDissector;

impl Dissector for XzDissector {
    fn name(&self) -> &'static str {
        "XZ"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= STREAM_HEADER_SIZE as usize && data.starts_with(HEADER_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        if data.len() < STREAM_HEADER_SIZE as usize {
            return Vec::new();
        }

        let Some(items) = locate_streams(data) else {
            return dissect_forward(data);
        };

        let single_stream = items.len() == 1;
        let mut blocks = Vec::new();
        let mut stream_number = 0;
        for item in items {
            match item {
                Item::Padding(start, end) => blocks.push(Block::leaf(
                    format!("Stream padding ({} bytes)", end - start),
                    ByteRange::new(start, end),
                )),
                Item::Stream(stream) => {
                    let children = stream_blocks(data, &stream);
                    if single_stream {
                        blocks.extend(children);
                    } else {
                        blocks.push(
                            Block::node(
                                format!("Stream {stream_number}"),
                                ByteRange::new(stream.start, stream.end),
                                children,
                            )
                            .expanded(),
                        );
                        stream_number += 1;
                    }
                }
            }
        }
        blocks
    }
}

struct Record {
    unpadded: u64,
    unpadded_range: ByteRange,
    uncompressed: u64,
    uncompressed_range: ByteRange,
}

struct Index {
    count: u64,
    count_range: ByteRange,
    records: Vec<Record>,
    padding_range: ByteRange,
    crc_offset: u64,
}

struct Stream {
    start: u64,
    index_start: u64,
    footer_start: u64,
    end: u64,
    index: Index,
}

enum Item {
    Stream(Stream),
    Padding(u64, u64),
}

fn read_u32(data: &[u8], offset: u64) -> Option<u32> {
    let offset = usize::try_from(offset).ok()?;
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: u64) -> Option<u64> {
    let offset = usize::try_from(offset).ok()?;
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn byte_at(data: &[u8], offset: u64) -> Option<u8> {
    data.get(usize::try_from(offset).ok()?).copied()
}

fn slice(data: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    data.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

/// Reads an xz variable-length integer (7 bits per byte, little-endian, at
/// most 9 bytes) that must end before `limit`. Returns the value and its end.
fn read_vli(data: &[u8], offset: u64, limit: u64) -> Option<(u64, u64)> {
    let mut value = 0u64;
    for i in 0..9u64 {
        let pos = offset.checked_add(i)?;
        if pos >= limit {
            return None;
        }
        let b = byte_at(data, pos)?;
        value |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, pos + 1));
        }
    }
    None
}

fn round_up4(n: u64) -> Option<u64> {
    n.checked_add(3).map(|v| v & !3)
}

fn check_size(check_type: u8) -> u64 {
    match check_type {
        0 => 0,
        n => 4 << ((u64::from(n) - 1) / 3),
    }
}

fn check_name(check_type: u8) -> String {
    match check_type {
        0x00 => "None".to_string(),
        0x01 => "CRC32".to_string(),
        0x04 => "CRC64".to_string(),
        0x0A => "SHA-256".to_string(),
        n => format!("reserved ({n:#04x})"),
    }
}

fn filter_name(id: u64) -> String {
    match id {
        0x03 => "Delta".to_string(),
        0x04 => "x86 BCJ".to_string(),
        0x05 => "PowerPC BCJ".to_string(),
        0x06 => "IA-64 BCJ".to_string(),
        0x07 => "ARM BCJ".to_string(),
        0x08 => "ARM-Thumb BCJ".to_string(),
        0x09 => "SPARC BCJ".to_string(),
        0x0A => "ARM64 BCJ".to_string(),
        0x0B => "RISC-V BCJ".to_string(),
        0x21 => "LZMA2".to_string(),
        n => format!("unknown ({n:#x})"),
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1 << 20 && bytes % (1 << 20) == 0 {
        format!("{} MiB", bytes >> 20)
    } else if bytes >= 1 << 10 && bytes % (1 << 10) == 0 {
        format!("{} KiB", bytes >> 10)
    } else {
        format!("{bytes} bytes")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn stream_flags_label(data: &[u8], offset: u64) -> String {
    match byte_at(data, offset + 1) {
        Some(flags) => format!("Stream flags: check type {}", check_name(flags & 0x0F)),
        None => "Stream flags".to_string(),
    }
}

fn crc32_leaf(data: &[u8], offset: u64) -> Option<Block> {
    let crc = read_u32(data, offset)?;
    Some(Block::leaf(
        format!("CRC32: {crc:#010x}"),
        ByteRange::new(offset, offset + 4),
    ))
}

/// Walks the file backwards from the end, as xz itself does: skip stream
/// padding, read the stream footer, use the backward size to find the index,
/// and use the index to find the stream header.
fn locate_streams(data: &[u8]) -> Option<Vec<Item>> {
    let mut items = Vec::new();
    let mut end = data.len() as u64;
    loop {
        let mut p = end;
        while p >= 4 && slice(data, p - 4, p)? == [0, 0, 0, 0] {
            p -= 4;
        }
        if p < end {
            items.push(Item::Padding(p, end));
        }
        end = p;

        if end < STREAM_HEADER_SIZE + STREAM_FOOTER_SIZE {
            return None;
        }
        let footer_start = end - STREAM_FOOTER_SIZE;
        if slice(data, end - 2, end)? != FOOTER_MAGIC {
            return None;
        }
        let backward_size = (u64::from(read_u32(data, footer_start + 4)?) + 1) * 4;
        let index_start = footer_start.checked_sub(backward_size)?;
        let index = parse_index(data, index_start, footer_start)?;

        let mut blocks_size = 0u64;
        for record in &index.records {
            blocks_size = blocks_size.checked_add(round_up4(record.unpadded)?)?;
        }
        let start = index_start
            .checked_sub(blocks_size)?
            .checked_sub(STREAM_HEADER_SIZE)?;
        if slice(data, start, start + HEADER_MAGIC.len() as u64)? != HEADER_MAGIC {
            return None;
        }

        items.push(Item::Stream(Stream {
            start,
            index_start,
            footer_start,
            end,
            index,
        }));
        if start == 0 {
            break;
        }
        end = start;
    }
    items.reverse();
    Some(items)
}

fn parse_index(data: &[u8], start: u64, end: u64) -> Option<Index> {
    if byte_at(data, start)? != 0 || end < start + 8 {
        return None;
    }
    let crc_offset = end - 4;
    let (count, mut pos) = read_vli(data, start + 1, crc_offset)?;
    let count_range = ByteRange::new(start + 1, pos);
    // Each record takes at least two bytes.
    if count > (crc_offset - pos) / 2 {
        return None;
    }
    let mut records = Vec::new();
    for _ in 0..count {
        let (unpadded, unpadded_end) = read_vli(data, pos, crc_offset)?;
        let (uncompressed, uncompressed_end) = read_vli(data, unpadded_end, crc_offset)?;
        records.push(Record {
            unpadded,
            unpadded_range: ByteRange::new(pos, unpadded_end),
            uncompressed,
            uncompressed_range: ByteRange::new(unpadded_end, uncompressed_end),
        });
        pos = uncompressed_end;
    }
    let padding_end = start + round_up4(pos - start)?;
    if padding_end != crc_offset {
        return None;
    }
    Some(Index {
        count,
        count_range,
        records,
        padding_range: ByteRange::new(pos, padding_end),
        crc_offset,
    })
}

fn stream_header_block(data: &[u8], start: u64) -> Option<Block> {
    let end = start + STREAM_HEADER_SIZE;
    slice(data, start, end)?;
    Some(
        Block::node(
            "Stream header",
            ByteRange::new(start, end),
            vec![
                Block::leaf("Magic: FD 37 7A 58 5A 00", ByteRange::new(start, start + 6)),
                Block::leaf(
                    stream_flags_label(data, start + 6),
                    ByteRange::new(start + 6, start + 8),
                ),
                crc32_leaf(data, start + 8)?,
            ],
        )
        .expanded(),
    )
}

fn stream_footer_block(data: &[u8], start: u64) -> Option<Block> {
    let backward = (u64::from(read_u32(data, start + 4)?) + 1) * 4;
    Some(
        Block::node(
            "Stream footer",
            ByteRange::new(start, start + STREAM_FOOTER_SIZE),
            vec![
                crc32_leaf(data, start)?,
                Block::leaf(
                    format!("Backward size: {backward} bytes"),
                    ByteRange::new(start + 4, start + 8),
                ),
                Block::leaf(
                    stream_flags_label(data, start + 8),
                    ByteRange::new(start + 8, start + 10),
                ),
                Block::leaf("Magic: YZ", ByteRange::new(start + 10, start + 12)),
            ],
        )
        .expanded(),
    )
}

fn index_block(data: &[u8], stream: &Stream) -> Block {
    let index = &stream.index;
    let start = stream.index_start;
    let mut children = vec![
        Block::leaf("Index indicator: 0x00", ByteRange::new(start, start + 1)),
        Block::leaf(
            format!("Number of records: {}", index.count),
            index.count_range,
        ),
    ];
    if let (Some(first), Some(last)) = (index.records.first(), index.records.last()) {
        let records = index
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| {
                Block::node(
                    format!("Record {i}"),
                    ByteRange::new(r.unpadded_range.start, r.uncompressed_range.end),
                    vec![
                        Block::leaf(format!("Unpadded size: {}", r.unpadded), r.unpadded_range),
                        Block::leaf(
                            format!("Uncompressed size: {}", r.uncompressed),
                            r.uncompressed_range,
                        ),
                    ],
                )
            })
            .collect();
        children.push(Block::node(
            "Records",
            ByteRange::new(first.unpadded_range.start, last.uncompressed_range.end),
            records,
        ));
    }
    if index.padding_range.end > index.padding_range.start {
        children.push(Block::leaf("Index padding", index.padding_range));
    }
    if let Some(crc) = crc32_leaf(data, index.crc_offset) {
        children.push(crc);
    }
    Block::node(
        "Index",
        ByteRange::new(start, stream.footer_start),
        children,
    )
}

fn filter_properties_label(id: u64, props: &[u8]) -> String {
    match (id, props) {
        (0x21, [p]) => {
            let bits = p & 0x3F;
            if bits > 40 {
                format!("Dictionary size: invalid ({p:#04x})")
            } else if bits == 40 {
                "Dictionary size: 4 GiB - 1".to_string()
            } else {
                let size = (2u64 | u64::from(bits & 1)) << (bits / 2 + 11);
                format!("Dictionary size: {}", format_size(size))
            }
        }
        (0x03, [p]) => format!("Delta distance: {}", u32::from(*p) + 1),
        (0x04..=0x0B, [a, b, c, d]) => {
            format!("Start offset: {}", u32::from_le_bytes([*a, *b, *c, *d]))
        }
        _ => format!("Properties: {}", hex(props)),
    }
}

/// Parses a block header starting at `start`. Returns the block and the
/// header's size in bytes (from the size byte).
fn block_header_block(data: &[u8], start: u64) -> Option<(Block, u64)> {
    let size_byte = byte_at(data, start)?;
    if size_byte == 0 {
        return None;
    }
    let size = (u64::from(size_byte) + 1) * 4;
    let end = start + size;
    let crc_offset = end - 4;
    slice(data, start, end)?;

    let flags = byte_at(data, start + 1)?;
    let filter_count = u64::from(flags & 0x03) + 1;
    let mut flag_desc = format!(
        "{filter_count} filter{}",
        if filter_count == 1 { "" } else { "s" }
    );
    if flags & FLAG_COMPRESSED_SIZE != 0 {
        flag_desc.push_str(", compressed size");
    }
    if flags & FLAG_UNCOMPRESSED_SIZE != 0 {
        flag_desc.push_str(", uncompressed size");
    }

    let mut children = vec![
        Block::leaf(
            format!("Block header size: {size} bytes"),
            ByteRange::new(start, start + 1),
        ),
        Block::leaf(
            format!("Block flags: {flags:#04x} ({flag_desc})"),
            ByteRange::new(start + 1, start + 2),
        ),
    ];

    let mut pos = start + 2;
    let mut ok = true;
    for (flag, label) in [
        (FLAG_COMPRESSED_SIZE, "Compressed size"),
        (FLAG_UNCOMPRESSED_SIZE, "Uncompressed size"),
    ] {
        if ok && flags & flag != 0 {
            match read_vli(data, pos, crc_offset) {
                Some((value, next)) => {
                    children.push(Block::leaf(
                        format!("{label}: {value}"),
                        ByteRange::new(pos, next),
                    ));
                    pos = next;
                }
                None => ok = false,
            }
        }
    }

    for i in 0..filter_count {
        if !ok {
            break;
        }
        let filter = (|| {
            let (id, id_end) = read_vli(data, pos, crc_offset)?;
            let (props_size, props_start) = read_vli(data, id_end, crc_offset)?;
            let props_end = props_start.checked_add(props_size)?;
            if props_end > crc_offset {
                return None;
            }
            let props = slice(data, props_start, props_end)?;
            let name = filter_name(id);
            let mut filter_children = vec![
                Block::leaf(
                    format!("Filter ID: {id:#04x} ({name})"),
                    ByteRange::new(pos, id_end),
                ),
                Block::leaf(
                    format!("Properties size: {props_size}"),
                    ByteRange::new(id_end, props_start),
                ),
            ];
            if props_size > 0 {
                filter_children.push(Block::leaf(
                    filter_properties_label(id, props),
                    ByteRange::new(props_start, props_end),
                ));
            }
            Some((
                Block::node(
                    format!("Filter {i}: {name}"),
                    ByteRange::new(pos, props_end),
                    filter_children,
                )
                .expanded(),
                props_end,
            ))
        })();
        match filter {
            Some((block, next)) => {
                children.push(block);
                pos = next;
            }
            None => ok = false,
        }
    }

    if pos < crc_offset {
        children.push(Block::leaf(
            if ok {
                "Header padding"
            } else {
                "Unparsed header data"
            },
            ByteRange::new(pos, crc_offset),
        ));
    }
    children.push(crc32_leaf(data, crc_offset)?);

    Some((
        Block::node("Block header", ByteRange::new(start, end), children),
        size,
    ))
}

fn check_leaf(data: &[u8], check_type: u8, start: u64, end: u64) -> Block {
    let range = ByteRange::new(start, end);
    let label = match check_type {
        0x01 => read_u32(data, start).map(|v| format!("CRC32: {v:#010x}")),
        0x04 => read_u64(data, start).map(|v| format!("CRC64: {v:#018x}")),
        0x0A => slice(data, start, end).map(|b| format!("SHA-256: {}", hex(b))),
        n => slice(data, start, end).map(|b| format!("Check ({}): {}", check_name(n), hex(b))),
    };
    Block::leaf(label.unwrap_or_else(|| "Check".to_string()), range)
}

fn data_block(data: &[u8], number: usize, start: u64, record: &Record, check_type: u8) -> Block {
    let padded_end = start + round_up4(record.unpadded).unwrap_or(record.unpadded);
    let check_len = check_size(check_type);
    let label = format!("Block {number}");
    let range = ByteRange::new(start, padded_end);

    let Some((header, header_size)) = block_header_block(data, start) else {
        return Block::node(
            label,
            range,
            vec![Block::leaf("Unparsed block data", range)],
        );
    };
    let Some(data_end) = record
        .unpadded
        .checked_sub(check_len)
        .filter(|&n| n >= header_size)
        .map(|n| start + n)
    else {
        return Block::node(label, range, vec![header]);
    };

    let mut children = vec![header];
    let data_start = start + header_size;
    children.push(Block::leaf(
        format!("Compressed data ({} bytes)", data_end - data_start),
        ByteRange::new(data_start, data_end),
    ));
    let check_start = padded_end - check_len;
    if check_start > data_end {
        children.push(Block::leaf(
            "Block padding",
            ByteRange::new(data_end, check_start),
        ));
    }
    if check_len > 0 {
        children.push(check_leaf(data, check_type, check_start, padded_end));
    }
    Block::node(label, range, children)
}

fn stream_blocks(data: &[u8], stream: &Stream) -> Vec<Block> {
    let mut blocks = Vec::new();
    if let Some(header) = stream_header_block(data, stream.start) {
        blocks.push(header);
    }
    let check_type = byte_at(data, stream.start + 7).unwrap_or(0) & 0x0F;
    let mut offset = stream.start + STREAM_HEADER_SIZE;
    for (i, record) in stream.index.records.iter().enumerate() {
        let block = data_block(data, i, offset, record, check_type);
        offset = block.range.end;
        blocks.push(block);
    }
    blocks.push(index_block(data, stream));
    if let Some(footer) = stream_footer_block(data, stream.footer_start) {
        blocks.push(footer);
    }
    blocks
}

/// Fallback for files whose footer or index can't be found (e.g. truncated
/// files): show the stream header and the first block header, if present.
fn dissect_forward(data: &[u8]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let Some(header) = stream_header_block(data, 0) else {
        return blocks;
    };
    blocks.push(header);
    let start = STREAM_HEADER_SIZE;
    let len = data.len() as u64;
    if let Some((block_header, size)) = block_header_block(data, start) {
        let mut children = vec![block_header];
        if start + size < len {
            children.push(Block::leaf(
                "Unparsed data",
                ByteRange::new(start + size, len),
            ));
        }
        blocks.push(Block::node("Block 0", ByteRange::new(start, len), children));
    } else if start < len {
        blocks.push(Block::leaf("Unparsed data", ByteRange::new(start, len)));
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK_NONE: u8 = 0x00;
    const CHECK_CRC32: u8 = 0x01;
    const CHECK_CRC64: u8 = 0x04;
    const CHECK_SHA256: u8 = 0x0A;

    fn vli(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn pad4(buf: &mut Vec<u8>, base: usize) {
        while (buf.len() - base) % 4 != 0 {
            buf.push(0);
        }
    }

    /// Builds a block with a Delta + LZMA2 filter chain and both optional
    /// sizes. Returns the block bytes and its unpadded size.
    fn build_block(payload: &[u8], uncompressed: u64, check_type: u8) -> (Vec<u8>, u64) {
        let mut header = vec![0u8, 0x01 | FLAG_COMPRESSED_SIZE | FLAG_UNCOMPRESSED_SIZE];
        header.extend(vli(payload.len() as u64));
        header.extend(vli(uncompressed));
        header.extend([0x03, 0x01, 0x00]); // Delta, distance 1
        header.extend([0x21, 0x01, 0x16]); // LZMA2, 8 MiB dictionary
        while header.len() % 4 != 0 {
            header.push(0);
        }
        header.extend([0xAA, 0xBB, 0xCC, 0xDD]); // header CRC32 (unchecked)
        header[0] = (header.len() / 4 - 1) as u8;

        let check_len = check_size(check_type) as usize;
        let unpadded = (header.len() + payload.len() + check_len) as u64;
        let mut block = header;
        block.extend_from_slice(payload);
        pad4(&mut block, 0);
        block.extend(std::iter::repeat_n(0x11u8, check_len));
        (block, unpadded)
    }

    fn build_xz(payloads: &[&[u8]], check_type: u8) -> Vec<u8> {
        let mut data = HEADER_MAGIC.to_vec();
        data.extend([0x00, check_type]);
        data.extend([0x01, 0x02, 0x03, 0x04]); // header CRC32 (unchecked)

        let mut records = Vec::new();
        for payload in payloads {
            let uncompressed = payload.len() as u64 * 2;
            let (block, unpadded) = build_block(payload, uncompressed, check_type);
            data.extend(block);
            records.push((unpadded, uncompressed));
        }

        let index_start = data.len();
        data.push(0x00);
        data.extend(vli(records.len() as u64));
        for (unpadded, uncompressed) in records {
            data.extend(vli(unpadded));
            data.extend(vli(uncompressed));
        }
        pad4(&mut data, index_start);
        data.extend([0x05, 0x06, 0x07, 0x08]); // index CRC32 (unchecked)
        let index_size = (data.len() - index_start) as u32;

        data.extend([0x09, 0x0A, 0x0B, 0x0C]); // footer CRC32 (unchecked)
        data.extend((index_size / 4 - 1).to_le_bytes());
        data.extend([0x00, check_type]);
        data.extend(FOOTER_MAGIC);
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

    fn labels(blocks: &[Block]) -> Vec<&str> {
        blocks.iter().map(|b| b.label.as_str()).collect()
    }

    #[test]
    fn matches_xz_magic() {
        let data = build_xz(&[b"hello"], CHECK_CRC64);
        assert!(XzDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_xz_data() {
        assert!(!XzDissector.matches(b""));
        assert!(!XzDissector.matches(b"not an xz file"));
        assert!(!XzDissector.matches(&[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!XzDissector.matches(&HEADER_MAGIC[..5]));
        assert!(!XzDissector.matches(HEADER_MAGIC));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        assert!(XzDissector.dissect(HEADER_MAGIC).is_empty());
        assert!(XzDissector.dissect(b"").is_empty());
    }

    #[test]
    fn dissect_truncated_file_does_not_panic() {
        let data = build_xz(&[b"hello", b"world!!"], CHECK_SHA256);
        for len in 0..data.len() {
            let blocks = XzDissector.dissect(&data[..len]);
            for block in &blocks {
                assert!(block.range.end <= len as u64);
            }
        }
        let truncated = XzDissector.dissect(&data[..40]);
        assert_eq!(labels(&truncated), vec!["Stream header", "Block 0"]);
        let block = find_block(&truncated, "Block 0");
        assert_eq!(
            labels(&block.children),
            vec!["Block header", "Unparsed data"]
        );
    }

    #[test]
    fn dissect_parses_single_stream() {
        let data = build_xz(&[b"hello"], CHECK_CRC64);
        assert_eq!(data.len(), 64);
        let blocks = XzDissector.dissect(&data);
        assert_eq!(
            labels(&blocks),
            vec!["Stream header", "Block 0", "Index", "Stream footer"]
        );

        let header = find_block(&blocks, "Stream header");
        assert_eq!(header.range, ByteRange::new(0, 12));
        let hc = &header.children;
        assert_eq!(
            find_block(hc, "Magic: FD 37 7A 58 5A 00").range,
            ByteRange::new(0, 6)
        );
        assert_eq!(
            find_block(hc, "Stream flags: check type CRC64").range,
            ByteRange::new(6, 8)
        );
        assert_eq!(
            find_block(hc, "CRC32: 0x04030201").range,
            ByteRange::new(8, 12)
        );

        let block = find_block(&blocks, "Block 0");
        assert_eq!(block.range, ByteRange::new(12, 44));
        let block_header = find_block(&block.children, "Block header");
        assert_eq!(block_header.range, ByteRange::new(12, 28));
        let bh = &block_header.children;
        assert_eq!(
            find_block(bh, "Block header size: 16 bytes").range,
            ByteRange::new(12, 13)
        );
        assert_eq!(
            find_block(
                bh,
                "Block flags: 0xc1 (2 filters, compressed size, uncompressed size)"
            )
            .range,
            ByteRange::new(13, 14)
        );
        assert_eq!(
            find_block(bh, "Compressed size: 5").range,
            ByteRange::new(14, 15)
        );
        assert_eq!(
            find_block(bh, "Uncompressed size: 10").range,
            ByteRange::new(15, 16)
        );
        let delta = find_block(bh, "Filter 0: Delta");
        assert_eq!(delta.range, ByteRange::new(16, 19));
        assert_eq!(
            find_block(&delta.children, "Filter ID: 0x03 (Delta)").range,
            ByteRange::new(16, 17)
        );
        assert_eq!(
            find_block(&delta.children, "Delta distance: 1").range,
            ByteRange::new(18, 19)
        );
        let lzma2 = find_block(bh, "Filter 1: LZMA2");
        assert_eq!(lzma2.range, ByteRange::new(19, 22));
        assert_eq!(
            find_block(&lzma2.children, "Properties size: 1").range,
            ByteRange::new(20, 21)
        );
        assert_eq!(
            find_block(&lzma2.children, "Dictionary size: 8 MiB").range,
            ByteRange::new(21, 22)
        );
        assert_eq!(
            find_block(bh, "Header padding").range,
            ByteRange::new(22, 24)
        );
        assert_eq!(
            find_block(bh, "CRC32: 0xddccbbaa").range,
            ByteRange::new(24, 28)
        );

        let bc = &block.children;
        assert_eq!(
            find_block(bc, "Compressed data (5 bytes)").range,
            ByteRange::new(28, 33)
        );
        assert_eq!(
            find_block(bc, "Block padding").range,
            ByteRange::new(33, 36)
        );
        assert_eq!(
            find_block(bc, "CRC64: 0x1111111111111111").range,
            ByteRange::new(36, 44)
        );

        let index = find_block(&blocks, "Index");
        assert_eq!(index.range, ByteRange::new(44, 52));
        let ic = &index.children;
        assert_eq!(
            find_block(ic, "Index indicator: 0x00").range,
            ByteRange::new(44, 45)
        );
        assert_eq!(
            find_block(ic, "Number of records: 1").range,
            ByteRange::new(45, 46)
        );
        let records = find_block(ic, "Records");
        let record = find_block(&records.children, "Record 0");
        assert_eq!(record.range, ByteRange::new(46, 48));
        assert_eq!(
            find_block(&record.children, "Unpadded size: 29").range,
            ByteRange::new(46, 47)
        );
        assert_eq!(
            find_block(&record.children, "Uncompressed size: 10").range,
            ByteRange::new(47, 48)
        );
        assert!(ic.iter().all(|b| b.label != "Index padding"));
        assert_eq!(
            find_block(ic, "CRC32: 0x08070605").range,
            ByteRange::new(48, 52)
        );

        let footer = find_block(&blocks, "Stream footer");
        assert_eq!(footer.range, ByteRange::new(52, 64));
        let fc = &footer.children;
        assert_eq!(
            find_block(fc, "CRC32: 0x0c0b0a09").range,
            ByteRange::new(52, 56)
        );
        assert_eq!(
            find_block(fc, "Backward size: 8 bytes").range,
            ByteRange::new(56, 60)
        );
        assert_eq!(
            find_block(fc, "Stream flags: check type CRC64").range,
            ByteRange::new(60, 62)
        );
        assert_eq!(find_block(fc, "Magic: YZ").range, ByteRange::new(62, 64));
    }

    #[test]
    fn dissect_handles_check_types_and_multiple_blocks() {
        let data = build_xz(&[b"abcd", b"efgh"], CHECK_NONE);
        let blocks = XzDissector.dissect(&data);
        assert_eq!(
            labels(&blocks),
            vec![
                "Stream header",
                "Block 0",
                "Block 1",
                "Index",
                "Stream footer"
            ]
        );
        let block = find_block(&blocks, "Block 1");
        assert_eq!(
            labels(&block.children),
            vec!["Block header", "Compressed data (4 bytes)"]
        );
        let index = find_block(&blocks, "Index");
        assert!(index.children.iter().any(|b| b.label == "Index padding"));

        let data = build_xz(&[b"abc"], CHECK_SHA256);
        let blocks = XzDissector.dissect(&data);
        let block = find_block(&blocks, "Block 0");
        let label = format!("SHA-256: {}", "11".repeat(32));
        let check = find_block(&block.children, &label);
        assert_eq!(check.range.end - check.range.start, 32);
        assert_eq!(check.range.end, block.range.end);

        let data = build_xz(&[b"abc"], CHECK_CRC32);
        let blocks = XzDissector.dissect(&data);
        let block = find_block(&blocks, "Block 0");
        find_block(&block.children, "CRC32: 0x11111111");
    }

    #[test]
    fn dissect_handles_concatenated_streams_and_padding() {
        let first = build_xz(&[b"one"], CHECK_CRC64);
        let second = build_xz(&[b"two", b"three"], CHECK_CRC32);
        let mut data = first.clone();
        data.extend([0u8; 8]);
        data.extend(&second);
        data.extend([0u8; 4]);

        let blocks = XzDissector.dissect(&data);
        assert_eq!(
            labels(&blocks),
            vec![
                "Stream 0",
                "Stream padding (8 bytes)",
                "Stream 1",
                "Stream padding (4 bytes)"
            ]
        );
        let s0 = find_block(&blocks, "Stream 0");
        assert_eq!(s0.range, ByteRange::new(0, first.len() as u64));
        let s1_start = first.len() as u64 + 8;
        let s1 = find_block(&blocks, "Stream 1");
        assert_eq!(
            s1.range,
            ByteRange::new(s1_start, s1_start + second.len() as u64)
        );
        assert_eq!(
            labels(&s1.children),
            vec![
                "Stream header",
                "Block 0",
                "Block 1",
                "Index",
                "Stream footer"
            ]
        );
        assert_eq!(
            find_block(&s1.children, "Stream header").range.start,
            s1_start
        );
    }

    #[test]
    fn identify_reports_xz() {
        let data = build_xz(&[b"hello"], CHECK_CRC64);
        assert_eq!(super::super::identify(&data), "XZ");
    }
}
