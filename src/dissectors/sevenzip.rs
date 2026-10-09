use super::{Block, ByteRange, Dissector};

const SEVENZIP_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const SIGNATURE_HEADER_SIZE: usize = 32;

// Property IDs used in the (encoded) header.
const K_END: u64 = 0x00;
const K_HEADER: u64 = 0x01;
const K_ARCHIVE_PROPERTIES: u64 = 0x02;
const K_ADDITIONAL_STREAMS_INFO: u64 = 0x03;
const K_MAIN_STREAMS_INFO: u64 = 0x04;
const K_FILES_INFO: u64 = 0x05;
const K_PACK_INFO: u64 = 0x06;
const K_UNPACK_INFO: u64 = 0x07;
const K_SUBSTREAMS_INFO: u64 = 0x08;
const K_SIZE: u64 = 0x09;
const K_CRC: u64 = 0x0A;
const K_FOLDER: u64 = 0x0B;
const K_CODERS_UNPACK_SIZE: u64 = 0x0C;
const K_NUM_UNPACK_STREAM: u64 = 0x0D;
const K_EMPTY_STREAM: u64 = 0x0E;
const K_EMPTY_FILE: u64 = 0x0F;
const K_ANTI: u64 = 0x10;
const K_NAME: u64 = 0x11;
const K_CTIME: u64 = 0x12;
const K_ATIME: u64 = 0x13;
const K_MTIME: u64 = 0x14;
const K_WIN_ATTRIBUTES: u64 = 0x15;
const K_COMMENT: u64 = 0x16;
const K_ENCODED_HEADER: u64 = 0x17;
const K_START_POS: u64 = 0x18;
const K_DUMMY: u64 = 0x19;

pub struct SevenZipDissector;

impl Dissector for SevenZipDissector {
    fn name(&self) -> &'static str {
        "7-Zip"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= SIGNATURE_HEADER_SIZE && data.starts_with(SEVENZIP_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let Some(sig) = signature_header(data) else {
            return blocks;
        };
        blocks.push(sig.block);

        let data_len = data.len() as u64;
        let base = SIGNATURE_HEADER_SIZE as u64;
        let packed_end = base.saturating_add(sig.next_header_offset).min(data_len);
        let next_start = packed_end;
        let next_end = base
            .saturating_add(sig.next_header_offset)
            .saturating_add(sig.next_header_size)
            .min(data_len);

        let mut packs = Vec::new();
        let mut next_header = None;
        if next_end > next_start && base.saturating_add(sig.next_header_offset) < data_len {
            let mut children = Vec::new();
            let mut reader = Reader::new(data, next_start as usize, next_end as usize);
            let _ = parse_next_header(&mut reader, &mut children, &mut packs);
            if (reader.pos as u64) < next_end {
                children.push(Block::leaf(
                    "Unparsed header bytes",
                    ByteRange::new(reader.pos as u64, next_end),
                ));
            }
            let crc_note = if next_end - next_start == sig.next_header_size {
                let actual = crc32(&data[next_start as usize..next_end as usize]);
                if actual == sig.next_header_crc {
                    " (CRC OK)"
                } else {
                    " (CRC mismatch)"
                }
            } else {
                " (truncated)"
            };
            next_header = Some(
                Block::node(
                    format!("Next header{crc_note}"),
                    ByteRange::new(next_start, next_end),
                    children,
                )
                .expanded(),
            );
        }

        if packed_end > base {
            packs.sort_by_key(|p| p.start);
            let mut children = Vec::new();
            for pack in packs {
                let start = pack.start.max(base);
                let end = pack.end.min(packed_end);
                if end > start {
                    children.push(Block::leaf(pack.label, ByteRange::new(start, end)));
                }
            }
            blocks.push(Block::node(
                "Packed streams",
                ByteRange::new(base, packed_end),
                children,
            ));
        }

        if let Some(block) = next_header {
            blocks.push(block);
        }

        let tail_start = next_end.max(packed_end);
        if tail_start < data_len && sig.next_header_size > 0 {
            blocks.push(Block::leaf(
                "Trailing data",
                ByteRange::new(tail_start, data_len),
            ));
        }

        blocks
    }
}

struct SignatureHeader {
    block: Block,
    next_header_offset: u64,
    next_header_size: u64,
    next_header_crc: u32,
}

fn signature_header(data: &[u8]) -> Option<SignatureHeader> {
    let header = data.get(..SIGNATURE_HEADER_SIZE)?;
    if !header.starts_with(SEVENZIP_MAGIC) {
        return None;
    }
    let major = header[6];
    let minor = header[7];
    let start_crc = read_u32(data, 8)?;
    let next_header_offset = read_u64(data, 12)?;
    let next_header_size = read_u64(data, 20)?;
    let next_header_crc = read_u32(data, 28)?;
    let start_ok = crc32(&header[12..32]) == start_crc;

    let children = vec![
        Block::leaf("Signature: 7z\\xBC\\xAF\\x27\\x1C", ByteRange::new(0, 6)),
        Block::leaf(format!("Version: {major}.{minor}"), ByteRange::new(6, 8)),
        Block::leaf(
            format!(
                "Start header CRC: 0x{start_crc:08X} ({})",
                if start_ok { "OK" } else { "mismatch" }
            ),
            ByteRange::new(8, 12),
        ),
        Block::leaf(
            format!(
                "Next header offset: {next_header_offset} (file offset {})",
                next_header_offset.saturating_add(SIGNATURE_HEADER_SIZE as u64)
            ),
            ByteRange::new(12, 20),
        ),
        Block::leaf(
            format!("Next header size: {next_header_size}"),
            ByteRange::new(20, 28),
        ),
        Block::leaf(
            format!("Next header CRC: 0x{next_header_crc:08X}"),
            ByteRange::new(28, 32),
        ),
    ];

    Some(SignatureHeader {
        block: Block::node(
            "Signature header",
            ByteRange::new(0, SIGNATURE_HEADER_SIZE as u64),
            children,
        )
        .expanded(),
        next_header_offset,
        next_header_size,
        next_header_crc,
    })
}

/// A packed stream discovered in a PackInfo, as an absolute file range.
struct PackStream {
    label: String,
    start: u64,
    end: u64,
}

#[derive(Default)]
struct FolderInfo {
    coder_names: Vec<String>,
    num_out_streams: u64,
    num_packed_streams: u64,
    crc_defined: bool,
}

#[derive(Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<FolderInfo>,
}

/// Bounds-checked cursor over `data[pos..end]`; positions are absolute file
/// offsets. Failed reads never advance the cursor.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        let end = end.min(data.len());
        Self {
            data,
            pos: pos.min(end),
            end,
        }
    }

    fn remaining(&self) -> usize {
        self.end - self.pos
    }

    fn bytes(&mut self, n: u64) -> Option<&'a [u8]> {
        if n > self.remaining() as u64 {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Some(slice)
    }

    fn byte(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// 7z variable-length NUMBER: the count of leading 1 bits in the first
    /// byte gives the number of extra little-endian bytes; the remaining low
    /// bits of the first byte are the most significant part.
    fn number(&mut self) -> Option<u64> {
        let saved = self.pos;
        let result = self.number_inner();
        if result.is_none() {
            self.pos = saved;
        }
        result
    }

    fn number_inner(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                value |= high << (8 * i);
                return Some(value);
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn property_name(id: u64) -> &'static str {
    match id {
        K_END => "kEnd",
        K_HEADER => "kHeader",
        K_ARCHIVE_PROPERTIES => "kArchiveProperties",
        K_ADDITIONAL_STREAMS_INFO => "kAdditionalStreamsInfo",
        K_MAIN_STREAMS_INFO => "kMainStreamsInfo",
        K_FILES_INFO => "kFilesInfo",
        K_PACK_INFO => "kPackInfo",
        K_UNPACK_INFO => "kUnPackInfo",
        K_SUBSTREAMS_INFO => "kSubStreamsInfo",
        K_SIZE => "kSize",
        K_CRC => "kCRC",
        K_FOLDER => "kFolder",
        K_CODERS_UNPACK_SIZE => "kCodersUnPackSize",
        K_NUM_UNPACK_STREAM => "kNumUnPackStream",
        K_EMPTY_STREAM => "kEmptyStream",
        K_EMPTY_FILE => "kEmptyFile",
        K_ANTI => "kAnti",
        K_NAME => "kName",
        K_CTIME => "kCTime",
        K_ATIME => "kATime",
        K_MTIME => "kMTime",
        K_WIN_ATTRIBUTES => "kWinAttributes",
        K_COMMENT => "kComment",
        K_ENCODED_HEADER => "kEncodedHeader",
        K_START_POS => "kStartPos",
        K_DUMMY => "kDummy",
        _ => "unknown",
    }
}

/// Reads a property ID and pushes a leaf for it.
fn read_property_id(r: &mut Reader, out: &mut Vec<Block>) -> Option<u64> {
    let start = r.pos;
    let id = r.number()?;
    out.push(Block::leaf(
        format!("Property ID: {} (0x{id:02X})", property_name(id)),
        range(start, r.pos),
    ));
    Some(id)
}

fn read_number_leaf(r: &mut Reader, out: &mut Vec<Block>, name: &str) -> Option<u64> {
    let start = r.pos;
    let value = r.number()?;
    out.push(Block::leaf(format!("{name}: {value}"), range(start, r.pos)));
    Some(value)
}

fn read_byte_leaf(r: &mut Reader, out: &mut Vec<Block>, name: &str) -> Option<u8> {
    let start = r.pos;
    let value = r.byte()?;
    out.push(Block::leaf(format!("{name}: {value}"), range(start, r.pos)));
    Some(value)
}

fn unknown_property(out: &mut Vec<Block>, start: usize, end: usize, id: u64) {
    out.truncate(out.len().saturating_sub(1));
    out.push(Block::leaf(
        format!("Unknown property ID 0x{id:02X}; parsing stopped"),
        range(start, end),
    ));
}

/// Runs `f` collecting children into a node spanning everything it consumed.
/// The node is pushed even if `f` fails partway, so truncated input still
/// shows what was parsed.
fn section<R>(
    r: &mut Reader,
    out: &mut Vec<Block>,
    label: impl FnOnce(&Option<R>) -> String,
    f: impl FnOnce(&mut Reader, &mut Vec<Block>) -> Option<R>,
) -> Option<R> {
    let start = r.pos;
    let mut children = Vec::new();
    let result = f(r, &mut children);
    if r.pos > start {
        out.push(Block::node(label(&result), range(start, r.pos), children));
    }
    result
}

fn parse_next_header(
    r: &mut Reader,
    out: &mut Vec<Block>,
    packs: &mut Vec<PackStream>,
) -> Option<()> {
    let start = r.pos;
    match read_property_id(r, out)? {
        K_HEADER => parse_header(r, out, packs),
        K_ENCODED_HEADER => {
            let info = section(
                r,
                out,
                |info: &Option<StreamsInfo>| match info {
                    Some(info) => format!(
                        "Encoded header streams info (real header compressed with {})",
                        folder_summary(info)
                    ),
                    None => "Encoded header streams info".to_string(),
                },
                |r, out| parse_streams_info(r, out),
            );
            if let Some(info) = &info {
                add_pack_streams(info, "Encoded header", packs);
            }
            info.map(|_| ())
        }
        id => {
            unknown_property(out, start, r.pos, id);
            None
        }
    }
}

fn parse_header(r: &mut Reader, out: &mut Vec<Block>, packs: &mut Vec<PackStream>) -> Option<()> {
    loop {
        let start = r.pos;
        let mut id_leaf = Vec::new();
        let id = read_property_id(r, &mut id_leaf)?;
        match id {
            K_END => {
                out.append(&mut id_leaf);
                return Some(());
            }
            K_ARCHIVE_PROPERTIES => {
                r.pos = start;
                section(
                    r,
                    out,
                    |_| "Archive properties".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_archive_properties(r, out)
                    },
                )?;
            }
            K_ADDITIONAL_STREAMS_INFO | K_MAIN_STREAMS_INFO => {
                r.pos = start;
                let (label, prefix) = if id == K_MAIN_STREAMS_INFO {
                    ("Main streams info", "")
                } else {
                    ("Additional streams info", "Additional ")
                };
                let info = section(
                    r,
                    out,
                    |_| label.to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_streams_info(r, out)
                    },
                )?;
                add_pack_streams(&info, prefix.trim_end(), packs);
            }
            K_FILES_INFO => {
                r.pos = start;
                section(
                    r,
                    out,
                    |_| "Files info".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_files_info(r, out)
                    },
                )?;
            }
            _ => {
                out.append(&mut id_leaf);
                unknown_property(out, start, r.pos, id);
                return None;
            }
        }
    }
}

fn parse_archive_properties(r: &mut Reader, out: &mut Vec<Block>) -> Option<()> {
    loop {
        let start = r.pos;
        let kind = r.number()?;
        if kind == K_END {
            out.push(Block::leaf("Property type: kEnd", range(start, r.pos)));
            return Some(());
        }
        let size = r.number()?;
        r.bytes(size)?;
        out.push(Block::leaf(
            format!("Archive property 0x{kind:02X} ({size} bytes)"),
            range(start, r.pos),
        ));
    }
}

fn parse_streams_info(r: &mut Reader, out: &mut Vec<Block>) -> Option<StreamsInfo> {
    let mut info = StreamsInfo::default();
    loop {
        let start = r.pos;
        let mut id_leaf = Vec::new();
        let id = read_property_id(r, &mut id_leaf)?;
        r.pos = start;
        match id {
            K_END => {
                read_property_id(r, out)?;
                return Some(info);
            }
            K_PACK_INFO => {
                section(
                    r,
                    out,
                    |_| "Pack info".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_pack_info(r, out, &mut info)
                    },
                )?;
            }
            K_UNPACK_INFO => {
                section(
                    r,
                    out,
                    |_| "Unpack info".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_unpack_info(r, out, &mut info)
                    },
                )?;
            }
            K_SUBSTREAMS_INFO => {
                section(
                    r,
                    out,
                    |_| "Substreams info".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_substreams_info(r, out, &info)
                    },
                )?;
            }
            _ => {
                read_property_id(r, out)?;
                unknown_property(out, start, r.pos, id);
                return None;
            }
        }
    }
}

fn parse_pack_info(r: &mut Reader, out: &mut Vec<Block>, info: &mut StreamsInfo) -> Option<()> {
    let start = r.pos;
    let pack_pos = r.number()?;
    out.push(Block::leaf(
        format!(
            "Pack position: {pack_pos} (file offset {})",
            pack_pos.saturating_add(SIGNATURE_HEADER_SIZE as u64)
        ),
        range(start, r.pos),
    ));
    info.pack_pos = pack_pos;
    let num_pack_streams = read_number_leaf(r, out, "Number of pack streams")?;

    loop {
        let start = r.pos;
        let id = r.number()?;
        r.pos = start;
        match id {
            K_END => {
                read_property_id(r, out)?;
                return Some(());
            }
            K_SIZE => {
                section(
                    r,
                    out,
                    |_| "Pack sizes".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        for i in 0..num_pack_streams {
                            let size = read_number_leaf(r, out, &format!("Pack stream {i} size"))?;
                            info.pack_sizes.push(size);
                        }
                        Some(())
                    },
                )?;
            }
            K_CRC => {
                section(
                    r,
                    out,
                    |_| "Pack stream CRCs".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_digests(r, out, num_pack_streams, "Pack stream").map(|_| ())
                    },
                )?;
            }
            _ => {
                read_property_id(r, out)?;
                unknown_property(out, start, r.pos, id);
                return None;
            }
        }
    }
}

/// Parses a 7z digests structure for `count` items; returns which items
/// have a CRC defined.
fn parse_digests(
    r: &mut Reader,
    out: &mut Vec<Block>,
    count: u64,
    item: &str,
) -> Option<Vec<bool>> {
    let defined = parse_defined_vector(r, out, count)?;
    let mut result = Vec::new();
    for (i, is_defined) in defined.enumerate() {
        if is_defined {
            let start = r.pos;
            let crc = r.u32()?;
            out.push(Block::leaf(
                format!("{item} {i} CRC: 0x{crc:08X}"),
                range(start, r.pos),
            ));
        }
        result.push(is_defined);
    }
    Some(result)
}

/// Reads an "AllAreDefined" byte, optionally followed by a bit vector, and
/// returns an iterator over the defined flags for `count` items.
fn parse_defined_vector(r: &mut Reader, out: &mut Vec<Block>, count: u64) -> Option<DefinedIter> {
    let start = r.pos;
    let all = r.byte()?;
    out.push(Block::leaf(
        format!("All defined: {}", if all != 0 { "yes" } else { "no" }),
        range(start, r.pos),
    ));
    if all != 0 {
        return Some(DefinedIter {
            bits: None,
            index: 0,
            count,
        });
    }
    let bits = read_bit_vector(r, out, count, "Defined bitmap")?;
    Some(DefinedIter {
        bits: Some(bits),
        index: 0,
        count,
    })
}

struct DefinedIter {
    bits: Option<Vec<bool>>,
    index: u64,
    count: u64,
}

impl Iterator for DefinedIter {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.index >= self.count {
            return None;
        }
        let i = self.index;
        self.index += 1;
        Some(match &self.bits {
            None => true,
            Some(bits) => bits.get(i as usize).copied().unwrap_or(false),
        })
    }
}

/// Reads a packed MSB-first bit vector of `count` bits.
fn read_bit_vector(
    r: &mut Reader,
    out: &mut Vec<Block>,
    count: u64,
    name: &str,
) -> Option<Vec<bool>> {
    let start = r.pos;
    let bytes = r.bytes(count.div_ceil(8))?;
    let bits: Vec<bool> = (0..count as usize)
        .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
        .collect();
    let set = bits.iter().filter(|b| **b).count();
    out.push(Block::leaf(
        format!("{name}: {set} of {count} set"),
        range(start, r.pos),
    ));
    Some(bits)
}

fn parse_unpack_info(r: &mut Reader, out: &mut Vec<Block>, info: &mut StreamsInfo) -> Option<()> {
    let start = r.pos;
    let id = read_property_id(r, out)?;
    if id != K_FOLDER {
        unknown_property(out, start, r.pos, id);
        return None;
    }
    let num_folders = read_number_leaf(r, out, "Number of folders")?;
    let external = read_byte_leaf(r, out, "External")?;
    if external != 0 {
        read_number_leaf(r, out, "Data stream index")?;
        let pos = r.pos;
        out.push(Block::leaf(
            "External folder data not supported; parsing stopped",
            range(pos, pos),
        ));
        return None;
    }

    for i in 0..num_folders {
        let folder = section(
            r,
            out,
            |folder: &Option<FolderInfo>| match folder {
                Some(f) => format!("Folder {i}: {}", f.coder_names.join(" + ")),
                None => format!("Folder {i}"),
            },
            parse_folder,
        )?;
        info.folders.push(folder);
    }

    let start = r.pos;
    let id = read_property_id(r, out)?;
    if id != K_CODERS_UNPACK_SIZE {
        unknown_property(out, start, r.pos, id);
        return None;
    }
    r.pos = start;
    out.pop();
    section(
        r,
        out,
        |_| "Unpack sizes".to_string(),
        |r, out| {
            read_property_id(r, out)?;
            for (i, folder) in info.folders.iter().enumerate() {
                for j in 0..folder.num_out_streams {
                    read_number_leaf(r, out, &format!("Folder {i} output {j} size"))?;
                }
            }
            Some(())
        },
    )?;

    loop {
        let start = r.pos;
        let id = r.number()?;
        r.pos = start;
        match id {
            K_END => {
                read_property_id(r, out)?;
                return Some(());
            }
            K_CRC => {
                let defined = section(
                    r,
                    out,
                    |_| "Folder CRCs".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_digests(r, out, num_folders, "Folder")
                    },
                )?;
                for (folder, d) in info.folders.iter_mut().zip(defined) {
                    folder.crc_defined = d;
                }
            }
            _ => {
                read_property_id(r, out)?;
                unknown_property(out, start, r.pos, id);
                return None;
            }
        }
    }
}

fn parse_folder(r: &mut Reader, out: &mut Vec<Block>) -> Option<FolderInfo> {
    let mut folder = FolderInfo::default();
    let num_coders = read_number_leaf(r, out, "Number of coders")?;
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for j in 0..num_coders {
        let coder = section(
            r,
            out,
            |c: &Option<CoderInfo>| match c {
                Some(c) => format!("Coder {j}: {}", c.name),
                None => format!("Coder {j}"),
            },
            parse_coder,
        )?;
        total_in = total_in.saturating_add(coder.num_in);
        total_out = total_out.saturating_add(coder.num_out);
        folder.coder_names.push(coder.name);
    }

    let num_bind_pairs = total_out.saturating_sub(1);
    if num_bind_pairs > 0 {
        section(
            r,
            out,
            |_| "Bind pairs".to_string(),
            |r, out| {
                for k in 0..num_bind_pairs {
                    let start = r.pos;
                    let in_index = r.number()?;
                    let out_index = r.number()?;
                    out.push(Block::leaf(
                        format!("Bind pair {k}: in stream {in_index} <- out stream {out_index}"),
                        range(start, r.pos),
                    ));
                }
                Some(())
            },
        )?;
    }

    let num_packed = total_in.saturating_sub(num_bind_pairs);
    if num_packed > 1 {
        for k in 0..num_packed {
            read_number_leaf(r, out, &format!("Packed stream {k} in-stream index"))?;
        }
    }

    folder.num_out_streams = total_out;
    folder.num_packed_streams = num_packed;
    Some(folder)
}

struct CoderInfo {
    name: String,
    num_in: u64,
    num_out: u64,
}

fn parse_coder(r: &mut Reader, out: &mut Vec<Block>) -> Option<CoderInfo> {
    let start = r.pos;
    let flags = r.byte()?;
    let id_size = u64::from(flags & 0x0F);
    let complex = flags & 0x10 != 0;
    let has_props = flags & 0x20 != 0;
    let alternative = flags & 0x80 != 0;
    let mut notes = vec![format!("ID size {id_size}")];
    if complex {
        notes.push("complex".to_string());
    }
    if has_props {
        notes.push("has properties".to_string());
    }
    if alternative {
        notes.push("alternative methods".to_string());
    }
    out.push(Block::leaf(
        format!("Flags: 0x{flags:02X} ({})", notes.join(", ")),
        range(start, r.pos),
    ));

    let start = r.pos;
    let id = r.bytes(id_size)?;
    let name = codec_name(id);
    let hex: Vec<String> = id.iter().map(|b| format!("{b:02X}")).collect();
    out.push(Block::leaf(
        format!("Codec ID: {} ({name})", hex.join(" ")),
        range(start, r.pos),
    ));

    let (num_in, num_out) = if complex {
        let num_in = read_number_leaf(r, out, "Number of in streams")?;
        let num_out = read_number_leaf(r, out, "Number of out streams")?;
        (num_in, num_out)
    } else {
        (1, 1)
    };

    if has_props {
        let size = read_number_leaf(r, out, "Properties size")?;
        let start = r.pos;
        let props = r.bytes(size)?;
        out.push(Block::leaf(
            format!("Properties: {}", describe_props(id, props)),
            range(start, r.pos),
        ));
    }

    if alternative {
        let pos = r.pos;
        out.push(Block::leaf(
            "Alternative methods not supported; parsing stopped",
            range(pos, pos),
        ));
        return None;
    }

    Some(CoderInfo {
        name: name.to_string(),
        num_in,
        num_out,
    })
}

fn codec_name(id: &[u8]) -> &'static str {
    match id {
        [0x00] => "Copy",
        [0x03] => "Delta",
        [0x04] => "BCJ (x86)",
        [0x05] => "PPC",
        [0x06] => "IA64",
        [0x07] => "ARM",
        [0x08] => "ARMT",
        [0x09] => "SPARC",
        [0x0A] => "ARM64",
        [0x0B] => "RISCV",
        [0x21] => "LZMA2",
        [0x03, 0x01, 0x01] => "LZMA",
        [0x03, 0x03, 0x01, 0x03] => "BCJ (x86)",
        [0x03, 0x03, 0x01, 0x1B] => "BCJ2",
        [0x03, 0x03, 0x02, 0x05] => "PPC",
        [0x03, 0x03, 0x04, 0x01] => "IA64",
        [0x03, 0x03, 0x05, 0x01] => "ARM",
        [0x03, 0x03, 0x07, 0x01] => "ARMT",
        [0x03, 0x03, 0x08, 0x05] => "SPARC",
        [0x03, 0x04, 0x01] => "PPMD",
        [0x04, 0x01, 0x08] => "Deflate",
        [0x04, 0x01, 0x09] => "Deflate64",
        [0x04, 0x02, 0x02] => "BZip2",
        [0x06, 0xF1, 0x07, 0x01] => "AES-256 + SHA-256",
        _ => "unknown",
    }
}

fn describe_props(id: &[u8], props: &[u8]) -> String {
    match (codec_name(id), props) {
        ("LZMA", [lclppb, d0, d1, d2, d3, ..]) => {
            let pb = lclppb / 45;
            let lp = (lclppb % 45) / 9;
            let lc = lclppb % 9;
            let dict = u32::from_le_bytes([*d0, *d1, *d2, *d3]);
            format!(
                "lc={lc} lp={lp} pb={pb}, dictionary {}",
                format_size(u64::from(dict))
            )
        }
        ("LZMA2", [d]) if *d <= 40 => {
            let d = u64::from(*d);
            let dict = if d == 40 {
                u64::from(u32::MAX)
            } else {
                (2 | (d & 1)) << (d / 2 + 11)
            };
            format!("dictionary {}", format_size(dict))
        }
        ("PPMD", [order, m0, m1, m2, m3, ..]) => {
            let mem = u32::from_le_bytes([*m0, *m1, *m2, *m3]);
            format!("order {order}, memory {}", format_size(u64::from(mem)))
        }
        _ => format!("{} bytes", props.len()),
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

fn parse_substreams_info(r: &mut Reader, out: &mut Vec<Block>, info: &StreamsInfo) -> Option<()> {
    let mut counts: Vec<u64> = vec![1; info.folders.len()];
    loop {
        let start = r.pos;
        let id = r.number()?;
        r.pos = start;
        match id {
            K_END => {
                read_property_id(r, out)?;
                return Some(());
            }
            K_NUM_UNPACK_STREAM => {
                section(
                    r,
                    out,
                    |_| "Unpack stream counts".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        for (i, count) in counts.iter_mut().enumerate() {
                            *count = read_number_leaf(r, out, &format!("Folder {i} streams"))?;
                        }
                        Some(())
                    },
                )?;
            }
            K_SIZE => {
                section(
                    r,
                    out,
                    |_| "Unpack stream sizes".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        for (i, count) in counts.iter().enumerate() {
                            for j in 1..*count {
                                read_number_leaf(
                                    r,
                                    out,
                                    &format!("Folder {i} stream {} size", j - 1),
                                )?;
                            }
                        }
                        Some(())
                    },
                )?;
            }
            K_CRC => {
                let num_digests = counts
                    .iter()
                    .zip(&info.folders)
                    .map(|(&n, f)| if n == 1 && f.crc_defined { 0 } else { n })
                    .fold(0u64, u64::saturating_add);
                section(
                    r,
                    out,
                    |_| "Unpack stream CRCs".to_string(),
                    |r, out| {
                        read_property_id(r, out)?;
                        parse_digests(r, out, num_digests, "Stream")
                    },
                )?;
            }
            _ => {
                read_property_id(r, out)?;
                unknown_property(out, start, r.pos, id);
                return None;
            }
        }
    }
}

fn folder_summary(info: &StreamsInfo) -> String {
    let names: Vec<String> = info
        .folders
        .iter()
        .map(|f| f.coder_names.join(" + "))
        .collect();
    if names.is_empty() {
        "no folders".to_string()
    } else {
        names.join("; ")
    }
}

fn add_pack_streams(info: &StreamsInfo, prefix: &str, packs: &mut Vec<PackStream>) {
    // Map pack streams to folders: each folder consumes num_packed_streams
    // consecutive pack streams.
    let mut owners = Vec::new();
    for (i, folder) in info.folders.iter().enumerate() {
        for _ in 0..folder.num_packed_streams.min(info.pack_sizes.len() as u64) {
            owners.push((i, folder.coder_names.join(" + ")));
        }
    }
    let mut offset = (SIGNATURE_HEADER_SIZE as u64).saturating_add(info.pack_pos);
    for (k, &size) in info.pack_sizes.iter().enumerate() {
        let end = offset.saturating_add(size);
        let mut label = if prefix.is_empty() {
            format!("Pack stream {k}: {size} bytes")
        } else {
            format!("{prefix} pack stream {k}: {size} bytes")
        };
        if let Some((folder, coders)) = owners.get(k) {
            label.push_str(&format!(" (folder {folder}: {coders})"));
        }
        packs.push(PackStream {
            label,
            start: offset,
            end,
        });
        offset = end;
    }
}

fn parse_files_info(r: &mut Reader, out: &mut Vec<Block>) -> Option<()> {
    let num_files = read_number_leaf(r, out, "Number of files")?;
    let mut names: Vec<String> = Vec::new();
    let mut num_empty_streams = 0u64;

    loop {
        let start = r.pos;
        let id = r.number()?;
        if id == K_END {
            out.push(Block::leaf("Property ID: kEnd (0x00)", range(start, r.pos)));
            return Some(());
        }
        let size = r.number()?;
        let body_start = r.pos;
        r.bytes(size)?;
        let body_end = r.pos;

        let mut children = Vec::new();
        let mut id_reader = Reader::new(r.data, start, body_start);
        read_property_id(&mut id_reader, &mut children)?;
        read_number_leaf(&mut id_reader, &mut children, "Size")?;

        let mut body = Reader::new(r.data, body_start, body_end);
        let label = match id {
            K_EMPTY_STREAM => {
                if let Some(bits) =
                    read_bit_vector(&mut body, &mut children, num_files, "Empty streams")
                {
                    num_empty_streams = bits.iter().filter(|b| **b).count() as u64;
                }
                "Empty streams".to_string()
            }
            K_EMPTY_FILE => {
                read_bit_vector(&mut body, &mut children, num_empty_streams, "Empty files");
                "Empty files".to_string()
            }
            K_ANTI => {
                read_bit_vector(&mut body, &mut children, num_empty_streams, "Anti items");
                "Anti items".to_string()
            }
            K_NAME => {
                parse_names(&mut body, &mut children, num_files, &mut names);
                format!("Names ({} files)", names.len())
            }
            K_CTIME | K_ATIME | K_MTIME => {
                let which = match id {
                    K_CTIME => "Creation times",
                    K_ATIME => "Access times",
                    _ => "Modification times",
                };
                parse_file_values(&mut body, &mut children, num_files, &names, 8, |b| {
                    format_filetime(u64::from_le_bytes([
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    ]))
                });
                which.to_string()
            }
            K_WIN_ATTRIBUTES => {
                parse_file_values(&mut body, &mut children, num_files, &names, 4, |b| {
                    describe_attributes(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                });
                "Attributes".to_string()
            }
            K_START_POS => {
                parse_file_values(&mut body, &mut children, num_files, &names, 8, |b| {
                    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string()
                });
                "Start positions".to_string()
            }
            K_COMMENT => "Comment".to_string(),
            K_DUMMY => "Padding".to_string(),
            _ => format!("Unknown property 0x{id:02X} (skipped)"),
        };
        if body.pos < body_end && body.pos > body_start {
            children.push(Block::leaf("Unparsed bytes", range(body.pos, body_end)));
        } else if body.pos == body_start && size > 0 {
            children.push(Block::leaf("Data", range(body_start, body_end)));
        }
        out.push(Block::node(label, range(start, body_end), children));
    }
}

fn parse_names(r: &mut Reader, out: &mut Vec<Block>, num_files: u64, names: &mut Vec<String>) {
    let Some(external) = read_byte_leaf(r, out, "External") else {
        return;
    };
    if external != 0 {
        return;
    }
    while (names.len() as u64) < num_files && r.remaining() >= 2 {
        let start = r.pos;
        let mut units = Vec::new();
        let mut terminated = false;
        while let Some(b) = r.bytes(2) {
            let unit = u16::from_le_bytes([b[0], b[1]]);
            if unit == 0 {
                terminated = true;
                break;
            }
            units.push(unit);
        }
        let name = String::from_utf16_lossy(&units);
        let suffix = if terminated { "" } else { " (unterminated)" };
        out.push(Block::leaf(
            format!("File {}: {name}{suffix}", names.len()),
            range(start, r.pos),
        ));
        names.push(name);
        if !terminated {
            break;
        }
    }
}

/// Parses a defined-vector + External byte + one fixed-size value per
/// defined file (times, attributes, start positions).
fn parse_file_values(
    r: &mut Reader,
    out: &mut Vec<Block>,
    num_files: u64,
    names: &[String],
    value_size: u64,
    describe: impl Fn(&[u8]) -> String,
) -> Option<()> {
    let defined = parse_defined_vector(r, out, num_files)?;
    let external = read_byte_leaf(r, out, "External")?;
    if external != 0 {
        return None;
    }
    for (i, is_defined) in defined.enumerate() {
        if !is_defined {
            continue;
        }
        let start = r.pos;
        let bytes = r.bytes(value_size)?;
        let file = match names.get(i) {
            Some(name) => format!("File {i} ({name})"),
            None => format!("File {i}"),
        };
        out.push(Block::leaf(
            format!("{file}: {}", describe(bytes)),
            range(start, r.pos),
        ));
    }
    Some(())
}

fn describe_attributes(attr: u32) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (0x01, "READONLY"),
        (0x02, "HIDDEN"),
        (0x04, "SYSTEM"),
        (0x10, "DIRECTORY"),
        (0x20, "ARCHIVE"),
        (0x80, "NORMAL"),
    ];
    let mut parts: Vec<String> = FLAGS
        .iter()
        .filter(|(bit, _)| attr & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    // 7-Zip stores Unix mode bits in the high 16 bits when 0x8000 is set.
    if attr & 0x8000 != 0 {
        parts.push(format!("unix mode 0o{:o}", attr >> 16));
    }
    if parts.is_empty() {
        format!("0x{attr:08X}")
    } else {
        format!("0x{attr:08X} ({})", parts.join(" | "))
    }
}

/// Formats a Windows FILETIME (100 ns ticks since 1601-01-01) as UTC.
fn format_filetime(ticks: u64) -> String {
    let unix = (ticks / 10_000_000) as i64 - 11_644_473_600;
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let b = data.get(offset..offset.checked_add(8)?)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Some(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn utf16z(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// Builds a 7z archive from packed data and a raw next header.
    fn build_7z(packed: &[u8], next_header: &[u8]) -> Vec<u8> {
        let mut start_header = Vec::new();
        push_bytes(&mut start_header, &(packed.len() as u64).to_le_bytes());
        push_bytes(&mut start_header, &(next_header.len() as u64).to_le_bytes());
        push_bytes(&mut start_header, &crc32(next_header).to_le_bytes());

        let mut data = Vec::new();
        push_bytes(&mut data, SEVENZIP_MAGIC);
        push_bytes(&mut data, &[0, 4]);
        push_bytes(&mut data, &crc32(&start_header).to_le_bytes());
        push_bytes(&mut data, &start_header);
        push_bytes(&mut data, packed);
        push_bytes(&mut data, next_header);
        data
    }

    // 2000-01-01 00:00:00 UTC as a FILETIME.
    const Y2K_FILETIME: u64 = 125_911_584_000_000_000;

    /// A plain (unencoded) header storing one file "a.txt" with the Copy
    /// coder. Packed data is "hello".
    fn build_plain_7z() -> Vec<u8> {
        let mut h = Vec::new();
        push_bytes(&mut h, &[0x01]); // kHeader
        push_bytes(&mut h, &[0x04]); // kMainStreamsInfo
        push_bytes(&mut h, &[0x06, 0x00, 0x01, 0x09, 0x05, 0x00]); // PackInfo
        push_bytes(&mut h, &[0x07, 0x0B, 0x01, 0x00]); // UnPackInfo, 1 folder
        push_bytes(&mut h, &[0x01, 0x01, 0x00]); // 1 coder: Copy
        push_bytes(&mut h, &[0x0C, 0x05, 0x00]); // unpack size, kEnd
        push_bytes(&mut h, &[0x08, 0x0A, 0x01]); // SubStreamsInfo, kCRC
        push_bytes(&mut h, &crc32(b"hello").to_le_bytes());
        push_bytes(&mut h, &[0x00]); // end SubStreamsInfo
        push_bytes(&mut h, &[0x00]); // end MainStreamsInfo
        push_bytes(&mut h, &[0x05, 0x01]); // kFilesInfo, 1 file
        let name = utf16z("a.txt");
        push_bytes(&mut h, &[0x11, (name.len() + 1) as u8, 0x00]);
        push_bytes(&mut h, &name);
        push_bytes(&mut h, &[0x14, 10, 0x01, 0x00]);
        push_bytes(&mut h, &Y2K_FILETIME.to_le_bytes());
        push_bytes(&mut h, &[0x15, 6, 0x01, 0x00]);
        push_bytes(&mut h, &0x20u32.to_le_bytes());
        push_bytes(&mut h, &[0x00]); // end FilesInfo
        push_bytes(&mut h, &[0x00]); // end Header
        build_7z(b"hello", &h)
    }

    /// An encoded header: the real header is a 10-byte LZMA stream.
    fn build_encoded_7z() -> Vec<u8> {
        let mut h = Vec::new();
        push_bytes(&mut h, &[0x17]); // kEncodedHeader
        push_bytes(&mut h, &[0x06, 0x00, 0x01, 0x09, 0x0A, 0x00]); // PackInfo
        push_bytes(&mut h, &[0x07, 0x0B, 0x01, 0x00, 0x01]); // 1 folder, 1 coder
        push_bytes(&mut h, &[0x23, 0x03, 0x01, 0x01, 0x05]); // LZMA + props
        push_bytes(&mut h, &[0x5D, 0x00, 0x00, 0x10, 0x00]);
        push_bytes(&mut h, &[0x0C, 0x20, 0x00]); // unpack size, kEnd
        push_bytes(&mut h, &[0x00]); // end StreamsInfo
        build_7z(&[0xAA; 10], &h)
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn assert_nested(blocks: &[Block]) {
        for block in blocks {
            assert!(block.range.start <= block.range.end, "{}", block.label);
            for child in &block.children {
                assert!(
                    child.range.start >= block.range.start && child.range.end <= block.range.end,
                    "{} not inside {}",
                    child.label,
                    block.label
                );
            }
            assert_nested(&block.children);
        }
    }

    #[test]
    fn matches_7z_magic() {
        assert!(SevenZipDissector.matches(&build_plain_7z()));
    }

    #[test]
    fn does_not_match_non_7z_data() {
        assert!(!SevenZipDissector.matches(b""));
        assert!(!SevenZipDissector.matches(b"not a 7z archive, just some text"));
        assert!(!SevenZipDissector.matches(&build_plain_7z()[..20]));
    }

    #[test]
    fn number_decoding() {
        let cases: &[(&[u8], u64)] = &[
            (&[0x00], 0),
            (&[0x7F], 0x7F),
            (&[0x80, 0x80], 0x80),
            (&[0xBF, 0xFF], 0x3FFF),
            (&[0xC0, 0x00, 0x40], 0x4000),
            (&[0xC1, 0x02, 0x03], 0x01_0302),
            (&[0xE1, 0x02, 0x03, 0x04], 0x0104_0302),
            (&[0xFF, 1, 2, 3, 4, 5, 6, 7, 8], 0x0807_0605_0403_0201),
        ];
        for (bytes, expected) in cases {
            let mut r = Reader::new(bytes, 0, bytes.len());
            assert_eq!(r.number(), Some(*expected), "{bytes:02X?}");
            assert_eq!(r.pos, bytes.len());
        }
        let mut r = Reader::new(&[0xC0, 0x00], 0, 2);
        assert_eq!(r.number(), None);
        assert_eq!(r.pos, 0);
    }

    #[test]
    fn helpers() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            format_filetime(116_444_736_000_000_000),
            "1970-01-01 00:00:00 UTC"
        );
        assert_eq!(format_filetime(Y2K_FILETIME), "2000-01-01 00:00:00 UTC");
        assert_eq!(codec_name(&[0x21]), "LZMA2");
        assert_eq!(codec_name(&[0x04, 0x02, 0x02]), "BZip2");
        assert_eq!(codec_name(&[0x06, 0xF1, 0x07, 0x01]), "AES-256 + SHA-256");
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let data = build_plain_7z();
        assert!(SevenZipDissector.dissect(&data[..31]).is_empty());
    }

    #[test]
    fn dissect_truncated_input_never_panics() {
        for data in [build_plain_7z(), build_encoded_7z()] {
            let full = SevenZipDissector.dissect(&data).len();
            for n in 0..data.len() {
                let blocks = SevenZipDissector.dissect(&data[..n]);
                assert!(blocks.len() <= full);
                assert_nested(&blocks);
            }
        }
    }

    #[test]
    fn dissect_parses_signature_header() {
        let data = build_plain_7z();
        let blocks = SevenZipDissector.dissect(&data);
        let sig = find_block(&blocks, "Signature header");
        assert_eq!(sig.range, ByteRange::new(0, 32));
        assert!(sig.children.iter().any(|b| b.label == "Version: 0.4"));
        assert!(sig.children.iter().any(|b| b.label.ends_with("(OK)")));
        let off = find_block(&sig.children, "Next header offset: 5 (file offset 37)");
        assert_eq!(off.range, ByteRange::new(12, 20));
    }

    #[test]
    fn dissect_parses_plain_header() {
        let data = build_plain_7z();
        let blocks = SevenZipDissector.dissect(&data);
        assert_nested(&blocks);

        let packed = find_block(&blocks, "Packed streams");
        assert_eq!(packed.range, ByteRange::new(32, 37));
        let stream = find_block(&packed.children, "Pack stream 0: 5 bytes (folder 0: Copy)");
        assert_eq!(stream.range, ByteRange::new(32, 37));

        let next = find_block(&blocks, "Next header (CRC OK)");
        assert_eq!(next.range, ByteRange::new(37, data.len() as u64));
        find_block(&next.children, "Property ID: kHeader (0x01)");

        let main = find_block(&next.children, "Main streams info");
        assert_eq!(main.range, ByteRange::new(38, 64));
        let unpack = find_block(&main.children, "Unpack info");
        let folder = find_block(&unpack.children, "Folder 0: Copy");
        assert_eq!(folder.range, ByteRange::new(49, 52));
        let coder = find_block(&folder.children, "Coder 0: Copy");
        let id = find_block(&coder.children, "Codec ID: 00 (Copy)");
        assert_eq!(id.range, ByteRange::new(51, 52));
        let sub = find_block(&main.children, "Substreams info");
        let crcs = find_block(&sub.children, "Unpack stream CRCs");
        find_block(
            &crcs.children,
            &format!("Stream 0 CRC: 0x{:08X}", crc32(b"hello")),
        );

        let files = find_block(&next.children, "Files info");
        find_block(&files.children, "Number of files: 1");
        let names = find_block(&files.children, "Names (1 files)");
        let name = find_block(&names.children, "File 0: a.txt");
        assert_eq!(name.range, ByteRange::new(69, 81));
        let times = find_block(&files.children, "Modification times");
        let mtime = find_block(&times.children, "File 0 (a.txt): 2000-01-01 00:00:00 UTC");
        assert_eq!(mtime.range, ByteRange::new(85, 93));
        let attrs = find_block(&files.children, "Attributes");
        find_block(&attrs.children, "File 0 (a.txt): 0x00000020 (ARCHIVE)");

        let last = next.children.last().unwrap();
        assert_eq!(last.label, "Property ID: kEnd (0x00)");
        assert_eq!(last.range.end, data.len() as u64);
    }

    #[test]
    fn dissect_parses_encoded_header() {
        let data = build_encoded_7z();
        let blocks = SevenZipDissector.dissect(&data);
        assert_nested(&blocks);

        let packed = find_block(&blocks, "Packed streams");
        let stream = find_block(
            &packed.children,
            "Encoded header pack stream 0: 10 bytes (folder 0: LZMA)",
        );
        assert_eq!(stream.range, ByteRange::new(32, 42));

        let next = find_block(&blocks, "Next header (CRC OK)");
        assert_eq!(next.range, ByteRange::new(42, data.len() as u64));
        find_block(&next.children, "Property ID: kEncodedHeader (0x17)");
        let info = find_block(
            &next.children,
            "Encoded header streams info (real header compressed with LZMA)",
        );
        let unpack = find_block(&info.children, "Unpack info");
        let folder = find_block(&unpack.children, "Folder 0: LZMA");
        let coder = find_block(&folder.children, "Coder 0: LZMA");
        find_block(&coder.children, "Codec ID: 03 01 01 (LZMA)");
        find_block(
            &coder.children,
            "Properties: lc=3 lp=0 pb=2, dictionary 1 MiB",
        );
        let sizes = find_block(&unpack.children, "Unpack sizes");
        find_block(&sizes.children, "Folder 0 output 0 size: 32");
    }

    #[test]
    fn dissect_stops_on_unknown_property() {
        let data = build_7z(b"", &[0x01, 0x04, 0x42, 0x00]);
        let blocks = SevenZipDissector.dissect(&data);
        assert_nested(&blocks);
        let next = find_block(&blocks, "Next header (CRC OK)");
        let main = find_block(&next.children, "Main streams info");
        let unknown = find_block(&main.children, "Unknown property ID 0x42; parsing stopped");
        assert_eq!(unknown.range, ByteRange::new(34, 35));
        let rest = find_block(&next.children, "Unparsed header bytes");
        assert_eq!(rest.range, ByteRange::new(35, 36));
    }

    #[test]
    fn identify_reports_7zip() {
        assert_eq!(super::super::identify(&build_plain_7z()), "7-Zip");
        assert_eq!(super::super::identify(&build_encoded_7z()), "7-Zip");
    }
}
