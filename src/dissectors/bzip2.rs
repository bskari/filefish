use super::{Block, ByteRange, Dissector};

const STREAM_MAGIC: &[u8] = b"BZh";
/// 48-bit block header magic: BCD digits of pi.
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
/// 48-bit end-of-stream magic: BCD digits of sqrt(pi).
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const MAGIC_BITS: u64 = 48;
const MAGIC_MASK: u64 = (1 << MAGIC_BITS) - 1;

const HEADER_LEN: usize = 4;
/// Bits from the start of a block magic to the start of its Huffman data:
/// magic (48) + block CRC (32) + randomised (1) + origPtr (24).
const BLOCK_HEADER_BITS: u64 = 105;
/// Bits from the start of the end-of-stream magic to its padding:
/// magic (48) + combined CRC (32).
const EOS_BITS: u64 = 80;

/// Maximum number of compressed blocks shown individually across all streams.
const MAX_BLOCKS: usize = 1000;

pub struct Bzip2Dissector;

impl Dissector for Bzip2Dissector {
    fn name(&self) -> &'static str {
        "bzip2"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if !has_stream_header(data, 0) {
            return false;
        }
        matches!(
            read_bits(data, HEADER_LEN as u64 * 8, 48),
            Some(BLOCK_MAGIC | EOS_MAGIC)
        )
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let streams = parse_streams(data);
        let mut blocks = Vec::new();
        if streams.is_empty() {
            return blocks;
        }
        let mut budget = MAX_BLOCKS;
        let single = streams.len() == 1;

        let mut shown_streams = 0;
        for (index, stream) in streams.iter().enumerate() {
            if budget == 0 && index > 0 {
                break;
            }
            let children = stream_children(data, stream, &mut budget);
            shown_streams += 1;
            if single {
                blocks.extend(children);
            } else {
                let label = format!(
                    "Stream {} ({} block{})",
                    index + 1,
                    stream.blocks.len(),
                    if stream.blocks.len() == 1 { "" } else { "s" }
                );
                blocks.push(
                    Block::node(label, span(stream.start, stream.end), children)
                        .expanded_if(index == 0),
                );
            }
        }

        if shown_streams < streams.len() {
            let rest = &streams[shown_streams..];
            blocks.push(Block::leaf(
                format!(
                    "Streams {}-{} (not shown)",
                    shown_streams + 1,
                    streams.len()
                ),
                span(rest[0].start, rest[rest.len() - 1].end),
            ));
        }

        let end = streams.last().map_or(0, |s| s.end);
        if end < data.len() {
            blocks.push(Block::leaf("Trailing data", span(end, data.len())));
        }

        blocks
    }
}

/// A bzip2 stream located by scanning for its bit-aligned markers.
struct Stream {
    /// Byte offset of the "BZh" header.
    start: usize,
    /// Byte offset just past the stream (end of EOS padding, or end of data).
    end: usize,
    /// Bit offsets of each block magic.
    blocks: Vec<u64>,
    /// Bit offset of the end-of-stream magic, if found.
    eos: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Marker {
    Block,
    Eos,
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

/// Byte range covering every byte that contains a bit in `[start_bit, end_bit)`.
fn bit_span(start_bit: u64, end_bit: u64) -> ByteRange {
    ByteRange::new(start_bit / 8, end_bit.div_ceil(8))
}

/// Suffix describing a bit position, shown only when it isn't byte-aligned.
fn bit_pos(bit: u64) -> String {
    if bit % 8 == 0 {
        String::new()
    } else {
        format!(" [byte {} + {} bits]", bit / 8, bit % 8)
    }
}

fn has_stream_header(data: &[u8], offset: usize) -> bool {
    data.get(offset..offset + HEADER_LEN)
        .is_some_and(|h| h.starts_with(STREAM_MAGIC) && (b'1'..=b'9').contains(&h[3]))
}

/// Reads `count` (at most 57) bits MSB-first starting at bit offset `bit`.
fn read_bits(data: &[u8], bit: u64, count: u32) -> Option<u64> {
    let end = bit.checked_add(count as u64)?;
    if end > data.len() as u64 * 8 {
        return None;
    }
    let mut value = 0u64;
    for b in bit..end {
        let byte = data[(b / 8) as usize];
        value = (value << 1) | ((byte >> (7 - (b % 8))) & 1) as u64;
    }
    Some(value)
}

/// Finds the first block or end-of-stream magic starting at or after bit
/// offset `from_bit`, returning its bit offset. Scans a byte at a time with a
/// rolling 64-bit window, testing the eight bit alignments ending in each byte.
fn find_marker(data: &[u8], from_bit: u64) -> Option<(u64, Marker)> {
    let first = (from_bit / 8) as usize;
    let mut window = 0u64;
    for (i, &byte) in data.iter().enumerate().skip(first) {
        window = (window << 8) | byte as u64;
        let end_byte_bit = (i as u64 + 1) * 8;
        // Shifts 7..=0 give magic end positions in increasing order.
        for shift in (0..8u64).rev() {
            let Some(start) = (end_byte_bit - shift).checked_sub(MAGIC_BITS) else {
                continue;
            };
            if start < from_bit {
                continue;
            }
            match (window >> shift) & MAGIC_MASK {
                BLOCK_MAGIC => return Some((start, Marker::Block)),
                EOS_MAGIC => return Some((start, Marker::Eos)),
                _ => {}
            }
        }
    }
    None
}

fn parse_streams(data: &[u8]) -> Vec<Stream> {
    let mut streams = Vec::new();
    let mut offset = 0;
    while has_stream_header(data, offset) {
        let mut stream = Stream {
            start: offset,
            end: data.len(),
            blocks: Vec::new(),
            eos: None,
        };
        let mut from = (offset + HEADER_LEN) as u64 * 8;
        while let Some((bit, marker)) = find_marker(data, from) {
            match marker {
                Marker::Block => {
                    stream.blocks.push(bit);
                    from = bit + MAGIC_BITS;
                }
                Marker::Eos => {
                    stream.eos = Some(bit);
                    stream.end = ((bit + EOS_BITS).div_ceil(8) as usize).min(data.len());
                    break;
                }
            }
        }
        offset = stream.end;
        streams.push(stream);
        if stream_is_open(&streams) {
            break;
        }
    }
    streams
}

fn stream_is_open(streams: &[Stream]) -> bool {
    streams.last().is_some_and(|s| s.eos.is_none())
}

fn stream_children(data: &[u8], stream: &Stream, budget: &mut usize) -> Vec<Block> {
    let mut children = vec![header_block(data, stream.start)];
    let data_end_bit = data.len() as u64 * 8;
    let blocks_end_bit = stream.eos.unwrap_or(data_end_bit);

    for (i, &bit) in stream.blocks.iter().enumerate() {
        if *budget == 0 {
            let last = stream.blocks.len();
            children.push(Block::leaf(
                format!("Blocks {}-{} (not shown)", i + 1, last),
                bit_span(bit, blocks_end_bit),
            ));
            break;
        }
        *budget -= 1;
        let next = stream.blocks.get(i + 1).copied().unwrap_or(blocks_end_bit);
        children.push(compressed_block(data, i + 1, bit, next));
    }

    if let Some(bit) = stream.eos {
        children.push(eos_block(data, bit));
    }
    children
}

fn header_block(data: &[u8], start: usize) -> Block {
    let level = data[start + 3] - b'0';
    Block::node(
        "Stream header",
        span(start, start + HEADER_LEN),
        vec![
            Block::leaf("Signature: BZ", span(start, start + 2)),
            Block::leaf("Version: h (Huffman)", span(start + 2, start + 3)),
            Block::leaf(
                format!("Block size: {level} ({}00 kB)", level),
                span(start + 3, start + 4),
            ),
        ],
    )
    .expanded()
}

fn compressed_block(data: &[u8], number: usize, bit: u64, next: u64) -> Block {
    let mut children = vec![Block::leaf(
        format!("Block magic: 0x{BLOCK_MAGIC:012X} (pi){}", bit_pos(bit)),
        bit_span(bit, bit + MAGIC_BITS),
    )];
    let crc_bit = bit + MAGIC_BITS;
    if let Some(crc) = read_bits(data, crc_bit, 32).filter(|_| crc_bit + 32 <= next) {
        children.push(Block::leaf(
            format!("Block CRC: 0x{crc:08X}{}", bit_pos(crc_bit)),
            bit_span(crc_bit, crc_bit + 32),
        ));
    }
    let rand_bit = crc_bit + 32;
    if let Some(rand) = read_bits(data, rand_bit, 1).filter(|_| rand_bit + 1 <= next) {
        children.push(Block::leaf(
            format!(
                "Randomised: {}{}",
                if rand == 1 { "yes (deprecated)" } else { "no" },
                bit_pos(rand_bit)
            ),
            bit_span(rand_bit, rand_bit + 1),
        ));
    }
    let ptr_bit = rand_bit + 1;
    if let Some(ptr) = read_bits(data, ptr_bit, 24).filter(|_| ptr_bit + 24 <= next) {
        children.push(Block::leaf(
            format!("origPtr: {ptr}{}", bit_pos(ptr_bit)),
            bit_span(ptr_bit, ptr_bit + 24),
        ));
    }
    let data_bit = bit + BLOCK_HEADER_BITS;
    if next > data_bit {
        children.push(Block::leaf(
            format!(
                "Compressed data: {} bits{}",
                next - data_bit,
                bit_pos(data_bit)
            ),
            bit_span(data_bit, next),
        ));
    }
    Block::node(
        format!("Block {number}{}", bit_pos(bit)),
        bit_span(bit, next),
        children,
    )
}

fn eos_block(data: &[u8], bit: u64) -> Block {
    let mut children = vec![Block::leaf(
        format!(
            "End-of-stream magic: 0x{EOS_MAGIC:012X} (sqrt pi){}",
            bit_pos(bit)
        ),
        bit_span(bit, bit + MAGIC_BITS),
    )];
    let crc_bit = bit + MAGIC_BITS;
    let end_bit = bit + EOS_BITS;
    if let Some(crc) = read_bits(data, crc_bit, 32) {
        children.push(Block::leaf(
            format!("Combined stream CRC: 0x{crc:08X}{}", bit_pos(crc_bit)),
            bit_span(crc_bit, end_bit),
        ));
        let pad_bits = (8 - end_bit % 8) % 8;
        if pad_bits > 0 {
            let pad = read_bits(data, end_bit, pad_bits as u32).unwrap_or(0);
            children.push(Block::leaf(
                format!(
                    "Padding: {pad_bits} bit{} (0b{pad:0width$b}){}",
                    if pad_bits == 1 { "" } else { "s" },
                    bit_pos(end_bit),
                    width = pad_bits as usize
                ),
                bit_span(end_bit, end_bit + pad_bits),
            ));
        }
    }
    let end = end_bit.div_ceil(8).min(data.len() as u64);
    Block::node(
        format!("End of stream{}", bit_pos(bit)),
        ByteRange::new(bit / 8, end),
        children,
    )
    .expanded()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MSB-first bit writer matching bzip2's bit order.
    struct BitWriter {
        bytes: Vec<u8>,
        bits: u64,
    }

    impl BitWriter {
        fn new(prefix: &[u8]) -> Self {
            Self {
                bytes: prefix.to_vec(),
                bits: prefix.len() as u64 * 8,
            }
        }

        fn put(&mut self, value: u64, count: u32) {
            for i in (0..count).rev() {
                if self.bits % 8 == 0 {
                    self.bytes.push(0);
                }
                let bit = (value >> i) & 1;
                let last = self.bytes.last_mut().unwrap();
                *last |= (bit as u8) << (7 - (self.bits % 8));
                self.bits += 1;
            }
        }
    }

    /// Writes one stream. Each block gets a header and `payload_bits` filler
    /// bits (all ones, which can never form a magic).
    fn write_stream(w: &mut BitWriter, level: u8, blocks: &[(u32, u32, u64)], crc: u32) {
        assert_eq!(w.bits % 8, 0);
        for &b in b"BZh" {
            w.put(b as u64, 8);
        }
        w.put((b'0' + level) as u64, 8);
        for &(block_crc, orig_ptr, payload_bits) in blocks {
            w.put(BLOCK_MAGIC, 48);
            w.put(block_crc as u64, 32);
            w.put(0, 1);
            w.put(orig_ptr as u64, 24);
            for _ in 0..payload_bits {
                w.put(1, 1);
            }
        }
        w.put(EOS_MAGIC, 48);
        w.put(crc as u64, 32);
        while w.bits % 8 != 0 {
            w.put(0, 1);
        }
    }

    fn build_bzip2(blocks: &[(u32, u32, u64)]) -> Vec<u8> {
        let mut w = BitWriter::new(&[]);
        write_stream(&mut w, 9, blocks, 0xCAFE_BABE);
        w.bytes
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
    fn matches_bzip2_streams() {
        assert!(Bzip2Dissector.matches(&build_bzip2(&[(1, 2, 20)])));
        assert!(Bzip2Dissector.matches(&build_bzip2(&[])));
    }

    #[test]
    fn does_not_match_non_bzip2_data() {
        assert!(!Bzip2Dissector.matches(b""));
        assert!(!Bzip2Dissector.matches(b"BZh9"));
        assert!(!Bzip2Dissector.matches(b"not a bzip2 file"));
        let mut data = build_bzip2(&[(1, 2, 20)]);
        data[3] = b'0';
        assert!(!Bzip2Dissector.matches(&data));
        let mut data = build_bzip2(&[(1, 2, 20)]);
        data[4] ^= 0xFF;
        assert!(!Bzip2Dissector.matches(&data));
        assert!(!Bzip2Dissector.matches(&data[..8]));
    }

    #[test]
    fn finds_markers_at_every_bit_alignment() {
        for shift in 0..8u32 {
            let mut w = BitWriter::new(&[0xAB, 0xCD]);
            w.put(0, shift);
            w.put(EOS_MAGIC, 48);
            w.put(0, 8);
            assert_eq!(
                find_marker(&w.bytes, 0),
                Some((16 + shift as u64, Marker::Eos)),
                "shift {shift}"
            );
            assert_eq!(find_marker(&w.bytes, 17 + shift as u64), None);
        }
    }

    #[test]
    fn dissects_single_stream() {
        // Block 1: 105 header bits + 7 payload = 112 bits = 14 bytes, so block 2
        // starts byte-aligned at byte 18. Block 2 has 3 payload bits, so the
        // EOS starts at bit 144 + 108 = 252 (byte 31 + 4 bits).
        let data = build_bzip2(&[(0x1234_5678, 42, 7), (0xDEAD_BEEF, 0x00AB_CDEF, 3)]);
        let blocks = Bzip2Dissector.dissect(&data);
        assert_eq!(blocks.len(), 4);

        let header = find_block(&blocks, "Stream header");
        assert_eq!(header.range, ByteRange::new(0, 4));
        assert_eq!(
            find_block(&header.children, "Block size: 9 (900 kB)").range,
            ByteRange::new(3, 4)
        );

        let b1 = find_block(&blocks, "Block 1");
        assert_eq!(b1.range, ByteRange::new(4, 18));
        let c = &b1.children;
        assert_eq!(
            find_block(c, "Block magic: 0x314159265359 (pi)").range,
            ByteRange::new(4, 10)
        );
        assert_eq!(
            find_block(c, "Block CRC: 0x12345678").range,
            ByteRange::new(10, 14)
        );
        assert_eq!(
            find_block(c, "Randomised: no").range,
            ByteRange::new(14, 15)
        );
        assert_eq!(
            find_block(c, "origPtr: 42 [byte 14 + 1 bits]").range,
            ByteRange::new(14, 18)
        );
        assert_eq!(
            find_block(c, "Compressed data: 7 bits [byte 17 + 1 bits]").range,
            ByteRange::new(17, 18)
        );

        let b2 = find_block(&blocks, "Block 2");
        assert_eq!(b2.range, ByteRange::new(18, 32));
        assert!(
            b2.children
                .iter()
                .any(|b| b.label == "origPtr: 11259375 [byte 28 + 1 bits]")
        );

        let eos = find_block(&blocks, "End of stream [byte 31 + 4 bits]");
        assert_eq!(eos.range, ByteRange::new(31, data.len() as u64));
        assert_eq!(data.len(), 42);
        let c = &eos.children;
        assert_eq!(
            find_block(
                c,
                "End-of-stream magic: 0x177245385090 (sqrt pi) [byte 31 + 4 bits]"
            )
            .range,
            ByteRange::new(31, 38)
        );
        assert_eq!(
            find_block(c, "Combined stream CRC: 0xCAFEBABE [byte 37 + 4 bits]").range,
            ByteRange::new(37, 42)
        );
        assert_eq!(
            find_block(c, "Padding: 4 bits (0b0000) [byte 41 + 4 bits]").range,
            ByteRange::new(41, 42)
        );
    }

    #[test]
    fn dissects_empty_stream() {
        let data = build_bzip2(&[]);
        assert_eq!(data.len(), 14);
        let blocks = Bzip2Dissector.dissect(&data);
        assert_eq!(blocks.len(), 2);
        let eos = find_block(&blocks, "End of stream");
        assert_eq!(eos.range, ByteRange::new(4, 14));
        assert_eq!(eos.children.len(), 2);
    }

    #[test]
    fn dissects_concatenated_streams_and_trailing_data() {
        let mut w = BitWriter::new(&[]);
        write_stream(&mut w, 1, &[(1, 0, 3)], 1);
        let first_len = w.bytes.len() as u64;
        write_stream(&mut w, 5, &[(2, 0, 10), (3, 0, 10)], 2);
        let total = w.bytes.len() as u64;
        let mut data = w.bytes;
        data.extend_from_slice(b"junk");

        let blocks = Bzip2Dissector.dissect(&data);
        assert_eq!(blocks.len(), 3);
        let s1 = find_block(&blocks, "Stream 1 (1 block)");
        assert_eq!(s1.range, ByteRange::new(0, first_len));
        let s2 = find_block(&blocks, "Stream 2 (2 blocks)");
        assert_eq!(s2.range, ByteRange::new(first_len, total));
        let header = find_block(&s2.children, "Stream header");
        find_block(&header.children, "Block size: 5 (500 kB)");
        assert_eq!(
            find_block(&blocks, "Trailing data").range,
            ByteRange::new(total, total + 4)
        );
    }

    #[test]
    fn caps_number_of_blocks_shown() {
        let specs = vec![(0u32, 0u32, 3u64); MAX_BLOCKS + 5];
        let data = build_bzip2(&specs);
        let blocks = Bzip2Dissector.dissect(&data);
        // Header, MAX_BLOCKS blocks, summary, EOS.
        assert_eq!(blocks.len(), MAX_BLOCKS + 3);
        let label = format!("Blocks {}-{} (not shown)", MAX_BLOCKS + 1, MAX_BLOCKS + 5);
        find_block(&blocks, &label);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let data = build_bzip2(&[(0x1234_5678, 42, 7), (5, 6, 30)]);
        let full = Bzip2Dissector.dissect(&data).len();
        for len in 0..data.len() {
            let blocks = Bzip2Dissector.dissect(&data[..len]);
            assert!(blocks.len() <= full);
        }
        assert!(Bzip2Dissector.dissect(b"BZh").is_empty());
        // Cut inside block 1's CRC: the block is shown with just its magic.
        let blocks = Bzip2Dissector.dissect(&data[..12]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(find_block(&blocks, "Block 1").children.len(), 1);
    }

    #[test]
    fn identify_reports_bzip2() {
        assert_eq!(super::super::identify(&build_bzip2(&[(1, 2, 20)])), "bzip2");
        assert_eq!(super::super::identify(&build_bzip2(&[])), "bzip2");
    }
}
