use super::{Block, ByteRange, Dissector};

const GIF87A: &[u8] = b"GIF87a";
const GIF89A: &[u8] = b"GIF89a";

const EXTENSION_INTRODUCER: u8 = 0x21;
const IMAGE_DESCRIPTOR_INTRODUCER: u8 = 0x2C;
const TRAILER: u8 = 0x3B;

pub struct GifDissector;

impl Dissector for GifDissector {
    fn name(&self) -> &'static str {
        "GIF"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(GIF87A) || data.starts_with(GIF89A)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 6 {
            return blocks;
        }
        blocks.push(Block::leaf("Header", ByteRange::new(0, 6)));

        let (lsd_block, mut offset) = match logical_screen_descriptor_block(data, 6) {
            Some(block) => {
                let end = block.range.end;
                (block, end)
            }
            None => return blocks,
        };
        blocks.push(lsd_block);

        let global_color_table_flag = data.get(10).map(|&b| b & 0x80 != 0).unwrap_or(false);
        let global_color_table_size = data
            .get(10)
            .map(|&b| 2usize << (b & 0x07))
            .unwrap_or(0);

        if global_color_table_flag {
            let table_len = (global_color_table_size * 3) as u64;
            let table_end = offset + table_len;
            if table_end > data.len() as u64 {
                return blocks;
            }
            blocks.push(Block::leaf(
                format!("Global color table ({global_color_table_size} entries)"),
                ByteRange::new(offset, table_end),
            ));
            offset = table_end;
        }

        loop {
            match data.get(offset as usize) {
                Some(&EXTENSION_INTRODUCER) => match extension_block(data, offset) {
                    Some(block) => {
                        offset = block.range.end;
                        blocks.push(block);
                    }
                    None => break,
                },
                Some(&IMAGE_DESCRIPTOR_INTRODUCER) => match image_descriptor_block(data, offset) {
                    Some(block) => {
                        offset = block.range.end;
                        blocks.push(block);
                    }
                    None => break,
                },
                Some(&TRAILER) => {
                    blocks.push(Block::leaf("Trailer", ByteRange::new(offset, offset + 1)));
                    break;
                }
                _ => break,
            }
        }

        blocks
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn logical_screen_descriptor_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 7 {
        return None;
    }

    let width = read_u16(data, off)?;
    let height = read_u16(data, off + 2)?;
    let packed = data[off + 4];
    let background_color_index = data[off + 5];
    let pixel_aspect_ratio = data[off + 6];

    let global_color_table_flag = packed & 0x80 != 0;
    let color_resolution = (packed >> 4) & 0x07;
    let sort_flag = packed & 0x08 != 0;
    let global_color_table_size = 2usize << (packed & 0x07);

    let children = vec![
        Block::leaf(format!("Canvas width: {width}"), ByteRange::new(offset, offset + 2)),
        Block::leaf(
            format!("Canvas height: {height}"),
            ByteRange::new(offset + 2, offset + 4),
        ),
        Block::leaf(
            format!("Global color table flag: {global_color_table_flag}"),
            ByteRange::new(offset + 4, offset + 5),
        ),
        Block::leaf(
            format!("Color resolution: {color_resolution}"),
            ByteRange::new(offset + 4, offset + 5),
        ),
        Block::leaf(
            format!("Sort flag: {sort_flag}"),
            ByteRange::new(offset + 4, offset + 5),
        ),
        Block::leaf(
            format!("Size of global color table: {global_color_table_size}"),
            ByteRange::new(offset + 4, offset + 5),
        ),
        Block::leaf(
            format!("Background color index: {background_color_index}"),
            ByteRange::new(offset + 5, offset + 6),
        ),
        Block::leaf(
            format!("Pixel aspect ratio: {pixel_aspect_ratio}"),
            ByteRange::new(offset + 6, offset + 7),
        ),
    ];

    Some(
        Block::node(
            "Logical screen descriptor",
            ByteRange::new(offset, offset + 7),
            children,
        )
        .expanded(),
    )
}

fn extension_label_name(label: u8) -> &'static str {
    match label {
        0xF9 => "Graphic Control Extension",
        0xFE => "Comment Extension",
        0x01 => "Plain Text Extension",
        0xFF => "Application Extension",
        _ => "Unknown Extension",
    }
}

/// Walks a size-prefixed sub-block sequence starting at `offset` (pointing at
/// the first size byte). Returns (children, end offset) on success, i.e. once
/// a terminating zero-size byte is found. Returns None if the data runs out
/// before a terminator is found.
fn sub_blocks(data: &[u8], offset: u64) -> Option<(Vec<Block>, u64)> {
    let mut children = Vec::new();
    let mut pos = offset;

    loop {
        let size = *data.get(pos as usize)?;
        if size == 0 {
            pos += 1;
            break;
        }
        let data_start = pos + 1;
        let data_end = data_start + size as u64;
        if data_end > data.len() as u64 {
            return None;
        }
        children.push(Block::leaf(
            format!("Sub-block ({size} bytes)"),
            ByteRange::new(pos, data_end),
        ));
        pos = data_end;
    }

    Some((children, pos))
}

fn extension_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    let &label = data.get(off + 1)?;

    let mut children = vec![
        Block::leaf("Introducer", ByteRange::new(offset, offset + 1)),
        Block::leaf(
            format!("Label: {:#04x}", label),
            ByteRange::new(offset + 1, offset + 2),
        ),
    ];

    let (sub_block_children, end) = sub_blocks(data, offset + 2)?;
    children.extend(sub_block_children);

    Some(Block::node(
        format!("Extension: {}", extension_label_name(label)),
        ByteRange::new(offset, end),
        children,
    ))
}

fn image_descriptor_block(data: &[u8], offset: u64) -> Option<Block> {
    let off = offset as usize;
    if data.len() < off + 10 {
        return None;
    }

    let left = read_u16(data, off + 1)?;
    let top = read_u16(data, off + 3)?;
    let width = read_u16(data, off + 5)?;
    let height = read_u16(data, off + 7)?;
    let packed = data[off + 9];

    let local_color_table_flag = packed & 0x80 != 0;
    let interlace_flag = packed & 0x40 != 0;
    let local_color_table_size = 2usize << (packed & 0x1F);

    let mut children = vec![
        Block::leaf("Introducer", ByteRange::new(offset, offset + 1)),
        Block::leaf(
            format!("Image left: {left}"),
            ByteRange::new(offset + 1, offset + 3),
        ),
        Block::leaf(
            format!("Image top: {top}"),
            ByteRange::new(offset + 3, offset + 5),
        ),
        Block::leaf(
            format!("Image width: {width}"),
            ByteRange::new(offset + 5, offset + 7),
        ),
        Block::leaf(
            format!("Image height: {height}"),
            ByteRange::new(offset + 7, offset + 9),
        ),
        Block::leaf(
            format!("Local color table flag: {local_color_table_flag}"),
            ByteRange::new(offset + 9, offset + 10),
        ),
        Block::leaf(
            format!("Interlace flag: {interlace_flag}"),
            ByteRange::new(offset + 9, offset + 10),
        ),
    ];

    let mut pos = offset + 10;

    if local_color_table_flag {
        let table_len = (local_color_table_size * 3) as u64;
        let table_end = pos + table_len;
        if table_end > data.len() as u64 {
            return None;
        }
        children.push(Block::leaf(
            format!("Local color table ({local_color_table_size} entries)"),
            ByteRange::new(pos, table_end),
        ));
        pos = table_end;
    }

    let &lzw_min_code_size = data.get(pos as usize)?;
    children.push(Block::leaf(
        format!("LZW minimum code size: {lzw_min_code_size}"),
        ByteRange::new(pos, pos + 1),
    ));
    pos += 1;

    let (sub_block_children, end) = sub_blocks(data, pos)?;
    children.push(Block::node(
        "Image data",
        ByteRange::new(pos, end),
        sub_block_children,
    ));

    Some(Block::node(
        "Image descriptor",
        ByteRange::new(offset, end),
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    /// Builds a minimal synthetic GIF: header, logical screen descriptor
    /// (no global color table), one Graphic Control Extension, one minimal
    /// image descriptor (no local color table) with a tiny fake LZW data
    /// sub-block, then trailer.
    fn build_gif() -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        push_bytes(&mut data, GIF89A);

        // Logical screen descriptor: 10x5 canvas, no global color table
        push_bytes(&mut data, &10u16.to_le_bytes()); // width
        push_bytes(&mut data, &5u16.to_le_bytes()); // height
        data.push(0x00); // packed: no global color table
        data.push(0x00); // background color index
        data.push(0x00); // pixel aspect ratio

        // Graphic Control Extension
        data.push(EXTENSION_INTRODUCER);
        data.push(0xF9); // label
        data.push(4); // sub-block size
        push_bytes(&mut data, &[0x00, 0x0A, 0x00, 0x00]); // fake GCE data
        data.push(0x00); // terminator

        // Image descriptor
        data.push(IMAGE_DESCRIPTOR_INTRODUCER);
        push_bytes(&mut data, &0u16.to_le_bytes()); // left
        push_bytes(&mut data, &0u16.to_le_bytes()); // top
        push_bytes(&mut data, &10u16.to_le_bytes()); // width
        push_bytes(&mut data, &5u16.to_le_bytes()); // height
        data.push(0x00); // packed: no local color table
        data.push(2); // LZW minimum code size
        data.push(2); // sub-block size
        push_bytes(&mut data, &[0x00, 0x01]); // fake LZW data
        data.push(0x00); // terminator

        // Trailer
        data.push(TRAILER);

        data
    }

    #[test]
    fn matches_gif_magic() {
        let mut gif87 = Vec::new();
        push_bytes(&mut gif87, GIF87A);
        assert!(GifDissector.matches(&gif87));

        let data = build_gif();
        assert!(GifDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_gif_data() {
        assert!(!GifDissector.matches(b"not a gif file"));
        assert!(!GifDissector.matches(b""));
        assert!(!GifDissector.matches(b"GIF88a"));
    }

    #[test]
    fn dissect_returns_empty_or_graceful_for_truncated_header() {
        let blocks = GifDissector.dissect(b"GIF89a");
        assert!(blocks.len() <= 1);

        let blocks = GifDissector.dissect(b"GIF89a\x0A\x00\x05");
        assert!(blocks.len() <= 1);
    }

    #[test]
    fn dissect_parses_full_structure() {
        let data = build_gif();
        let blocks = GifDissector.dissect(&data);

        find_block(&blocks, "Header");

        let lsd = find_block(&blocks, "Logical screen descriptor");
        assert!(lsd.children.iter().any(|b| b.label == "Canvas width: 10"));
        assert!(lsd.children.iter().any(|b| b.label == "Canvas height: 5"));

        let gce = find_block(&blocks, "Extension: Graphic Control Extension");
        assert!(!gce.children.is_empty());

        let img = find_block(&blocks, "Image descriptor");
        assert!(
            img.children
                .iter()
                .any(|b| b.label == "Image width: 10")
        );
        assert!(
            img.children
                .iter()
                .any(|b| b.label == "Image height: 5")
        );
        assert!(img.children.iter().any(|b| b.label == "Image data"));

        find_block(&blocks, "Trailer");
    }

    #[test]
    fn identify_reports_gif() {
        let data = build_gif();
        assert_eq!(super::super::identify(&data), "GIF");
    }
}
