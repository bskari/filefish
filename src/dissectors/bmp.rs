use super::{Block, ByteRange, Dissector};

const BMP_MAGIC: &[u8] = b"BM";

pub struct BmpDissector;

impl Dissector for BmpDissector {
    fn name(&self) -> &'static str {
        "BMP"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(BMP_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 14 {
            return blocks;
        }

        let file_size = read_u32(data, 2).unwrap_or(0);
        let pixel_data_offset = read_u32(data, 10).unwrap_or(0);

        blocks.push(file_header_block(data));

        let dib_header_size = read_u32(data, 14);
        if let Some(dib_size) = dib_header_size {
            if let Some(dib_block) = dib_header_block(data, 14, dib_size as u64) {
                blocks.push(dib_block);
            }
        }

        let offset = pixel_data_offset as u64;
        let data_len = data.len() as u64;
        let declared_end = (file_size as u64).min(data_len);
        let end = if declared_end > offset {
            declared_end
        } else {
            data_len
        };
        if offset < data_len && end > offset {
            blocks.push(Block::leaf("Pixel data", ByteRange::new(offset, end)));
        }

        blocks
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    read_u32(data, offset).map(|v| v as i32)
}

fn compression_name(value: u32) -> String {
    match value {
        0 => "BI_RGB".to_string(),
        1 => "BI_RLE8".to_string(),
        2 => "BI_RLE4".to_string(),
        3 => "BI_BITFIELDS".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn file_header_block(data: &[u8]) -> Block {
    let file_size = read_u32(data, 2).unwrap_or(0);
    let pixel_data_offset = read_u32(data, 10).unwrap_or(0);
    Block::node(
        "BMP file header",
        ByteRange::new(0, 14),
        vec![
            Block::leaf("Signature: BM", ByteRange::new(0, 2)),
            Block::leaf(format!("File size: {file_size}"), ByteRange::new(2, 6)),
            Block::leaf("Reserved", ByteRange::new(6, 10)),
            Block::leaf(
                format!("Pixel data offset: {pixel_data_offset}"),
                ByteRange::new(10, 14),
            ),
        ],
    )
    .expanded()
}

fn dib_header_block(data: &[u8], offset: u64, size: u64) -> Option<Block> {
    let off = offset as usize;
    if size == 0 {
        return None;
    }
    let data_len = data.len() as u64;
    let end = (offset + size).min(data_len);

    if size == 40 && data.len() >= off + 40 {
        let width = read_i32(data, off + 4)?;
        let height = read_i32(data, off + 8)?;
        let planes = read_u16(data, off + 12)?;
        let bpp = read_u16(data, off + 14)?;
        let compression = read_u32(data, off + 16)?;
        let image_size = read_u32(data, off + 20)?;
        let h_res = read_i32(data, off + 24)?;
        let v_res = read_i32(data, off + 28)?;
        let colors_used = read_u32(data, off + 32)?;
        let important_colors = read_u32(data, off + 36)?;

        return Some(
            Block::node(
                "DIB header",
                ByteRange::new(offset, end),
                vec![
                    Block::leaf(
                        format!("Header size: {size}"),
                        ByteRange::new(offset, offset + 4),
                    ),
                    Block::leaf(
                        format!("Width: {width}"),
                        ByteRange::new(offset + 4, offset + 8),
                    ),
                    Block::leaf(
                        format!("Height: {height}"),
                        ByteRange::new(offset + 8, offset + 12),
                    ),
                    Block::leaf(
                        format!("Planes: {planes}"),
                        ByteRange::new(offset + 12, offset + 14),
                    ),
                    Block::leaf(
                        format!("Bits per pixel: {bpp}"),
                        ByteRange::new(offset + 14, offset + 16),
                    ),
                    Block::leaf(
                        format!("Compression: {}", compression_name(compression)),
                        ByteRange::new(offset + 16, offset + 20),
                    ),
                    Block::leaf(
                        format!("Image size: {image_size}"),
                        ByteRange::new(offset + 20, offset + 24),
                    ),
                    Block::leaf(
                        format!("Horizontal resolution: {h_res}"),
                        ByteRange::new(offset + 24, offset + 28),
                    ),
                    Block::leaf(
                        format!("Vertical resolution: {v_res}"),
                        ByteRange::new(offset + 28, offset + 32),
                    ),
                    Block::leaf(
                        format!("Colors used: {colors_used}"),
                        ByteRange::new(offset + 32, offset + 36),
                    ),
                    Block::leaf(
                        format!("Important colors: {important_colors}"),
                        ByteRange::new(offset + 36, offset + 40),
                    ),
                ],
            )
            .expanded(),
        );
    }

    Some(Block::leaf(
        format!("DIB header ({size} bytes)"),
        ByteRange::new(offset, end),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_bmp(width: i32, height: i32, bpp: u16, pixel_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        let header_size = 14u32;
        let dib_size = 40u32;
        let pixel_data_offset = header_size + dib_size;
        let file_size = pixel_data_offset + pixel_data.len() as u32;

        // BITMAPFILEHEADER
        push_bytes(&mut data, b"BM");
        push_bytes(&mut data, &file_size.to_le_bytes());
        push_bytes(&mut data, &0u16.to_le_bytes()); // reserved1
        push_bytes(&mut data, &0u16.to_le_bytes()); // reserved2
        push_bytes(&mut data, &pixel_data_offset.to_le_bytes());

        // BITMAPINFOHEADER
        push_bytes(&mut data, &dib_size.to_le_bytes());
        push_bytes(&mut data, &width.to_le_bytes());
        push_bytes(&mut data, &height.to_le_bytes());
        push_bytes(&mut data, &1u16.to_le_bytes()); // planes
        push_bytes(&mut data, &bpp.to_le_bytes());
        push_bytes(&mut data, &0u32.to_le_bytes()); // compression: BI_RGB
        push_bytes(&mut data, &(pixel_data.len() as u32).to_le_bytes()); // image size
        push_bytes(&mut data, &2835i32.to_le_bytes()); // h res
        push_bytes(&mut data, &2835i32.to_le_bytes()); // v res
        push_bytes(&mut data, &0u32.to_le_bytes()); // colors used
        push_bytes(&mut data, &0u32.to_le_bytes()); // important colors

        push_bytes(&mut data, pixel_data);

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
    fn matches_bmp_magic() {
        let data = build_bmp(2, 2, 24, &[0u8; 16]);
        assert!(BmpDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_bmp_data() {
        assert!(!BmpDissector.matches(b"not a bmp file"));
        assert!(!BmpDissector.matches(b""));
        assert!(!BmpDissector.matches(b"BZh91AY"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = BmpDissector.dissect(b"BM");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_headers_and_pixel_data() {
        let pixel_data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let data = build_bmp(4, 2, 24, &pixel_data);
        let blocks = BmpDissector.dissect(&data);

        let file_header = find_block(&blocks, "BMP file header");
        assert!(
            file_header
                .children
                .iter()
                .any(|b| b.label == "Signature: BM")
        );

        let dib = find_block(&blocks, "DIB header");
        assert!(dib.children.iter().any(|b| b.label == "Width: 4"));
        assert!(dib.children.iter().any(|b| b.label == "Height: 2"));
        assert!(
            dib.children
                .iter()
                .any(|b| b.label == "Bits per pixel: 24")
        );
        assert!(
            dib.children
                .iter()
                .any(|b| b.label == "Compression: BI_RGB")
        );

        let pixel_block = find_block(&blocks, "Pixel data");
        assert_eq!(pixel_block.range, ByteRange::new(54, 70));
    }

    #[test]
    fn identify_reports_bmp() {
        let data = build_bmp(1, 1, 24, &[0u8; 4]);
        assert_eq!(super::super::identify(&data), "BMP");
    }
}
