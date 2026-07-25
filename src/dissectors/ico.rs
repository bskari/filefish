use super::{Block, ByteRange, Dissector};

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

pub struct IcoDissector;

impl Dissector for IcoDissector {
    fn name(&self) -> &'static str {
        "ICO"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= 6
            && data[0] == 0
            && data[1] == 0
            && (data[2..4] == [1, 0] || data[2..4] == [2, 0])
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 6 {
            return blocks;
        }

        let image_type = read_u16(data, 2).unwrap_or(0);
        let count = read_u16(data, 4).unwrap_or(0);

        blocks.push(icondir_block(data, image_type, count));

        let mut offset = 6usize;
        for i in 0..count as usize {
            if data.len() < offset + 16 {
                break;
            }
            blocks.push(icondirentry_block(data, offset, i, image_type));
            offset += 16;
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

fn image_type_name(value: u16) -> &'static str {
    match value {
        1 => "ICO",
        2 => "CUR",
        _ => "unknown",
    }
}

fn icondir_block(data: &[u8], image_type: u16, count: u16) -> Block {
    let _ = data;
    Block::node(
        "ICONDIR header",
        ByteRange::new(0, 6),
        vec![
            Block::leaf("Reserved", ByteRange::new(0, 2)),
            Block::leaf(
                format!("Type: {} ({})", image_type, image_type_name(image_type)),
                ByteRange::new(2, 4),
            ),
            Block::leaf(format!("Image count: {count}"), ByteRange::new(4, 6)),
        ],
    )
    .expanded()
}

fn icondirentry_block(data: &[u8], offset: usize, index: usize, image_type: u16) -> Block {
    let width = data[offset];
    let height = data[offset + 1];
    let color_count = data[offset + 2];
    let planes_or_hotspot_x = read_u16(data, offset + 4).unwrap_or(0);
    let bit_count_or_hotspot_y = read_u16(data, offset + 6).unwrap_or(0);
    let bytes_in_resource = read_u32(data, offset + 8).unwrap_or(0);
    let image_offset = read_u32(data, offset + 12).unwrap_or(0);

    let width_display = if width == 0 { 256 } else { width as u32 };
    let height_display = if height == 0 { 256 } else { height as u32 };

    let (field3_label, field4_label) = if image_type == 2 {
        ("Hotspot X", "Hotspot Y")
    } else {
        ("Planes", "Bit count")
    };

    let mut children = vec![
        Block::leaf(
            format!("Width: {width_display}"),
            ByteRange::new(offset as u64, offset as u64 + 1),
        ),
        Block::leaf(
            format!("Height: {height_display}"),
            ByteRange::new(offset as u64 + 1, offset as u64 + 2),
        ),
        Block::leaf(
            format!("Color count: {color_count}"),
            ByteRange::new(offset as u64 + 2, offset as u64 + 3),
        ),
        Block::leaf("Reserved", ByteRange::new(offset as u64 + 3, offset as u64 + 4)),
        Block::leaf(
            format!("{field3_label}: {planes_or_hotspot_x}"),
            ByteRange::new(offset as u64 + 4, offset as u64 + 6),
        ),
        Block::leaf(
            format!("{field4_label}: {bit_count_or_hotspot_y}"),
            ByteRange::new(offset as u64 + 6, offset as u64 + 8),
        ),
        Block::leaf(
            format!("Bytes in resource: {bytes_in_resource}"),
            ByteRange::new(offset as u64 + 8, offset as u64 + 12),
        ),
        Block::leaf(
            format!("Image offset: {image_offset}"),
            ByteRange::new(offset as u64 + 12, offset as u64 + 16),
        ),
    ];

    if let Some(image_block) = image_data_block(data, image_offset as u64, bytes_in_resource as u64)
    {
        children.push(image_block);
    }

    Block::node(
        format!("ICONDIRENTRY[{index}]"),
        ByteRange::new(offset as u64, offset as u64 + 16),
        children,
    )
    .expanded_if(index == 0)
}

fn image_data_block(data: &[u8], offset: u64, size: u64) -> Option<Block> {
    if size == 0 {
        return None;
    }
    let data_len = data.len() as u64;
    if offset >= data_len {
        return None;
    }
    let end = (offset + size).min(data_len);
    let off = offset as usize;

    if data[off..].starts_with(PNG_MAGIC) {
        return Some(Block::leaf(
            format!("Image data: PNG image ({size} bytes)"),
            ByteRange::new(offset, end),
        ));
    }

    // Otherwise, treat it as a raw DIB (BITMAPINFOHEADER-based) image.
    if let Some(dib) = dib_header_block(data, offset, end) {
        return Some(Block::node(
            format!("Image data: DIB image ({size} bytes)"),
            ByteRange::new(offset, end),
            vec![dib],
        ));
    }

    Some(Block::leaf(
        format!("Image data ({size} bytes)"),
        ByteRange::new(offset, end),
    ))
}

fn dib_header_block(data: &[u8], offset: u64, data_end: u64) -> Option<Block> {
    let off = offset as usize;
    let header_size = read_u32(data, off)?;
    if header_size != 40 || data.len() < off + 40 {
        return None;
    }

    let end = (offset + 40).min(data_end);

    let width = read_i32(data, off + 4)?;
    // ICO DIB headers store double the actual height (AND mask + XOR mask).
    let height = read_i32(data, off + 8)?;
    let planes = read_u16(data, off + 12)?;
    let bpp = read_u16(data, off + 14)?;
    let compression = read_u32(data, off + 16)?;
    let image_size = read_u32(data, off + 20)?;

    Some(
        Block::node(
            "DIB header",
            ByteRange::new(offset, end),
            vec![
                Block::leaf(
                    format!("Header size: {header_size}"),
                    ByteRange::new(offset, offset + 4),
                ),
                Block::leaf(
                    format!("Width: {width}"),
                    ByteRange::new(offset + 4, offset + 8),
                ),
                Block::leaf(
                    format!("Height (combined XOR+AND masks): {height}"),
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
                    format!("Compression: {compression}"),
                    ByteRange::new(offset + 16, offset + 20),
                ),
                Block::leaf(
                    format!("Image size: {image_size}"),
                    ByteRange::new(offset + 20, offset + 24),
                ),
            ],
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(bytes);
    }

    fn build_ico_with_dib(width: u8, height: u8, image_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        let header_len = 6usize;
        let entry_len = 16usize;
        let image_offset = (header_len + entry_len) as u32;

        // ICONDIR
        push_bytes(&mut data, &0u16.to_le_bytes()); // reserved
        push_bytes(&mut data, &1u16.to_le_bytes()); // type = ICO
        push_bytes(&mut data, &1u16.to_le_bytes()); // count

        // ICONDIRENTRY
        data.push(width);
        data.push(height);
        data.push(0); // color count
        data.push(0); // reserved
        push_bytes(&mut data, &1u16.to_le_bytes()); // planes
        push_bytes(&mut data, &32u16.to_le_bytes()); // bit count
        push_bytes(&mut data, &(image_data.len() as u32).to_le_bytes()); // bytes in resource
        push_bytes(&mut data, &image_offset.to_le_bytes()); // image offset

        push_bytes(&mut data, image_data);

        data
    }

    fn build_dib_image(width: i32, height: i32) -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, &40u32.to_le_bytes()); // header size
        push_bytes(&mut data, &width.to_le_bytes());
        push_bytes(&mut data, &height.to_le_bytes());
        push_bytes(&mut data, &1u16.to_le_bytes()); // planes
        push_bytes(&mut data, &32u16.to_le_bytes()); // bpp
        push_bytes(&mut data, &0u32.to_le_bytes()); // compression
        push_bytes(&mut data, &0u32.to_le_bytes()); // image size
        push_bytes(&mut data, &0i32.to_le_bytes()); // h res
        push_bytes(&mut data, &0i32.to_le_bytes()); // v res
        push_bytes(&mut data, &0u32.to_le_bytes()); // colors used
        push_bytes(&mut data, &0u32.to_le_bytes()); // important colors
        push_bytes(&mut data, &[0u8; 32]); // pixel data padding
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
    fn matches_ico_magic() {
        let image = build_dib_image(16, 32);
        let data = build_ico_with_dib(16, 16, &image);
        assert!(IcoDissector.matches(&data));
    }

    #[test]
    fn matches_cur_magic() {
        let mut data = vec![0u8, 0, 2, 0, 0, 0];
        data.extend_from_slice(&[0u8; 16]);
        assert!(IcoDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_ico_data() {
        assert!(!IcoDissector.matches(b"not an ico file"));
        assert!(!IcoDissector.matches(b""));
        assert!(!IcoDissector.matches(b"BM"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        let blocks = IcoDissector.dissect(&[0u8, 0]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_icondir_and_entries() {
        let image = build_dib_image(16, 32);
        let data = build_ico_with_dib(16, 16, &image);
        let blocks = IcoDissector.dissect(&data);

        let icondir = find_block(&blocks, "ICONDIR header");
        assert!(
            icondir
                .children
                .iter()
                .any(|b| b.label == "Type: 1 (ICO)")
        );
        assert!(icondir.children.iter().any(|b| b.label == "Image count: 1"));

        let entry = find_block(&blocks, "ICONDIRENTRY[0]");
        assert!(entry.children.iter().any(|b| b.label == "Width: 16"));
        assert!(entry.children.iter().any(|b| b.label == "Height: 16"));

        let image_block = entry
            .children
            .iter()
            .find(|b| b.label.starts_with("Image data: DIB image"))
            .expect("expected DIB image block");
        let dib = find_block(&image_block.children, "DIB header");
        assert!(dib.children.iter().any(|b| b.label == "Width: 16"));
    }

    #[test]
    fn identify_reports_ico() {
        let image = build_dib_image(16, 32);
        let data = build_ico_with_dib(16, 16, &image);
        assert_eq!(super::super::identify(&data), "ICO");
    }
}
