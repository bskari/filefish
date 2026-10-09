use super::{Block, ByteRange, Dissector};

const PSD_MAGIC: &[u8] = b"8BPS";
const HEADER_LEN: u64 = 26;

/// Signatures that may start an image resource block.
const RESOURCE_SIGNATURES: [&[u8]; 5] = [b"8BIM", b"MeSa", b"AgHg", b"PHUT", b"DCSR"];

/// Tagged-block keys whose length field is 8 bytes in PSB files.
const PSB_LONG_KEYS: [&[u8]; 13] = [
    b"LMsk", b"Lr16", b"Lr32", b"Layr", b"Mt16", b"Mt32", b"Mtrn", b"Alph", b"FMsk", b"lnk2",
    b"FEid", b"FXid", b"PxSD",
];

/// Longest layer/resource name shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct PsdDissector;

impl Dissector for PsdDissector {
    fn name(&self) -> &'static str {
        "PSD"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(PSD_MAGIC) && matches!(read_u16(data, 4), Some(1) | Some(2))
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let data_len = data.len() as u64;
        if data_len < HEADER_LEN {
            return blocks;
        }
        let psb = read_u16(data, 4) == Some(2);
        blocks.push(header_block(data, psb));

        // Color mode data section.
        let mut off = HEADER_LEN;
        let Some(cm_len) = read_u32(data, off) else {
            return blocks;
        };
        let cm_len = cm_len as u64;
        let cm_end = off.saturating_add(4).saturating_add(cm_len);
        let mut children = vec![Block::leaf(
            format!("Length: {cm_len}"),
            ByteRange::new(off, off + 4),
        )];
        if cm_len > 0 && off + 4 < data_len {
            children.push(Block::leaf(
                "Data",
                ByteRange::new(off + 4, cm_end.min(data_len)),
            ));
        }
        blocks.push(Block::node(
            "Color mode data",
            ByteRange::new(off, cm_end.min(data_len)),
            children,
        ));
        off = cm_end;

        // Image resources section.
        let Some(ir_len) = read_u32(data, off) else {
            return blocks;
        };
        let ir_len = ir_len as u64;
        let ir_end = off.saturating_add(4).saturating_add(ir_len);
        let mut children = vec![Block::leaf(
            format!("Length: {ir_len}"),
            ByteRange::new(off, off + 4),
        )];
        children.extend(resource_blocks(data, off + 4, ir_end.min(data_len)));
        blocks.push(
            Block::node(
                "Image resources",
                ByteRange::new(off, ir_end.min(data_len)),
                children,
            )
            .expanded(),
        );
        off = ir_end;

        // Layer and mask information section.
        let Some(lm) = layer_and_mask_block(data, off, psb) else {
            return blocks;
        };
        blocks.push(lm.0);
        off = lm.1;

        // Image data section.
        if let Some(compression) = read_u16(data, off) {
            let mut children = vec![Block::leaf(
                format!("Compression: {}", compression_name(compression)),
                ByteRange::new(off, off + 2),
            )];
            if off + 2 < data_len {
                children.push(Block::leaf("Data", ByteRange::new(off + 2, data_len)));
            }
            blocks.push(
                Block::node("Image data", ByteRange::new(off, data_len), children).expanded(),
            );
        }

        blocks
    }
}

fn bytes(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn read_u8(data: &[u8], offset: u64) -> Option<u8> {
    bytes(data, offset, 1).map(|b| b[0])
}

fn read_u16(data: &[u8], offset: u64) -> Option<u16> {
    Some(u16::from_be_bytes(bytes(data, offset, 2)?.try_into().ok()?))
}

fn read_i16(data: &[u8], offset: u64) -> Option<i16> {
    read_u16(data, offset).map(|v| v as i16)
}

fn read_u32(data: &[u8], offset: u64) -> Option<u32> {
    Some(u32::from_be_bytes(bytes(data, offset, 4)?.try_into().ok()?))
}

fn read_i32(data: &[u8], offset: u64) -> Option<i32> {
    read_u32(data, offset).map(|v| v as i32)
}

fn read_u64(data: &[u8], offset: u64) -> Option<u64> {
    Some(u64::from_be_bytes(bytes(data, offset, 8)?.try_into().ok()?))
}

/// Reads a 4-byte length, or an 8-byte one when `long` is set (PSB).
fn read_len(data: &[u8], offset: u64, long: bool) -> Option<u64> {
    if long {
        read_u64(data, offset)
    } else {
        read_u32(data, offset).map(u64::from)
    }
}

fn round_up(value: u64, multiple: u64) -> u64 {
    value.saturating_add(multiple - 1) / multiple * multiple
}

fn truncate_label(s: &str) -> String {
    if s.chars().count() > MAX_LABEL_CHARS {
        let mut out: String = s.chars().take(MAX_LABEL_CHARS).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

/// Decodes a Pascal string (length byte + bytes) as Latin-1.
fn pascal_string(data: &[u8], offset: u64) -> Option<String> {
    let len = read_u8(data, offset)? as usize;
    let raw = bytes(data, offset + 1, len)?;
    Some(raw.iter().map(|&b| b as char).collect())
}

fn color_mode_name(mode: u16) -> String {
    match mode {
        0 => "Bitmap".to_string(),
        1 => "Grayscale".to_string(),
        2 => "Indexed".to_string(),
        3 => "RGB".to_string(),
        4 => "CMYK".to_string(),
        7 => "Multichannel".to_string(),
        8 => "Duotone".to_string(),
        9 => "Lab".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn compression_name(value: u16) -> String {
    match value {
        0 => "Raw".to_string(),
        1 => "RLE".to_string(),
        2 => "ZIP".to_string(),
        3 => "ZIP with prediction".to_string(),
        n => format!("unknown ({n})"),
    }
}

fn resource_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1000 => "Channels/rows/columns/depth/mode",
        1001 => "Macintosh print manager info",
        1002 => "Macintosh page format info",
        1003 => "Indexed color table",
        1005 => "ResolutionInfo",
        1006 => "Alpha channel names",
        1007 => "DisplayInfo (obsolete)",
        1008 => "Caption",
        1009 => "Border information",
        1010 => "Background color",
        1011 => "Print flags",
        1012 => "Grayscale/multichannel halftoning",
        1013 => "Color halftoning",
        1014 => "Duotone halftoning",
        1015 => "Grayscale/multichannel transfer",
        1016 => "Color transfer",
        1017 => "Duotone transfer",
        1018 => "Duotone image information",
        1019 => "Effective black and white values",
        1021 => "EPS options",
        1022 => "Quick Mask information",
        1024 => "Layer state",
        1025 => "Working path",
        1026 => "Layer groups",
        1028 => "IPTC-NAA record",
        1029 => "Raw image mode",
        1030 => "JPEG quality",
        1032 => "Grid and guides",
        1033 => "Thumbnail (Photoshop 4.0)",
        1034 => "Copyright flag",
        1035 => "URL",
        1036 => "Thumbnail",
        1037 => "Global angle",
        1038 => "Color samplers (obsolete)",
        1039 => "ICC profile",
        1040 => "Watermark",
        1041 => "ICC untagged profile",
        1042 => "Effects visible",
        1043 => "Spot halftone",
        1044 => "Document ID seed",
        1045 => "Unicode alpha names",
        1046 => "Indexed color table count",
        1047 => "Transparency index",
        1049 => "Global altitude",
        1050 => "Slices",
        1051 => "Workflow URL",
        1052 => "Jump to XPEP",
        1053 => "Alpha identifiers",
        1054 => "URL list",
        1057 => "Version info",
        1058 => "EXIF data 1",
        1059 => "EXIF data 3",
        1060 => "XMP metadata",
        1061 => "Caption digest",
        1062 => "Print scale",
        1064 => "Pixel aspect ratio",
        1065 => "Layer comps",
        1066 => "Alternate duotone colors",
        1067 => "Alternate spot colors",
        1069 => "Layer selection IDs",
        1070 => "HDR toning information",
        1071 => "Print info",
        1072 => "Layer group(s) enabled ID",
        1073 => "Color samplers",
        1074 => "Measurement scale",
        1075 => "Timeline information",
        1076 => "Sheet disclosure",
        1077 => "DisplayInfo",
        1078 => "Onion skins",
        1080 => "Count information",
        1082 => "Print information",
        1083 => "Print style",
        1084 => "Macintosh NSPrintInfo",
        1085 => "Windows DEVMODE",
        1086 => "Auto save file path",
        1087 => "Auto save format",
        1088 => "Path selection state",
        2000..=2997 => "Path information",
        2999 => "Clipping path name",
        3000 => "Origin path info",
        4000..=4999 => "Plug-in resource",
        7000 => "Image Ready variables",
        7001 => "Image Ready data sets",
        7002 => "Image Ready default selected state",
        7003 => "Image Ready 7 rollover expanded state",
        7004 => "Image Ready rollover expanded state",
        7005 => "Image Ready save layer settings",
        7006 => "Image Ready version",
        8000 => "Lightroom workflow",
        10000 => "Print flags information",
        _ => return None,
    })
}

fn blend_mode_name(key: &[u8]) -> Option<&'static str> {
    Some(match key {
        b"pass" => "Pass through",
        b"norm" => "Normal",
        b"diss" => "Dissolve",
        b"dark" => "Darken",
        b"mul " => "Multiply",
        b"idiv" => "Color burn",
        b"lbrn" => "Linear burn",
        b"dkCl" => "Darker color",
        b"lite" => "Lighten",
        b"scrn" => "Screen",
        b"div " => "Color dodge",
        b"lddg" => "Linear dodge",
        b"lgCl" => "Lighter color",
        b"over" => "Overlay",
        b"sLit" => "Soft light",
        b"hLit" => "Hard light",
        b"vLit" => "Vivid light",
        b"lLit" => "Linear light",
        b"pLit" => "Pin light",
        b"hMix" => "Hard mix",
        b"diff" => "Difference",
        b"smud" => "Exclusion",
        b"fsub" => "Subtract",
        b"fdiv" => "Divide",
        b"hue " => "Hue",
        b"sat " => "Saturation",
        b"colr" => "Color",
        b"lum " => "Luminosity",
        _ => return None,
    })
}

fn tagged_block_name(key: &[u8]) -> Option<&'static str> {
    Some(match key {
        b"luni" => "Unicode layer name",
        b"lyid" => "Layer ID",
        b"lsct" | b"lsdk" => "Section divider",
        b"lnsr" => "Layer name source",
        b"clbl" => "Blend clipping elements",
        b"infx" => "Blend interior elements",
        b"knko" => "Knockout",
        b"lspf" => "Protected setting",
        b"lclr" => "Sheet color",
        b"fxrp" => "Reference point",
        b"shmd" => "Metadata setting",
        b"lfx2" => "Object-based effects",
        b"lrFX" => "Effects layer",
        b"iOpa" => "Fill opacity",
        b"brst" => "Channel blending restrictions",
        b"vmsk" | b"vsms" => "Vector mask",
        b"vscg" => "Vector stroke content",
        b"vstk" => "Vector stroke",
        b"vogk" => "Vector origination data",
        b"TySh" => "Type tool object",
        b"tySh" => "Type tool info",
        b"Txt2" => "Text engine data",
        b"SoLd" | b"SoLE" => "Placed layer data",
        b"PlLd" | b"plLd" => "Placed layer",
        b"lnk2" | b"lnkD" | b"lnk3" => "Linked layer",
        b"Patt" | b"Pat2" | b"Pat3" => "Patterns",
        b"Lr16" => "16-bit layer data",
        b"Lr32" => "32-bit layer data",
        b"Layr" => "Layer data",
        b"Mt16" | b"Mt32" | b"Mtrn" => "Saved transparency",
        b"Alph" => "Alpha channel data",
        b"FMsk" => "Filter mask",
        b"LMsk" => "User mask",
        b"FXid" | b"FEid" => "Filter effects",
        b"PxSD" => "Pixel source data",
        b"Anno" => "Annotations",
        b"cinf" => "Compositor info",
        b"artb" | b"artd" | b"abdd" => "Artboard data",
        b"lmgm" => "Layer mask as global mask",
        b"sn2P" => "Using aligned rendering",
        b"CgEd" => "Content generator extra data",
        b"SoCo" => "Solid color fill",
        b"GdFl" => "Gradient fill",
        b"PtFl" => "Pattern fill",
        b"brit" => "Brightness/contrast",
        b"levl" => "Levels",
        b"curv" => "Curves",
        b"expA" => "Exposure",
        b"vibA" => "Vibrance",
        b"hue " | b"hue2" => "Hue/saturation",
        b"blnc" => "Color balance",
        b"blwh" => "Black and white",
        b"phfl" => "Photo filter",
        b"mixr" => "Channel mixer",
        b"clrL" => "Color lookup",
        b"nvrt" => "Invert",
        b"post" => "Posterize",
        b"thrs" => "Threshold",
        b"grdm" => "Gradient map",
        b"selc" => "Selective color",
        _ => return None,
    })
}

fn channel_id_name(id: i16) -> String {
    match id {
        -1 => "Channel -1 (transparency mask)".to_string(),
        -2 => "Channel -2 (user layer mask)".to_string(),
        -3 => "Channel -3 (real user layer mask)".to_string(),
        n => format!("Channel {n}"),
    }
}

fn header_block(data: &[u8], psb: bool) -> Block {
    let version = read_u16(data, 4).unwrap_or(0);
    let channels = read_u16(data, 12).unwrap_or(0);
    let height = read_u32(data, 14).unwrap_or(0);
    let width = read_u32(data, 18).unwrap_or(0);
    let depth = read_u16(data, 22).unwrap_or(0);
    let mode = read_u16(data, 24).unwrap_or(0);
    let kind = if psb { "PSB" } else { "PSD" };
    Block::node(
        "File header",
        ByteRange::new(0, HEADER_LEN),
        vec![
            Block::leaf("Signature: 8BPS", ByteRange::new(0, 4)),
            Block::leaf(format!("Version: {version} ({kind})"), ByteRange::new(4, 6)),
            Block::leaf("Reserved", ByteRange::new(6, 12)),
            Block::leaf(format!("Channels: {channels}"), ByteRange::new(12, 14)),
            Block::leaf(format!("Height: {height}"), ByteRange::new(14, 18)),
            Block::leaf(format!("Width: {width}"), ByteRange::new(18, 22)),
            Block::leaf(format!("Depth: {depth}"), ByteRange::new(22, 24)),
            Block::leaf(
                format!("Color mode: {}", color_mode_name(mode)),
                ByteRange::new(24, 26),
            ),
        ],
    )
    .expanded()
}

fn resource_blocks(data: &[u8], start: u64, end: u64) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut pos = start;
    // Minimum resource: signature + ID + empty padded name + size.
    while pos + 12 <= end {
        let sig = bytes(data, pos, 4).unwrap_or_default();
        if !RESOURCE_SIGNATURES.contains(&sig) {
            blocks.push(Block::leaf("Unknown data", ByteRange::new(pos, end)));
            return blocks;
        }
        let sig_str = String::from_utf8_lossy(sig).into_owned();
        let Some(id) = read_u16(data, pos + 4) else {
            break;
        };
        let Some(name) = pascal_string(data, pos + 6) else {
            break;
        };
        let name_field_len = round_up(1 + name.len() as u64, 2);
        let size_off = pos + 6 + name_field_len;
        if size_off + 4 > end {
            blocks.push(Block::leaf("Truncated resource", ByteRange::new(pos, end)));
            return blocks;
        }
        let Some(size) = read_u32(data, size_off) else {
            break;
        };
        let size = size as u64;
        let data_off = size_off + 4;
        let next = data_off.saturating_add(round_up(size, 2));
        let block_end = next.min(end);

        let id_label = match resource_name(id) {
            Some(n) => format!("{id} ({n})"),
            None => id.to_string(),
        };
        let mut children = vec![
            Block::leaf(
                format!("Signature: {sig_str}"),
                ByteRange::new(pos, pos + 4),
            ),
            Block::leaf(format!("ID: {id_label}"), ByteRange::new(pos + 4, pos + 6)),
            Block::leaf(
                format!("Name: \"{}\"", truncate_label(&name)),
                ByteRange::new(pos + 6, size_off),
            ),
            Block::leaf(format!("Size: {size}"), ByteRange::new(size_off, data_off)),
        ];
        if size > 0 && data_off < end {
            children.push(Block::leaf(
                "Data",
                ByteRange::new(data_off, data_off.saturating_add(size).min(end)),
            ));
        }
        let label = if name.is_empty() {
            format!("Resource {id_label}")
        } else {
            format!("Resource {id_label} \"{}\"", truncate_label(&name))
        };
        blocks.push(Block::node(label, ByteRange::new(pos, block_end), children));
        pos = next;
    }
    if pos < end {
        blocks.push(Block::leaf("Padding", ByteRange::new(pos, end)));
    }
    blocks
}

/// Parses "Additional layer information" tagged blocks in `start..end`.
fn tagged_blocks(data: &[u8], start: u64, end: u64, psb: bool) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut pos = start;
    while pos + 12 <= end {
        let sig = bytes(data, pos, 4).unwrap_or_default();
        if sig != b"8BIM" && sig != b"8B64" {
            blocks.push(Block::leaf("Unknown data", ByteRange::new(pos, end)));
            return blocks;
        }
        let key = bytes(data, pos + 4, 4).unwrap_or_default();
        let key_str = String::from_utf8_lossy(key).into_owned();
        let long = psb && PSB_LONG_KEYS.contains(&key);
        let len_width = if long { 8 } else { 4 };
        let len_off = pos + 8;
        if len_off + len_width > end {
            blocks.push(Block::leaf("Truncated block", ByteRange::new(pos, end)));
            return blocks;
        }
        let Some(len) = read_len(data, len_off, long) else {
            break;
        };
        let data_off = len_off + len_width;
        let next = data_off.saturating_add(round_up(len, 2));
        let mut children = vec![
            Block::leaf(
                format!("Signature: {}", String::from_utf8_lossy(sig)),
                ByteRange::new(pos, pos + 4),
            ),
            Block::leaf(format!("Key: {key_str}"), ByteRange::new(pos + 4, pos + 8)),
            Block::leaf(format!("Length: {len}"), ByteRange::new(len_off, data_off)),
        ];
        if len > 0 && data_off < end {
            let data_end = data_off.saturating_add(len).min(end);
            let label = if key == b"luni" {
                unicode_string(data, data_off, data_end)
                    .map(|s| format!("Name: \"{}\"", truncate_label(&s)))
                    .unwrap_or_else(|| "Data".to_string())
            } else if key == b"lyid" && len >= 4 {
                format!("Layer ID: {}", read_u32(data, data_off).unwrap_or(0))
            } else {
                "Data".to_string()
            };
            children.push(Block::leaf(label, ByteRange::new(data_off, data_end)));
        }
        let label = match tagged_block_name(key) {
            Some(n) => format!("{key_str} ({n})"),
            None => key_str,
        };
        blocks.push(Block::node(
            label,
            ByteRange::new(pos, next.min(end)),
            children,
        ));
        pos = next;
    }
    if pos < end {
        blocks.push(Block::leaf("Padding", ByteRange::new(pos, end)));
    }
    blocks
}

/// Decodes a Photoshop Unicode string (u32 char count + UTF-16BE).
fn unicode_string(data: &[u8], start: u64, end: u64) -> Option<String> {
    let count = read_u32(data, start)? as u64;
    let byte_len = count.checked_mul(2)?;
    if start + 4 + byte_len > end {
        return None;
    }
    let raw = bytes(data, start + 4, usize::try_from(byte_len).ok()?)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    Some(s.trim_end_matches('\0').to_string())
}

struct LayerRecord {
    block: Block,
    end: u64,
    name: String,
    channels: Vec<(i16, u64)>,
}

fn layer_record(
    data: &[u8],
    start: u64,
    limit: u64,
    index: usize,
    psb: bool,
) -> Option<LayerRecord> {
    let len_width: u64 = if psb { 8 } else { 4 };
    if start + 18 > limit {
        return None;
    }
    let top = read_i32(data, start)?;
    let left = read_i32(data, start + 4)?;
    let bottom = read_i32(data, start + 8)?;
    let right = read_i32(data, start + 12)?;
    let channel_count = read_u16(data, start + 16)? as u64;

    let mut children = vec![Block::node(
        format!("Bounds: top {top}, left {left}, bottom {bottom}, right {right}"),
        ByteRange::new(start, start + 16),
        vec![
            Block::leaf(format!("Top: {top}"), ByteRange::new(start, start + 4)),
            Block::leaf(
                format!("Left: {left}"),
                ByteRange::new(start + 4, start + 8),
            ),
            Block::leaf(
                format!("Bottom: {bottom}"),
                ByteRange::new(start + 8, start + 12),
            ),
            Block::leaf(
                format!("Right: {right}"),
                ByteRange::new(start + 12, start + 16),
            ),
        ],
    )];
    children.push(Block::leaf(
        format!("Channels: {channel_count}"),
        ByteRange::new(start + 16, start + 18),
    ));

    let entry_len = 2 + len_width;
    let info_start = start + 18;
    let info_end = info_start + channel_count * entry_len;
    if info_end + 16 > limit {
        return None;
    }
    let mut channels = Vec::new();
    let mut channel_blocks = Vec::new();
    for i in 0..channel_count {
        let p = info_start + i * entry_len;
        let id = read_i16(data, p)?;
        let len = read_len(data, p + 2, psb)?;
        channels.push((id, len));
        channel_blocks.push(Block::leaf(
            format!("{}: {len} bytes", channel_id_name(id)),
            ByteRange::new(p, p + entry_len),
        ));
    }
    children.push(Block::node(
        "Channel information",
        ByteRange::new(info_start, info_end),
        channel_blocks,
    ));

    let p = info_end;
    let blend_sig = bytes(data, p, 4)?;
    let blend_key = bytes(data, p + 4, 4)?;
    let opacity = read_u8(data, p + 8)?;
    let clipping = read_u8(data, p + 9)?;
    let flags = read_u8(data, p + 10)?;
    let extra_len = read_u32(data, p + 12)? as u64;

    children.push(Block::leaf(
        format!(
            "Blend mode signature: {}",
            String::from_utf8_lossy(blend_sig)
        ),
        ByteRange::new(p, p + 4),
    ));
    let key_str = String::from_utf8_lossy(blend_key).into_owned();
    let blend_label = match blend_mode_name(blend_key) {
        Some(n) => format!("Blend mode: {n} ({key_str})"),
        None => format!("Blend mode: {key_str}"),
    };
    children.push(Block::leaf(blend_label, ByteRange::new(p + 4, p + 8)));
    children.push(Block::leaf(
        format!("Opacity: {opacity}"),
        ByteRange::new(p + 8, p + 9),
    ));
    children.push(Block::leaf(
        format!(
            "Clipping: {}",
            if clipping == 0 { "Base" } else { "Non-base" }
        ),
        ByteRange::new(p + 9, p + 10),
    ));
    let mut flag_names = Vec::new();
    if flags & 0x01 != 0 {
        flag_names.push("transparency protected");
    }
    flag_names.push(if flags & 0x02 != 0 {
        "hidden"
    } else {
        "visible"
    });
    if flags & 0x18 == 0x18 {
        flag_names.push("pixel data irrelevant");
    }
    children.push(Block::leaf(
        format!("Flags: 0x{flags:02X} ({})", flag_names.join(", ")),
        ByteRange::new(p + 10, p + 11),
    ));
    children.push(Block::leaf("Filler", ByteRange::new(p + 11, p + 12)));
    children.push(Block::leaf(
        format!("Extra data length: {extra_len}"),
        ByteRange::new(p + 12, p + 16),
    ));

    let extra_start = p + 16;
    let extra_end = extra_start.saturating_add(extra_len).min(limit);
    let mut name = String::new();
    if extra_len > 0 {
        let mut extra = Vec::new();
        let mut q = extra_start;
        for label in ["Layer mask data", "Layer blending ranges"] {
            if q + 4 > extra_end {
                break;
            }
            let len = read_u32(data, q)? as u64;
            let end = (q + 4).saturating_add(len).min(extra_end);
            extra.push(Block::node(
                format!("{label} ({len} bytes)"),
                ByteRange::new(q, end),
                vec![Block::leaf(
                    format!("Length: {len}"),
                    ByteRange::new(q, q + 4),
                )],
            ));
            q = (q + 4).saturating_add(len);
        }
        if q < extra_end {
            if let Some(n) = pascal_string(data, q) {
                let field_end = (q + round_up(1 + n.len() as u64, 4)).min(extra_end);
                extra.push(Block::leaf(
                    format!("Layer name: \"{}\"", truncate_label(&n)),
                    ByteRange::new(q, field_end),
                ));
                name = n;
                q = field_end;
            }
        }
        if q < extra_end {
            let tagged = tagged_blocks(data, q, extra_end, psb);
            // A Unicode name, if present, is more accurate than the Pascal one.
            for b in &tagged {
                if b.label.starts_with("luni") {
                    if let Some(n) = b.children.iter().find_map(|c| {
                        c.label
                            .strip_prefix("Name: \"")
                            .and_then(|s| s.strip_suffix('"'))
                    }) {
                        name = n.to_string();
                    }
                }
            }
            extra.push(Block::node(
                "Additional layer information",
                ByteRange::new(q, extra_end),
                tagged,
            ));
        }
        children.push(Block::node(
            "Extra data",
            ByteRange::new(extra_start, extra_end),
            extra,
        ));
    }

    let end = extra_start.saturating_add(extra_len);
    let label = if name.is_empty() {
        format!("Layer {index}")
    } else {
        format!("Layer {index}: \"{}\"", truncate_label(&name))
    };
    Some(LayerRecord {
        block: Block::node(label, ByteRange::new(start, end.min(limit)), children),
        end,
        name,
        channels,
    })
}

/// Returns the layer and mask section block and the offset just past it.
fn layer_and_mask_block(data: &[u8], off: u64, psb: bool) -> Option<(Block, u64)> {
    let data_len = data.len() as u64;
    let len_width: u64 = if psb { 8 } else { 4 };
    let lm_len = read_len(data, off, psb)?;
    let body = off + len_width;
    let lm_end_raw = body.saturating_add(lm_len);
    let lm_end = lm_end_raw.min(data_len);

    let mut children = vec![Block::leaf(
        format!("Length: {lm_len}"),
        ByteRange::new(off, body),
    )];

    if lm_len > 0 {
        if let Some(li_len) = read_len(data, body, psb).filter(|_| body + len_width <= lm_end) {
            let li_body = body + len_width;
            let li_end_raw = li_body.saturating_add(li_len);
            let li_end = li_end_raw.min(lm_end);
            children.push(layer_info_block(data, body, li_body, li_end, li_len, psb));

            // Global layer mask info.
            let mut pos = li_end_raw;
            if pos + 4 <= lm_end {
                let gm_len = read_u32(data, pos)? as u64;
                let gm_end = (pos + 4).saturating_add(gm_len);
                let mut gm_children = vec![Block::leaf(
                    format!("Length: {gm_len}"),
                    ByteRange::new(pos, pos + 4),
                )];
                if gm_len > 0 && pos + 4 < lm_end {
                    gm_children.push(Block::leaf(
                        "Data",
                        ByteRange::new(pos + 4, gm_end.min(lm_end)),
                    ));
                }
                children.push(Block::node(
                    "Global layer mask info",
                    ByteRange::new(pos, gm_end.min(lm_end)),
                    gm_children,
                ));
                pos = gm_end;
            }
            if pos < lm_end {
                children.push(Block::node(
                    "Additional layer information",
                    ByteRange::new(pos, lm_end),
                    tagged_blocks(data, pos, lm_end, psb),
                ));
            }
        }
    }

    Some((
        Block::node(
            "Layer and mask information",
            ByteRange::new(off, lm_end),
            children,
        )
        .expanded(),
        lm_end_raw,
    ))
}

fn layer_info_block(data: &[u8], start: u64, body: u64, end: u64, len: u64, psb: bool) -> Block {
    let mut children = vec![Block::leaf(
        format!("Length: {len}"),
        ByteRange::new(start, body),
    )];
    if len == 0 {
        return Block::node("Layer info", ByteRange::new(start, end), children);
    }
    let Some(count) = read_i16(data, body).filter(|_| body + 2 <= end) else {
        return Block::node("Layer info", ByteRange::new(start, end), children);
    };
    let count_label = if count < 0 {
        format!("Layer count: {count} (first alpha channel is merged transparency)")
    } else {
        format!("Layer count: {count}")
    };
    children.push(Block::leaf(count_label, ByteRange::new(body, body + 2)));

    let layer_count = count.unsigned_abs() as usize;
    let mut records = Vec::new();
    let mut pos = body + 2;
    for i in 0..layer_count {
        match layer_record(data, pos, end, i, psb) {
            Some(r) => {
                pos = r.end;
                records.push(r);
            }
            None => break,
        }
    }
    let records_start = body + 2;
    if !records.is_empty() {
        let records_end = pos.min(end);
        let mut channel_data = Vec::new();
        let mut cpos = pos;
        for (i, r) in records.iter().enumerate() {
            if cpos >= end {
                break;
            }
            let layer_start = cpos;
            let mut layer_channels = Vec::new();
            for &(id, clen) in &r.channels {
                if cpos >= end {
                    break;
                }
                let cend = cpos.saturating_add(clen).min(end);
                let compression = if clen >= 2 {
                    read_u16(data, cpos).map(compression_name)
                } else {
                    None
                };
                let label = match compression {
                    Some(c) => format!("{}: {c}, {clen} bytes", channel_id_name(id)),
                    None => format!("{}: {clen} bytes", channel_id_name(id)),
                };
                layer_channels.push(Block::leaf(label, ByteRange::new(cpos, cend)));
                cpos = cpos.saturating_add(clen);
            }
            let label = if r.name.is_empty() {
                format!("Layer {i}")
            } else {
                format!("Layer {i}: \"{}\"", truncate_label(&r.name))
            };
            channel_data.push(Block::node(
                label,
                ByteRange::new(layer_start, cpos.min(end)),
                layer_channels,
            ));
        }
        children.push(
            Block::node(
                "Layer records",
                ByteRange::new(records_start, records_end),
                records.into_iter().map(|r| r.block).collect(),
            )
            .expanded(),
        );
        if records_end < end {
            children.push(Block::node(
                "Channel image data",
                ByteRange::new(records_end, cpos.min(end)),
                channel_data,
            ));
        }
        if cpos < end {
            children.push(Block::leaf("Padding", ByteRange::new(cpos, end)));
        }
    } else if records_start < end {
        children.push(Block::leaf(
            "Layer records (unparsed)",
            ByteRange::new(records_start, end),
        ));
    }
    Block::node("Layer info", ByteRange::new(start, end), children).expanded()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLayer {
        name: &'static str,
        /// (channel id, channel image data including the 2-byte compression)
        channels: Vec<(i16, Vec<u8>)>,
        tagged: Vec<u8>,
    }

    fn push_len(buf: &mut Vec<u8>, len: u64, psb: bool) {
        if psb {
            buf.extend_from_slice(&len.to_be_bytes());
        } else {
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }

    fn build_resource(id: u16, name: &str, payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"8BIM");
        r.extend_from_slice(&id.to_be_bytes());
        r.push(name.len() as u8);
        r.extend_from_slice(name.as_bytes());
        if (1 + name.len()) % 2 == 1 {
            r.push(0);
        }
        r.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        r.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            r.push(0);
        }
        r
    }

    fn build_layer_info(layers: &[TestLayer], psb: bool) -> Vec<u8> {
        let mut li = Vec::new();
        li.extend_from_slice(&(layers.len() as i16).to_be_bytes());
        for layer in layers {
            for v in [0i32, 0, 2, 3] {
                li.extend_from_slice(&v.to_be_bytes());
            }
            li.extend_from_slice(&(layer.channels.len() as u16).to_be_bytes());
            for (id, payload) in &layer.channels {
                li.extend_from_slice(&id.to_be_bytes());
                push_len(&mut li, payload.len() as u64, psb);
            }
            li.extend_from_slice(b"8BIM");
            li.extend_from_slice(b"mul ");
            li.extend_from_slice(&[200, 0, 0x02, 0]);
            let mut extra = Vec::new();
            extra.extend_from_slice(&0u32.to_be_bytes()); // mask data
            extra.extend_from_slice(&0u32.to_be_bytes()); // blending ranges
            extra.push(layer.name.len() as u8);
            extra.extend_from_slice(layer.name.as_bytes());
            while extra.len() % 4 != 0 {
                extra.push(0);
            }
            extra.extend_from_slice(&layer.tagged);
            li.extend_from_slice(&(extra.len() as u32).to_be_bytes());
            li.extend_from_slice(&extra);
        }
        for layer in layers {
            for (_, payload) in &layer.channels {
                li.extend_from_slice(payload);
            }
        }
        li
    }

    fn build_psd(psb: bool, resources: &[u8], layers: &[TestLayer], image: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"8BPS");
        d.extend_from_slice(&(if psb { 2u16 } else { 1u16 }).to_be_bytes());
        d.extend_from_slice(&[0; 6]);
        d.extend_from_slice(&3u16.to_be_bytes()); // channels
        d.extend_from_slice(&3u32.to_be_bytes()); // height
        d.extend_from_slice(&2u32.to_be_bytes()); // width
        d.extend_from_slice(&8u16.to_be_bytes()); // depth
        d.extend_from_slice(&3u16.to_be_bytes()); // RGB
        d.extend_from_slice(&0u32.to_be_bytes()); // color mode data
        d.extend_from_slice(&(resources.len() as u32).to_be_bytes());
        d.extend_from_slice(resources);

        let mut lm = Vec::new();
        if !layers.is_empty() {
            let li = build_layer_info(layers, psb);
            push_len(&mut lm, li.len() as u64, psb);
            lm.extend_from_slice(&li);
            lm.extend_from_slice(&0u32.to_be_bytes()); // global mask
        }
        push_len(&mut d, lm.len() as u64, psb);
        d.extend_from_slice(&lm);
        d.extend_from_slice(image);
        d
    }

    fn sample(psb: bool) -> Vec<u8> {
        let resources = build_resource(1005, "", &[0u8; 16]);
        let mut tagged = Vec::new();
        tagged.extend_from_slice(b"8BIM");
        tagged.extend_from_slice(b"lyid");
        tagged.extend_from_slice(&4u32.to_be_bytes());
        tagged.extend_from_slice(&7u32.to_be_bytes());
        let layers = [TestLayer {
            name: "Bg",
            channels: vec![(0, vec![0, 0, 1, 2, 3, 4, 5, 6]), (-1, vec![0, 1, 9, 9])],
            tagged,
        }];
        build_psd(psb, &resources, &layers, &[0, 1, 0xAA, 0xBB])
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn assert_nested(blocks: &[Block], parent: ByteRange) {
        for b in blocks {
            assert!(b.range.start <= b.range.end, "{}", b.label);
            assert!(
                b.range.start >= parent.start && b.range.end <= parent.end,
                "{} {:?} outside {:?}",
                b.label,
                b.range,
                parent
            );
            assert_nested(&b.children, b.range);
        }
    }

    #[test]
    fn matches_psd_and_psb() {
        assert!(PsdDissector.matches(&sample(false)));
        assert!(PsdDissector.matches(&sample(true)));
    }

    #[test]
    fn does_not_match_non_psd_data() {
        assert!(!PsdDissector.matches(b""));
        assert!(!PsdDissector.matches(b"not a psd file"));
        assert!(!PsdDissector.matches(b"8BPS"));
        assert!(!PsdDissector.matches(b"8BPS\x00\x03rest"));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = sample(false);
        assert!(PsdDissector.dissect(&data[..10]).is_empty());
        for len in 0..data.len() {
            let blocks = PsdDissector.dissect(&data[..len]);
            assert_nested(&blocks, ByteRange::new(0, len as u64));
        }
        let full = PsdDissector.dissect(&data);
        assert!(PsdDissector.dissect(&data[..30]).len() < full.len());
    }

    #[test]
    fn dissect_parses_header() {
        let data = sample(false);
        let blocks = PsdDissector.dissect(&data);
        let header = find_block(&blocks, "File header");
        assert_eq!(header.range, ByteRange::new(0, 26));
        for label in [
            "Signature: 8BPS",
            "Version: 1 (PSD)",
            "Channels: 3",
            "Height: 3",
            "Width: 2",
            "Depth: 8",
            "Color mode: RGB",
        ] {
            find_block(&header.children, label);
        }
        let cm = find_block(&blocks, "Color mode data");
        assert_eq!(cm.range, ByteRange::new(26, 30));
    }

    #[test]
    fn dissect_parses_image_resources() {
        let data = sample(false);
        let blocks = PsdDissector.dissect(&data);
        let ir = find_block(&blocks, "Image resources");
        // 4-byte length + 4 sig + 2 id + 2 name + 4 size + 16 data
        assert_eq!(ir.range, ByteRange::new(30, 62));
        let res = find_block(&ir.children, "Resource 1005 (ResolutionInfo)");
        assert_eq!(res.range, ByteRange::new(34, 62));
        assert_eq!(
            find_block(&res.children, "Data").range,
            ByteRange::new(46, 62)
        );
        find_block(&res.children, "Name: \"\"");
    }

    #[test]
    fn dissect_parses_layers_and_image_data() {
        let data = sample(false);
        let blocks = PsdDissector.dissect(&data);
        let lm = find_block(&blocks, "Layer and mask information");
        assert_eq!(lm.range.start, 62);
        let li = find_block(&lm.children, "Layer info");
        find_block(&li.children, "Layer count: 1");
        let records = find_block(&li.children, "Layer records");
        let layer = find_block(&records.children, "Layer 0: \"Bg\"");
        find_block(&layer.children, "Bounds: top 0, left 0, bottom 2, right 3");
        find_block(&layer.children, "Blend mode: Multiply (mul )");
        find_block(&layer.children, "Opacity: 200");
        find_block(&layer.children, "Flags: 0x02 (hidden)");
        let ci = find_block(&layer.children, "Channel information");
        find_block(&ci.children, "Channel 0: 8 bytes");
        find_block(&ci.children, "Channel -1 (transparency mask): 4 bytes");
        let extra = find_block(&layer.children, "Extra data");
        find_block(&extra.children, "Layer name: \"Bg\"");
        let ali = find_block(&extra.children, "Additional layer information");
        let lyid = find_block(&ali.children, "lyid (Layer ID)");
        find_block(&lyid.children, "Layer ID: 7");

        let cd = find_block(&li.children, "Channel image data");
        let lc = find_block(&cd.children, "Layer 0: \"Bg\"");
        let c0 = find_block(&lc.children, "Channel 0: Raw, 8 bytes");
        let c1 = find_block(&lc.children, "Channel -1 (transparency mask): RLE, 4 bytes");
        assert_eq!(c0.range.end, c1.range.start);
        assert_eq!(c1.range.end, li.range.end);
        let gm = find_block(&lm.children, "Global layer mask info");
        assert_eq!(gm.range, ByteRange::new(li.range.end, li.range.end + 4));
        assert_eq!(lm.range.end, gm.range.end);

        let img = find_block(&blocks, "Image data");
        let len = data.len() as u64;
        assert_eq!(img.range, ByteRange::new(len - 4, len));
        find_block(&img.children, "Compression: RLE");
        assert_eq!(
            find_block(&img.children, "Data").range,
            ByteRange::new(len - 2, len)
        );
        assert_nested(&blocks, ByteRange::new(0, len));
    }

    #[test]
    fn dissect_psb_uses_long_lengths() {
        let data = sample(true);
        let blocks = PsdDissector.dissect(&data);
        let header = find_block(&blocks, "File header");
        find_block(&header.children, "Version: 2 (PSB)");
        let lm = find_block(&blocks, "Layer and mask information");
        assert_eq!(
            find_block(
                &lm.children,
                &format!("Length: {}", lm.range.end - lm.range.start - 8)
            )
            .range,
            ByteRange::new(62, 70)
        );
        let li = find_block(&lm.children, "Layer info");
        let records = find_block(&li.children, "Layer records");
        let layer = find_block(&records.children, "Layer 0: \"Bg\"");
        let ci = find_block(&layer.children, "Channel information");
        let c0 = find_block(&ci.children, "Channel 0: 8 bytes");
        assert_eq!(c0.range.end - c0.range.start, 10);
        let img = find_block(&blocks, "Image data");
        find_block(&img.children, "Compression: RLE");
        assert_nested(&blocks, ByteRange::new(0, data.len() as u64));
    }

    #[test]
    fn dissect_without_layers() {
        let data = build_psd(false, &[], &[], &[0, 2, 1, 2, 3]);
        let blocks = PsdDissector.dissect(&data);
        let lm = find_block(&blocks, "Layer and mask information");
        assert_eq!(lm.range, ByteRange::new(34, 38));
        let img = find_block(&blocks, "Image data");
        find_block(&img.children, "Compression: ZIP");
    }

    #[test]
    fn identify_reports_psd() {
        assert_eq!(super::super::identify(&sample(false)), "PSD");
        assert_eq!(super::super::identify(&sample(true)), "PSD");
    }
}
