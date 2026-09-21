use super::{Block, ByteRange, Dissector};

const CONTAINER_TYPES: &[&str] = &[
    "moov", "trak", "mdia", "minf", "stbl", "udta", "edts", "dinf", "mvex", "moof", "traf",
    "mfra", "meco", "sinf", "schi", "ipro", "strk", "strd",
];

pub struct Mp4Dissector;

impl Dissector for Mp4Dissector {
    fn name(&self) -> &'static str {
        "MP4"
    }

    fn matches(&self, data: &[u8]) -> bool {
        parse_box_header(data, 0)
            .map(|(header, _)| header.box_type == "ftyp")
            .unwrap_or(false)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        boxes_in_range(data, 0, data.len() as u64)
    }
}

struct BoxHeader {
    box_type: String,
    header_len: u64,
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn fourcc_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Parses a box header at `offset`, returning the box's type and header
/// length (including any extended size/uuid fields), along with the
/// absolute end offset of the whole box (clamped to the available data).
fn parse_box_header(data: &[u8], offset: u64) -> Option<(BoxHeader, u64)> {
    let off = offset as usize;
    if data.len() < off + 8 {
        return None;
    }
    let size32 = read_u32(data, off)?;
    let box_type = fourcc_string(&data[off + 4..off + 8]);

    let mut header_len = 8u64;
    let box_size: u64 = if size32 == 1 {
        if data.len() < off + 16 {
            return None;
        }
        header_len = 16;
        read_u64(data, off + 8)?
    } else if size32 == 0 {
        data.len() as u64 - offset
    } else {
        size32 as u64
    };

    if box_type == "uuid" {
        if (data.len() as u64) < offset + header_len + 16 {
            return None;
        }
        header_len += 16;
    }

    if box_size < header_len {
        return None;
    }

    let end = (offset + box_size).min(data.len() as u64);
    Some((BoxHeader { box_type, header_len }, end))
}

fn boxes_in_range(data: &[u8], start: u64, end: u64) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut offset = start;

    while offset + 8 <= end {
        let Some((header, box_end)) = parse_box_header(data, offset) else {
            break;
        };
        let box_end = box_end.min(end);
        if box_end <= offset {
            break;
        }
        blocks.push(box_block(data, offset, header, box_end));
        offset = box_end;
    }

    blocks
}

fn friendly_name(box_type: &str) -> Option<&'static str> {
    Some(match box_type {
        "ftyp" => "File Type",
        "moov" => "Movie",
        "mdat" => "Media Data",
        "free" | "skip" => "Free Space",
        "wide" => "Reserved Space",
        "trak" => "Track",
        "mdia" => "Media",
        "minf" => "Media Information",
        "stbl" => "Sample Table",
        "udta" => "User Data",
        "edts" => "Edit",
        "elst" => "Edit List",
        "dinf" => "Data Information",
        "dref" => "Data Reference",
        "mvex" => "Movie Extends",
        "moof" => "Movie Fragment",
        "traf" => "Track Fragment",
        "mfra" => "Movie Fragment Random Access",
        "meta" => "Metadata",
        "hdlr" => "Handler Reference",
        "mvhd" => "Movie Header",
        "tkhd" => "Track Header",
        "mdhd" => "Media Header",
        "stsd" => "Sample Description",
        "stts" => "Decoding Time to Sample",
        "ctts" => "Composition Time to Sample",
        "stsc" => "Sample to Chunk",
        "stsz" => "Sample Sizes",
        "stz2" => "Compact Sample Sizes",
        "stco" => "Chunk Offset (32-bit)",
        "co64" => "Chunk Offset (64-bit)",
        "stss" => "Sync Sample",
        "smhd" => "Sound Media Header",
        "vmhd" => "Video Media Header",
        "nmhd" => "Null Media Header",
        "gmhd" => "Generic Media Header",
        "pnot" => "Preview",
        _ => return None,
    })
}

fn box_label(box_type: &str) -> String {
    match friendly_name(box_type) {
        Some(name) => format!("{box_type} ({name})"),
        None => box_type.to_string(),
    }
}

fn header_field_blocks(data: &[u8], offset: u64, header: &BoxHeader) -> Vec<Block> {
    let mut fields = Vec::new();
    let size32 = read_u32(data, offset as usize).unwrap_or(0);

    if size32 == 1 {
        fields.push(Block::leaf(
            "Size: 1 (extended size follows)",
            ByteRange::new(offset, offset + 4),
        ));
        fields.push(Block::leaf(
            format!("Type: {}", header.box_type),
            ByteRange::new(offset + 4, offset + 8),
        ));
        let large_size = read_u64(data, offset as usize + 8).unwrap_or(0);
        fields.push(Block::leaf(
            format!("Extended size: {large_size}"),
            ByteRange::new(offset + 8, offset + 16),
        ));
    } else {
        let size_label = if size32 == 0 {
            "Size: 0 (extends to end of file)".to_string()
        } else {
            format!("Size: {size32}")
        };
        fields.push(Block::leaf(size_label, ByteRange::new(offset, offset + 4)));
        fields.push(Block::leaf(
            format!("Type: {}", header.box_type),
            ByteRange::new(offset + 4, offset + 8),
        ));
    }

    if header.box_type == "uuid" {
        let ext_start = offset + header.header_len - 16;
        fields.push(Block::leaf(
            "Extended type (UUID)",
            ByteRange::new(ext_start, ext_start + 16),
        ));
    }

    fields
}

fn box_block(data: &[u8], offset: u64, header: BoxHeader, box_end: u64) -> Block {
    let box_type = header.box_type.clone();
    let content_start = offset + header.header_len;
    let label = box_label(&box_type);

    let mut children = header_field_blocks(data, offset, &header);

    if content_start < box_end {
        if CONTAINER_TYPES.contains(&box_type.as_str()) {
            children.extend(boxes_in_range(data, content_start, box_end));
        } else if box_type == "meta" {
            // meta is a FullBox whose children follow a version/flags field.
            if content_start + 4 <= box_end {
                let version = data[content_start as usize];
                children.push(Block::leaf(
                    format!("Version: {version}"),
                    ByteRange::new(content_start, content_start + 1),
                ));
                children.push(Block::leaf(
                    "Flags",
                    ByteRange::new(content_start + 1, content_start + 4),
                ));
                children.extend(boxes_in_range(data, content_start + 4, box_end));
            }
        } else if box_type == "mdat" {
            children.push(Block::leaf(
                format!("Media data ({} bytes)", box_end - content_start),
                ByteRange::new(content_start, box_end),
            ));
        } else if let Some(mut specific) =
            specific_box_children(data, &box_type, content_start, box_end)
        {
            children.append(&mut specific);
        } else {
            children.push(Block::leaf(
                format!("Data ({} bytes)", box_end - content_start),
                ByteRange::new(content_start, box_end),
            ));
        }
    }

    let node = Block::node(label, ByteRange::new(offset, box_end), children);
    node.expanded_if(box_type == "ftyp")
}

fn specific_box_children(data: &[u8], box_type: &str, start: u64, end: u64) -> Option<Vec<Block>> {
    match box_type {
        "ftyp" => ftyp_children(data, start, end),
        "mvhd" => mvhd_children(data, start, end),
        "tkhd" => tkhd_children(data, start, end),
        "mdhd" => mdhd_children(data, start, end),
        "hdlr" => hdlr_children(data, start, end),
        "stsd" => stsd_children(data, start, end),
        _ => None,
    }
}

fn push_u32_field(data: &[u8], children: &mut Vec<Block>, label: &str, offset: u64) -> Option<()> {
    let value = read_u32(data, offset as usize)?;
    children.push(Block::leaf(
        format!("{label}: {value}"),
        ByteRange::new(offset, offset + 4),
    ));
    Some(())
}

/// Seconds between the MP4 (1904-01-01 00:00:00 UTC) and Unix epochs.
const MP4_EPOCH_OFFSET: i64 = 2_082_844_800;

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

/// Formats an MP4 timestamp (seconds since 1904-01-01 00:00:00 UTC) as a
/// human-readable UTC date/time.
fn format_mp4_epoch(mp4_seconds: u64) -> String {
    format_unix_timestamp(mp4_seconds as i64 - MP4_EPOCH_OFFSET)
}

/// Formats a duration given in seconds as `H:MM:SS.sss`, `M:SS.sss`, or
/// `S.sssS`, dropping leading zero components.
fn format_duration_secs(total_secs: f64) -> String {
    let hours = (total_secs / 3600.0).floor() as u64;
    let minutes = ((total_secs % 3600.0) / 60.0).floor() as u64;
    let secs = total_secs % 60.0;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{secs:06.3}")
    } else if minutes > 0 {
        format!("{minutes}:{secs:06.3}")
    } else {
        format!("{secs:.3}s")
    }
}

/// Pushes a version-dependent 32/64-bit absolute time field (creation or
/// modification time), annotated with a human-readable UTC date/time.
fn push_absolute_time_field(
    data: &[u8],
    children: &mut Vec<Block>,
    label: &str,
    offset: u64,
    width: u64,
) -> Option<()> {
    let value = if width == 8 {
        read_u64(data, offset as usize)?
    } else {
        read_u32(data, offset as usize)? as u64
    };
    children.push(Block::leaf(
        format!("{label}: {value} ({})", format_mp4_epoch(value)),
        ByteRange::new(offset, offset + width),
    ));
    Some(())
}

/// Pushes a version-dependent 32/64-bit duration field. When `timescale` is
/// known, annotates it with a human-readable duration.
fn push_duration_field(
    data: &[u8],
    children: &mut Vec<Block>,
    label: &str,
    offset: u64,
    width: u64,
    timescale: Option<u32>,
) -> Option<()> {
    let value = if width == 8 {
        read_u64(data, offset as usize)?
    } else {
        read_u32(data, offset as usize)? as u64
    };
    let text = match timescale {
        Some(timescale) if timescale > 0 => {
            format!(
                "{label}: {value} ({})",
                format_duration_secs(value as f64 / timescale as f64)
            )
        }
        _ => format!("{label}: {value}"),
    };
    children.push(Block::leaf(text, ByteRange::new(offset, offset + width)));
    Some(())
}

/// Reads the box's timescale field, pushing a plain integer block and
/// returning the parsed value for use when formatting a sibling duration field.
fn push_timescale_field(data: &[u8], children: &mut Vec<Block>, offset: u64) -> Option<u32> {
    let value = read_u32(data, offset as usize)?;
    children.push(Block::leaf(
        format!("Timescale: {value}"),
        ByteRange::new(offset, offset + 4),
    ));
    Some(value)
}

fn parse_language(code: u16) -> String {
    let c1 = (((code >> 10) & 0x1f) as u8).wrapping_add(0x60);
    let c2 = (((code >> 5) & 0x1f) as u8).wrapping_add(0x60);
    let c3 = ((code & 0x1f) as u8).wrapping_add(0x60);
    String::from_utf8_lossy(&[c1, c2, c3]).into_owned()
}

fn ftyp_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    if end < start + 8 {
        return None;
    }
    let s = start as usize;
    let major_brand = fourcc_string(&data[s..s + 4]);
    let minor_version = read_u32(data, s + 4)?;

    let mut children = vec![
        Block::leaf(
            format!("Major brand: {major_brand}"),
            ByteRange::new(start, start + 4),
        ),
        Block::leaf(
            format!("Minor version: {minor_version}"),
            ByteRange::new(start + 4, start + 8),
        ),
    ];

    let mut offset = start + 8;
    while offset + 4 <= end {
        let brand = fourcc_string(&data[offset as usize..offset as usize + 4]);
        children.push(Block::leaf(
            format!("Compatible brand: {brand}"),
            ByteRange::new(offset, offset + 4),
        ));
        offset += 4;
    }

    Some(children)
}

fn mvhd_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    let mut children = Vec::new();
    if end < start + 4 {
        return None;
    }
    let version = data[start as usize];
    children.push(Block::leaf(
        format!("Version: {version}"),
        ByteRange::new(start, start + 1),
    ));
    children.push(Block::leaf("Flags", ByteRange::new(start + 1, start + 4)));

    let width = if version == 1 { 8 } else { 4 };
    let mut offset = start + 4;
    if end < offset + width * 3 + 4 {
        return Some(children);
    }
    push_absolute_time_field(data, &mut children, "Creation time", offset, width)?;
    offset += width;
    push_absolute_time_field(data, &mut children, "Modification time", offset, width)?;
    offset += width;
    let timescale = push_timescale_field(data, &mut children, offset)?;
    offset += 4;
    push_duration_field(data, &mut children, "Duration", offset, width, Some(timescale))?;
    offset += width;

    if offset + 4 <= end {
        let rate = read_u32(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Rate: {}", rate as f64 / 65536.0),
            ByteRange::new(offset, offset + 4),
        ));
        offset += 4;
    }
    if offset + 2 <= end {
        let volume = read_u16(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Volume: {}", volume as f64 / 256.0),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }
    if offset + 10 <= end {
        children.push(Block::leaf("Reserved", ByteRange::new(offset, offset + 10)));
        offset += 10;
    }
    if offset + 36 <= end {
        children.push(Block::leaf(
            "Transformation matrix",
            ByteRange::new(offset, offset + 36),
        ));
        offset += 36;
    }
    if offset + 24 <= end {
        children.push(Block::leaf("Pre-defined", ByteRange::new(offset, offset + 24)));
        offset += 24;
    }
    if offset + 4 <= end {
        push_u32_field(data, &mut children, "Next track ID", offset)?;
    }

    Some(children)
}

fn tkhd_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    let mut children = Vec::new();
    if end < start + 4 {
        return None;
    }
    let version = data[start as usize];
    children.push(Block::leaf(
        format!("Version: {version}"),
        ByteRange::new(start, start + 1),
    ));
    children.push(Block::leaf("Flags", ByteRange::new(start + 1, start + 4)));

    let width = if version == 1 { 8 } else { 4 };
    let mut offset = start + 4;
    if end < offset + width * 2 + 8 + width {
        return Some(children);
    }
    push_absolute_time_field(data, &mut children, "Creation time", offset, width)?;
    offset += width;
    push_absolute_time_field(data, &mut children, "Modification time", offset, width)?;
    offset += width;
    push_u32_field(data, &mut children, "Track ID", offset)?;
    offset += 4;
    children.push(Block::leaf("Reserved", ByteRange::new(offset, offset + 4)));
    offset += 4;
    // The track's duration is expressed in the movie header's timescale,
    // which isn't available here, so it's shown without a human-readable form.
    push_duration_field(data, &mut children, "Duration", offset, width, None)?;
    offset += width;

    if offset + 8 <= end {
        children.push(Block::leaf("Reserved", ByteRange::new(offset, offset + 8)));
        offset += 8;
    }
    if offset + 2 <= end {
        let layer = read_u16(data, offset as usize)? as i16;
        children.push(Block::leaf(
            format!("Layer: {layer}"),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }
    if offset + 2 <= end {
        let alt_group = read_u16(data, offset as usize)? as i16;
        children.push(Block::leaf(
            format!("Alternate group: {alt_group}"),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }
    if offset + 2 <= end {
        let volume = read_u16(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Volume: {}", volume as f64 / 256.0),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }
    if offset + 2 <= end {
        children.push(Block::leaf("Reserved", ByteRange::new(offset, offset + 2)));
        offset += 2;
    }
    if offset + 36 <= end {
        children.push(Block::leaf(
            "Transformation matrix",
            ByteRange::new(offset, offset + 36),
        ));
        offset += 36;
    }
    if offset + 4 <= end {
        let width_fixed = read_u32(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Width: {}", width_fixed as f64 / 65536.0),
            ByteRange::new(offset, offset + 4),
        ));
        offset += 4;
    }
    if offset + 4 <= end {
        let height_fixed = read_u32(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Height: {}", height_fixed as f64 / 65536.0),
            ByteRange::new(offset, offset + 4),
        ));
    }

    Some(children)
}

fn mdhd_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    let mut children = Vec::new();
    if end < start + 4 {
        return None;
    }
    let version = data[start as usize];
    children.push(Block::leaf(
        format!("Version: {version}"),
        ByteRange::new(start, start + 1),
    ));
    children.push(Block::leaf("Flags", ByteRange::new(start + 1, start + 4)));

    let width = if version == 1 { 8 } else { 4 };
    let mut offset = start + 4;
    if end < offset + width * 3 + width {
        return Some(children);
    }
    push_absolute_time_field(data, &mut children, "Creation time", offset, width)?;
    offset += width;
    push_absolute_time_field(data, &mut children, "Modification time", offset, width)?;
    offset += width;
    let timescale = push_timescale_field(data, &mut children, offset)?;
    offset += 4;
    push_duration_field(data, &mut children, "Duration", offset, width, Some(timescale))?;
    offset += width;

    if offset + 2 <= end {
        let code = read_u16(data, offset as usize)?;
        children.push(Block::leaf(
            format!("Language: {}", parse_language(code)),
            ByteRange::new(offset, offset + 2),
        ));
        offset += 2;
    }
    if offset + 2 <= end {
        children.push(Block::leaf("Pre-defined", ByteRange::new(offset, offset + 2)));
    }

    Some(children)
}

fn hdlr_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    let mut children = Vec::new();
    if end < start + 4 {
        return None;
    }
    let version = data[start as usize];
    children.push(Block::leaf(
        format!("Version: {version}"),
        ByteRange::new(start, start + 1),
    ));
    children.push(Block::leaf("Flags", ByteRange::new(start + 1, start + 4)));

    let mut offset = start + 4;
    if end < offset + 20 {
        return Some(children);
    }
    children.push(Block::leaf("Pre-defined", ByteRange::new(offset, offset + 4)));
    offset += 4;
    let handler_type = fourcc_string(&data[offset as usize..offset as usize + 4]);
    children.push(Block::leaf(
        format!("Handler type: {handler_type}"),
        ByteRange::new(offset, offset + 4),
    ));
    offset += 4;
    children.push(Block::leaf("Reserved", ByteRange::new(offset, offset + 12)));
    offset += 12;

    if offset < end {
        let raw = &data[offset as usize..end as usize];
        let name_bytes = raw.split(|&b| b == 0).next().unwrap_or(raw);
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        children.push(Block::leaf(
            format!("Name: {name}"),
            ByteRange::new(offset, end),
        ));
    }

    Some(children)
}

fn stsd_children(data: &[u8], start: u64, end: u64) -> Option<Vec<Block>> {
    let mut children = Vec::new();
    if end < start + 4 {
        return None;
    }
    let version = data[start as usize];
    children.push(Block::leaf(
        format!("Version: {version}"),
        ByteRange::new(start, start + 1),
    ));
    children.push(Block::leaf("Flags", ByteRange::new(start + 1, start + 4)));

    let offset = start + 4;
    if end < offset + 4 {
        return Some(children);
    }
    let entry_count = read_u32(data, offset as usize)?;
    children.push(Block::leaf(
        format!("Entry count: {entry_count}"),
        ByteRange::new(offset, offset + 4),
    ));

    let entries_start = offset + 4;
    if entries_start < end {
        children.push(Block::leaf(
            format!("Sample entries ({} bytes)", end - entries_start),
            ByteRange::new(entries_start, end),
        ));
    }

    Some(children)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let size = 8 + payload.len() as u32;
        buf.extend_from_slice(&size.to_be_bytes());
        buf.extend_from_slice(box_type);
        buf.extend_from_slice(payload);
        buf
    }

    fn encode_language(lang: &str) -> u16 {
        let bytes = lang.as_bytes();
        let c1 = (bytes[0] - 0x60) as u16;
        let c2 = (bytes[1] - 0x60) as u16;
        let c3 = (bytes[2] - 0x60) as u16;
        (c1 << 10) | (c2 << 5) | c3
    }

    fn build_mp4() -> Vec<u8> {
        let ftyp_payload = {
            let mut p = Vec::new();
            p.extend_from_slice(b"isom");
            p.extend_from_slice(&0u32.to_be_bytes());
            p.extend_from_slice(b"isom");
            p.extend_from_slice(b"iso2");
            p.extend_from_slice(b"mp41");
            p
        };
        let ftyp = make_box(b"ftyp", &ftyp_payload);

        let free = make_box(b"free", &[0u8; 4]);

        let mvhd_payload = {
            let mut p = Vec::new();
            p.push(0); // version
            p.extend_from_slice(&[0, 0, 0]); // flags
            p.extend_from_slice(&0u32.to_be_bytes()); // creation time
            p.extend_from_slice(&0u32.to_be_bytes()); // modification time
            p.extend_from_slice(&1000u32.to_be_bytes()); // timescale
            p.extend_from_slice(&5000u32.to_be_bytes()); // duration
            p.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
            p.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
            p.extend_from_slice(&[0u8; 10]); // reserved
            p.extend_from_slice(&[0u8; 36]); // matrix
            p.extend_from_slice(&[0u8; 24]); // pre-defined
            p.extend_from_slice(&2u32.to_be_bytes()); // next track ID
            p
        };
        let mvhd = make_box(b"mvhd", &mvhd_payload);

        let tkhd_payload = {
            let mut p = Vec::new();
            p.push(0); // version
            p.extend_from_slice(&[0, 0, 0]); // flags
            p.extend_from_slice(&0u32.to_be_bytes()); // creation time
            p.extend_from_slice(&0u32.to_be_bytes()); // modification time
            p.extend_from_slice(&1u32.to_be_bytes()); // track ID
            p.extend_from_slice(&0u32.to_be_bytes()); // reserved
            p.extend_from_slice(&5000u32.to_be_bytes()); // duration
            p.extend_from_slice(&[0u8; 8]); // reserved
            p.extend_from_slice(&0i16.to_be_bytes()); // layer
            p.extend_from_slice(&0i16.to_be_bytes()); // alternate group
            p.extend_from_slice(&0u16.to_be_bytes()); // volume
            p.extend_from_slice(&0u16.to_be_bytes()); // reserved
            p.extend_from_slice(&[0u8; 36]); // matrix
            p.extend_from_slice(&320u32.wrapping_shl(16).to_be_bytes()); // width 320.0
            p.extend_from_slice(&240u32.wrapping_shl(16).to_be_bytes()); // height 240.0
            p
        };
        let tkhd = make_box(b"tkhd", &tkhd_payload);

        let mdhd_payload = {
            let mut p = Vec::new();
            p.push(0); // version
            p.extend_from_slice(&[0, 0, 0]); // flags
            p.extend_from_slice(&0u32.to_be_bytes()); // creation time
            p.extend_from_slice(&0u32.to_be_bytes()); // modification time
            p.extend_from_slice(&1000u32.to_be_bytes()); // timescale
            p.extend_from_slice(&5000u32.to_be_bytes()); // duration
            p.extend_from_slice(&encode_language("und").to_be_bytes());
            p.extend_from_slice(&0u16.to_be_bytes()); // pre-defined
            p
        };
        let mdhd = make_box(b"mdhd", &mdhd_payload);

        let hdlr_payload = {
            let mut p = Vec::new();
            p.push(0); // version
            p.extend_from_slice(&[0, 0, 0]); // flags
            p.extend_from_slice(&0u32.to_be_bytes()); // pre-defined
            p.extend_from_slice(b"vide"); // handler type
            p.extend_from_slice(&[0u8; 12]); // reserved
            p.extend_from_slice(b"VideoHandler\0");
            p
        };
        let hdlr = make_box(b"hdlr", &hdlr_payload);

        let mdia_payload = [mdhd, hdlr].concat();
        let mdia = make_box(b"mdia", &mdia_payload);

        let trak_payload = [tkhd, mdia].concat();
        let trak = make_box(b"trak", &trak_payload);

        let moov_payload = [mvhd, trak].concat();
        let moov = make_box(b"moov", &moov_payload);

        let mdat = make_box(b"mdat", b"fakemediadata");

        [ftyp, free, moov, mdat].concat()
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        fn find<'a>(blocks: &'a [Block], label: &str) -> Option<&'a Block> {
            for block in blocks {
                if block.label == label {
                    return Some(block);
                }
                if let Some(found) = find(&block.children, label) {
                    return Some(found);
                }
            }
            None
        }
        find(blocks, label).unwrap_or_else(|| panic!("block {label:?} not found"))
    }

    #[test]
    fn matches_ftyp_magic() {
        let data = build_mp4();
        assert!(Mp4Dissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_mp4_data() {
        assert!(!Mp4Dissector.matches(b"not an mp4 file"));
        assert!(!Mp4Dissector.matches(b""));
        assert!(!Mp4Dissector.matches(b"\0\0\0\x08free"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_data() {
        let blocks = Mp4Dissector.dissect(b"ftyp");
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_ftyp_moov_and_mdat() {
        let data = build_mp4();
        let blocks = Mp4Dissector.dissect(&data);

        let ftyp = find_block(&blocks, "ftyp (File Type)");
        assert!(
            ftyp.children
                .iter()
                .any(|b| b.label == "Major brand: isom")
        );
        assert!(
            ftyp.children
                .iter()
                .any(|b| b.label == "Compatible brand: iso2")
        );

        let mvhd = find_block(&blocks, "mvhd (Movie Header)");
        assert!(
            mvhd.children
                .iter()
                .any(|b| b.label == "Creation time: 0 (1904-01-01 00:00:00 UTC)")
        );
        assert!(mvhd.children.iter().any(|b| b.label == "Timescale: 1000"));
        assert!(
            mvhd.children
                .iter()
                .any(|b| b.label == "Duration: 5000 (5.000s)")
        );
        assert!(
            mvhd.children
                .iter()
                .any(|b| b.label == "Next track ID: 2")
        );

        let tkhd = find_block(&blocks, "tkhd (Track Header)");
        assert!(tkhd.children.iter().any(|b| b.label == "Track ID: 1"));
        assert!(tkhd.children.iter().any(|b| b.label == "Width: 320"));
        assert!(tkhd.children.iter().any(|b| b.label == "Height: 240"));

        let mdhd = find_block(&blocks, "mdhd (Media Header)");
        assert!(mdhd.children.iter().any(|b| b.label == "Language: und"));

        let hdlr = find_block(&blocks, "hdlr (Handler Reference)");
        assert!(
            hdlr.children
                .iter()
                .any(|b| b.label == "Handler type: vide")
        );
        assert!(
            hdlr.children
                .iter()
                .any(|b| b.label == "Name: VideoHandler")
        );

        let mdat = find_block(&blocks, "mdat (Media Data)");
        assert!(
            mdat.children
                .iter()
                .any(|b| b.label == "Media data (13 bytes)")
        );
    }

    #[test]
    fn identify_reports_mp4() {
        let data = build_mp4();
        assert_eq!(super::super::identify(&data), "MP4");
    }
}
