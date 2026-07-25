use super::{Block, ByteRange, Dissector};

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const DQT: u8 = 0xDB;
const DHT: u8 = 0xC4;
const APP0: u8 = 0xE0;
const APP1: u8 = 0xE1;
const EXIF_IDENTIFIER: &[u8] = b"Exif\0\0";
const JFIF_IDENTIFIER: &[u8] = b"JFIF\0";
const MAX_IFD_DEPTH: u32 = 4;

pub struct JpegDissector;

impl Dissector for JpegDissector {
    fn name(&self) -> &'static str {
        "JPEG"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(&[0xFF, SOI])
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();

        if data.len() < 2 || data[0] != 0xFF || data[1] != SOI {
            return blocks;
        }
        blocks.push(Block::leaf("SOI", ByteRange::new(0, 2)));

        let mut offset: u64 = 2;

        loop {
            let off = offset as usize;
            match (data.get(off), data.get(off + 1)) {
                (Some(&0xFF), Some(&marker)) => {
                    if marker == EOI {
                        blocks.push(Block::leaf("EOI", ByteRange::new(offset, offset + 2)));
                        break;
                    }
                    if marker == SOS {
                        match sos_block(data, offset) {
                            Some(block) => {
                                offset = block.range.end;
                                blocks.push(block);
                            }
                            None => break,
                        }
                        continue;
                    }
                    match marker_block(data, offset, marker) {
                        Some(block) => {
                            offset = block.range.end;
                            blocks.push(block);
                        }
                        None => break,
                    }
                }
                _ => break,
            }
        }

        blocks
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Reads a generic `0xFF <marker> <length u16> <payload>` marker, returning
/// the payload byte range (data_start, data_end) and the offset just past it.
fn marker_payload(data: &[u8], offset: u64) -> Option<(u64, u64)> {
    let off = offset as usize;
    let length = read_u16(data, off + 2)? as u64;
    if length < 2 {
        return None;
    }
    let data_start = offset + 4;
    let available = data.len() as u64 - data_start.min(data.len() as u64);
    let data_end = data_start + (length - 2).min(available);
    Some((data_start, data_end))
}

fn sof_fields(data: &[u8], offset: u64) -> Option<Vec<Block>> {
    let off = offset as usize;
    if data.len() < off + 6 {
        return None;
    }

    let precision = data[off];
    let height = read_u16(data, off + 1)?;
    let width = read_u16(data, off + 3)?;
    let num_components = data[off + 5];

    let mut fields = vec![
        Block::leaf(
            format!("Precision: {precision}"),
            ByteRange::new(offset, offset + 1),
        ),
        Block::leaf(
            format!("Height: {height}"),
            ByteRange::new(offset + 1, offset + 3),
        ),
        Block::leaf(
            format!("Width: {width}"),
            ByteRange::new(offset + 3, offset + 5),
        ),
        Block::leaf(
            format!("Number of components: {num_components}"),
            ByteRange::new(offset + 5, offset + 6),
        ),
    ];

    let mut pos = off + 6;
    for _ in 0..num_components {
        if data.len() < pos + 3 {
            break;
        }
        let id = data[pos];
        let sampling = data[pos + 1];
        let quant_table = data[pos + 2];
        let start = pos as u64;
        fields.push(Block::node(
            format!("Component {id}"),
            ByteRange::new(start, start + 3),
            vec![
                Block::leaf(
                    format!("Component id: {id}"),
                    ByteRange::new(start, start + 1),
                ),
                Block::leaf(
                    format!("Sampling factors: {:#04x}", sampling),
                    ByteRange::new(start + 1, start + 2),
                ),
                Block::leaf(
                    format!("Quantization table selector: {quant_table}"),
                    ByteRange::new(start + 2, start + 3),
                ),
            ],
        ));
        pos += 3;
    }

    Some(fields)
}

fn app_label(marker: u8) -> String {
    format!("APP{} marker", marker - 0xE0)
}

fn marker_label(marker: u8) -> String {
    match marker {
        0xE0..=0xEF => app_label(marker),
        DQT => "DQT marker".to_string(),
        DHT => "DHT marker".to_string(),
        0xC0 => "SOF0 marker".to_string(),
        0xC1 => "SOF1 marker".to_string(),
        0xC2 => "SOF2 marker".to_string(),
        0xC3 => "SOF3 marker".to_string(),
        _ => format!("Marker {:#04x}", marker),
    }
}

fn is_sof(marker: u8) -> bool {
    matches!(marker, 0xC0 | 0xC1 | 0xC2 | 0xC3)
        || (matches!(marker, 0xC0..=0xCF) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC)
}

fn marker_block(data: &[u8], offset: u64, marker: u8) -> Option<Block> {
    let (data_start, data_end) = marker_payload(data, offset)?;

    let starts_with = |prefix: &[u8]| {
        data.get(data_start as usize..)
            .is_some_and(|d| d.starts_with(prefix))
    };
    let is_exif = marker == APP1 && starts_with(EXIF_IDENTIFIER);
    let is_jfif = marker == APP0 && starts_with(JFIF_IDENTIFIER);
    let sof = is_sof(marker);

    let children = if sof {
        sof_fields(data, data_start).unwrap_or_else(|| generic_data_children(data_start, data_end))
    } else if marker == DQT {
        generic_data_children_labeled(data_start, data_end, "Quantization table data")
    } else if marker == DHT {
        generic_data_children_labeled(data_start, data_end, "Huffman table data")
    } else if is_exif {
        exif_children(data, data_start, data_end)
    } else if is_jfif {
        jfif_children(data, data_start, data_end)
    } else {
        generic_data_children(data_start, data_end)
    };

    let label = if is_exif {
        "APP1 marker (Exif)".to_string()
    } else if is_jfif {
        "APP0 marker (JFIF)".to_string()
    } else {
        marker_label(marker)
    };

    Some(
        Block::node(label, ByteRange::new(offset, data_end), children)
            .expanded_if(sof || is_exif || is_jfif),
    )
}

fn jfif_density_units_name(value: u8) -> &'static str {
    match value {
        0 => "No units (aspect ratio)",
        1 => "Pixels per inch",
        2 => "Pixels per centimeter",
        _ => "Unknown",
    }
}

/// Parses an APP0 "JFIF\0"-prefixed segment: the 5-byte identifier,
/// version, density units/X/Y, thumbnail width/height, and (if present) an
/// uncompressed 24-bit RGB thumbnail. Falls back to a generic data leaf if
/// the payload is truncated before the fixed-size fields.
fn jfif_children(data: &[u8], data_start: u64, data_end: u64) -> Vec<Block> {
    let off = data_start as usize + JFIF_IDENTIFIER.len();
    if data.len() < off + 9 {
        return generic_data_children_labeled(data_start, data_end, "JFIF data");
    }

    let major = data[off];
    let minor = data[off + 1];
    let density_units = data[off + 2];
    let x_density = read_u16(data, off + 3).unwrap_or(0);
    let y_density = read_u16(data, off + 5).unwrap_or(0);
    let thumbnail_width = data[off + 7];
    let thumbnail_height = data[off + 8];

    let mut children = vec![
        Block::leaf(
            "Identifier: JFIF",
            ByteRange::new(data_start, data_start + JFIF_IDENTIFIER.len() as u64),
        ),
        Block::leaf(
            format!("Version: {major}.{minor:02}"),
            ByteRange::new(off as u64, off as u64 + 2),
        ),
        Block::leaf(
            format!(
                "Density units: {} ({density_units})",
                jfif_density_units_name(density_units)
            ),
            ByteRange::new(off as u64 + 2, off as u64 + 3),
        ),
        Block::leaf(
            format!("X density: {x_density}"),
            ByteRange::new(off as u64 + 3, off as u64 + 5),
        ),
        Block::leaf(
            format!("Y density: {y_density}"),
            ByteRange::new(off as u64 + 5, off as u64 + 7),
        ),
        Block::leaf(
            format!("Thumbnail width: {thumbnail_width}"),
            ByteRange::new(off as u64 + 7, off as u64 + 8),
        ),
        Block::leaf(
            format!("Thumbnail height: {thumbnail_height}"),
            ByteRange::new(off as u64 + 8, off as u64 + 9),
        ),
    ];

    let thumbnail_bytes = 3u64 * thumbnail_width as u64 * thumbnail_height as u64;
    let thumbnail_start = off as u64 + 9;
    let thumbnail_end = (thumbnail_start + thumbnail_bytes).min(data_end);
    if thumbnail_end > thumbnail_start {
        children.push(Block::leaf(
            "Thumbnail data (RGB)",
            ByteRange::new(thumbnail_start, thumbnail_end),
        ));
    }

    children
}

fn generic_data_children(data_start: u64, data_end: u64) -> Vec<Block> {
    generic_data_children_labeled(data_start, data_end, "Data")
}

fn generic_data_children_labeled(data_start: u64, data_end: u64, label: &str) -> Vec<Block> {
    if data_end > data_start {
        vec![Block::leaf(
            label.to_string(),
            ByteRange::new(data_start, data_end),
        )]
    } else {
        Vec::new()
    }
}

/// EXIF/TIFF tag names, per the standard tag registry (see
/// <https://exiv2.org/tags.html>). Not exhaustive, but covers the tags
/// commonly found in IFD0, the Exif SubIFD, and the Interoperability IFD.
fn exif_tag_name(tag: u16) -> &'static str {
    match tag {
        0x000B => "ProcessingSoftware",
        0x00FE => "NewSubfileType",
        0x00FF => "SubfileType",
        0x0100 => "ImageWidth",
        0x0101 => "ImageLength",
        0x0102 => "BitsPerSample",
        0x0103 => "Compression",
        0x0106 => "PhotometricInterpretation",
        0x010A => "FillOrder",
        0x010D => "DocumentName",
        0x010E => "ImageDescription",
        0x010F => "Make",
        0x0110 => "Model",
        0x0111 => "StripOffsets",
        0x0112 => "Orientation",
        0x0115 => "SamplesPerPixel",
        0x0116 => "RowsPerStrip",
        0x0117 => "StripByteCounts",
        0x011A => "XResolution",
        0x011B => "YResolution",
        0x011C => "PlanarConfiguration",
        0x0128 => "ResolutionUnit",
        0x012D => "TransferFunction",
        0x0131 => "Software",
        0x0132 => "DateTime",
        0x013B => "Artist",
        0x013C => "HostComputer",
        0x013D => "Predictor",
        0x013E => "WhitePoint",
        0x013F => "PrimaryChromaticities",
        0x0140 => "ColorMap",
        0x0142 => "TileWidth",
        0x0143 => "TileLength",
        0x0144 => "TileOffsets",
        0x0145 => "TileByteCounts",
        0x014A => "SubIFDs",
        0x0201 => "JPEGInterchangeFormat",
        0x0202 => "JPEGInterchangeFormatLength",
        0x0211 => "YCbCrCoefficients",
        0x0212 => "YCbCrSubSampling",
        0x0213 => "YCbCrPositioning",
        0x0214 => "ReferenceBlackWhite",
        0x02BC => "XMLPacket",
        0x4746 => "Rating",
        0x4749 => "RatingPercent",
        0x800D => "ImageID",
        0x828D => "CFARepeatPatternDim",
        0x828E => "CFAPattern",
        0x828F => "BatteryLevel",
        0x8298 => "Copyright",
        0x829A => "ExposureTime",
        0x829D => "FNumber",
        0x83BB => "IPTCNAA",
        0x8649 => "ImageResources",
        0x8769 => "Exif IFD pointer",
        0x8773 => "InterColorProfile",
        0x8822 => "ExposureProgram",
        0x8824 => "SpectralSensitivity",
        0x8825 => "GPS Info IFD pointer",
        0x8827 => "ISOSpeedRatings",
        0x8828 => "OECF",
        0x8830 => "SensitivityType",
        0x8832 => "RecommendedExposureIndex",
        0x9000 => "ExifVersion",
        0x9003 => "DateTimeOriginal",
        0x9004 => "DateTimeDigitized",
        0x9010 => "OffsetTime",
        0x9011 => "OffsetTimeOriginal",
        0x9012 => "OffsetTimeDigitized",
        0x9101 => "ComponentsConfiguration",
        0x9102 => "CompressedBitsPerPixel",
        0x9201 => "ShutterSpeedValue",
        0x9202 => "ApertureValue",
        0x9203 => "BrightnessValue",
        0x9204 => "ExposureBiasValue",
        0x9205 => "MaxApertureValue",
        0x9206 => "SubjectDistance",
        0x9207 => "MeteringMode",
        0x9208 => "LightSource",
        0x9209 => "Flash",
        0x920A => "FocalLength",
        0x920B => "FlashEnergy",
        0x920E => "FocalPlaneXResolution",
        0x920F => "FocalPlaneYResolution",
        0x9210 => "FocalPlaneResolutionUnit",
        0x9214 => "SubjectLocation",
        0x9215 => "ExposureIndex",
        0x9217 => "SensingMethod",
        0x9286 => "UserComment",
        0x9290 => "SubSecTime",
        0x9291 => "SubSecTimeOriginal",
        0x9292 => "SubSecTimeDigitized",
        0x9400 => "Temperature",
        0x9401 => "Humidity",
        0x9402 => "Pressure",
        0x9403 => "WaterDepth",
        0x9404 => "Acceleration",
        0x9405 => "CameraElevationAngle",
        0x9C9B => "XPTitle",
        0x9C9C => "XPComment",
        0x9C9D => "XPAuthor",
        0x9C9E => "XPKeywords",
        0x9C9F => "XPSubject",
        0xA000 => "FlashpixVersion",
        0xA001 => "ColorSpace",
        0xA002 => "PixelXDimension",
        0xA003 => "PixelYDimension",
        0xA004 => "RelatedSoundFile",
        0xA005 => "Interoperability IFD pointer",
        0xA20B => "FlashEnergy",
        0xA20E => "FocalPlaneXResolution",
        0xA20F => "FocalPlaneYResolution",
        0xA210 => "FocalPlaneResolutionUnit",
        0xA214 => "SubjectLocation",
        0xA215 => "ExposureIndex",
        0xA217 => "SensingMethod",
        0xA300 => "FileSource",
        0xA301 => "SceneType",
        0xA302 => "CFAPattern",
        0xA401 => "CustomRendered",
        0xA402 => "ExposureMode",
        0xA403 => "WhiteBalance",
        0xA404 => "DigitalZoomRatio",
        0xA405 => "FocalLengthIn35mmFilm",
        0xA406 => "SceneCaptureType",
        0xA407 => "GainControl",
        0xA408 => "Contrast",
        0xA409 => "Saturation",
        0xA40A => "Sharpness",
        0xA40B => "DeviceSettingDescription",
        0xA40C => "SubjectDistanceRange",
        0xA420 => "ImageUniqueID",
        0xA430 => "CameraOwnerName",
        0xA431 => "BodySerialNumber",
        0xA432 => "LensSpecification",
        0xA433 => "LensMake",
        0xA434 => "LensModel",
        0xA435 => "LensSerialNumber",
        0xA460 => "CompositeImage",
        0xA500 => "Gamma",
        _ => "",
    }
}

/// Friendly names for EXIF SHORT fields that are really enums. Returns
/// `None` for tags with no known enum mapping or unrecognized values (in
/// which case the caller falls back to the raw numeric value).
fn exif_enum_value(tag: u16, value: u16) -> Option<&'static str> {
    match (tag, value) {
        (0x0103, 1) => Some("Uncompressed"),
        (0x0103, 6) => Some("JPEG"),

        (0x0112, 1) => Some("Horizontal (normal)"),
        (0x0112, 2) => Some("Mirrored horizontal"),
        (0x0112, 3) => Some("Rotated 180"),
        (0x0112, 4) => Some("Mirrored vertical"),
        (0x0112, 5) => Some("Mirrored horizontal, rotated 90 CW"),
        (0x0112, 6) => Some("Rotated 90 CW (Vertical)"),
        (0x0112, 7) => Some("Mirrored horizontal, rotated 90 CCW"),
        (0x0112, 8) => Some("Rotated 90 CCW (Vertical)"),

        (0x0128, 1) => Some("None"),
        (0x0128, 2) => Some("Inches"),
        (0x0128, 3) => Some("Centimeters"),

        (0x0213, 1) => Some("Centered"),
        (0x0213, 2) => Some("Co-sited"),

        (0x8822, 0) => Some("Not defined"),
        (0x8822, 1) => Some("Manual"),
        (0x8822, 2) => Some("Normal program"),
        (0x8822, 3) => Some("Aperture priority"),
        (0x8822, 4) => Some("Shutter priority"),
        (0x8822, 5) => Some("Creative program"),
        (0x8822, 6) => Some("Action program"),
        (0x8822, 7) => Some("Portrait mode"),
        (0x8822, 8) => Some("Landscape mode"),

        (0x9207, 0) => Some("Unknown"),
        (0x9207, 1) => Some("Average"),
        (0x9207, 2) => Some("Center-weighted average"),
        (0x9207, 3) => Some("Spot"),
        (0x9207, 4) => Some("Multi-spot"),
        (0x9207, 5) => Some("Pattern"),
        (0x9207, 6) => Some("Partial"),
        (0x9207, 255) => Some("Other"),

        (0x9208, 0) => Some("Unknown"),
        (0x9208, 1) => Some("Daylight"),
        (0x9208, 2) => Some("Fluorescent"),
        (0x9208, 3) => Some("Tungsten"),
        (0x9208, 4) => Some("Flash"),
        (0x9208, 9) => Some("Fine weather"),
        (0x9208, 10) => Some("Cloudy"),
        (0x9208, 11) => Some("Shade"),
        (0x9208, 255) => Some("Other"),

        (0x9209, 0x00) => Some("No flash"),
        (0x9209, 0x01) => Some("Flash fired"),
        (0x9209, 0x05) => Some("Flash fired, return not detected"),
        (0x9209, 0x07) => Some("Flash fired, return detected"),
        (0x9209, 0x09) => Some("Flash fired, compulsory"),
        (0x9209, 0x0D) => Some("Flash fired, compulsory, return not detected"),
        (0x9209, 0x0F) => Some("Flash fired, compulsory, return detected"),
        (0x9209, 0x10) => Some("Flash did not fire, compulsory"),
        (0x9209, 0x18) => Some("No flash function"),
        (0x9209, 0x19) => Some("Flash fired, auto mode"),
        (0x9209, 0x1D) => Some("Flash fired, auto mode, return not detected"),
        (0x9209, 0x1F) => Some("Flash fired, auto mode, return detected"),
        (0x9209, 0x20) => Some("No flash function"),

        (0xA001, 1) => Some("sRGB"),
        (0xA001, 0xFFFF) => Some("Uncalibrated"),

        (0xA403, 0) => Some("Auto"),
        (0xA403, 1) => Some("Manual"),

        (0xA406, 0) => Some("Standard"),
        (0xA406, 1) => Some("Landscape"),
        (0xA406, 2) => Some("Portrait"),
        (0xA406, 3) => Some("Night scene"),

        _ => None,
    }
}

fn exif_type_name(field_type: u16) -> &'static str {
    match field_type {
        1 => "BYTE",
        2 => "ASCII",
        3 => "SHORT",
        4 => "LONG",
        5 => "RATIONAL",
        6 => "SBYTE",
        7 => "UNDEFINED",
        8 => "SSHORT",
        9 => "SLONG",
        10 => "SRATIONAL",
        11 => "FLOAT",
        12 => "DOUBLE",
        _ => "UNKNOWN",
    }
}

fn exif_type_size(field_type: u16) -> u32 {
    match field_type {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

fn read_exif_u16(data: &[u8], offset: usize, big_endian: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(if big_endian {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    })
}

fn read_exif_u32(data: &[u8], offset: usize, big_endian: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

/// Formats a short human-readable summary of an IFD entry's value, when the
/// type/count combination is simple enough to decode without a full TIFF
/// value-array reader (single SHORT/LONG, ASCII strings, or a single
/// RATIONAL). Falls back to `None` for anything more complex.
fn exif_value_summary(
    data: &[u8],
    tiff_start: usize,
    big_endian: bool,
    field_type: u16,
    count: u32,
    value_field_offset: usize,
    total_size: u32,
) -> Option<String> {
    let value_offset = if total_size <= 4 {
        value_field_offset
    } else {
        tiff_start + read_exif_u32(data, value_field_offset, big_endian)? as usize
    };

    match field_type {
        2 => {
            let bytes = data.get(value_offset..value_offset + count as usize)?;
            let text = String::from_utf8_lossy(bytes);
            Some(text.trim_end_matches('\0').to_string())
        }
        3 if count == 1 => Some(read_exif_u16(data, value_offset, big_endian)?.to_string()),
        4 if count == 1 => Some(read_exif_u32(data, value_offset, big_endian)?.to_string()),
        5 | 10 if count == 1 => {
            let numerator = read_exif_u32(data, value_offset, big_endian)?;
            let denominator = read_exif_u32(data, value_offset + 4, big_endian)?;
            Some(format!("{numerator}/{denominator}"))
        }
        _ => None,
    }
}

/// Which tag namespace an IFD's entries should be interpreted under. The
/// GPS IFD reuses small tag numbers (0x0000-0x001F) with entirely different
/// meanings from the main Exif/TIFF tag space, so it needs its own name
/// table and value formatting (coordinates, timestamps, refs).
#[derive(Clone, Copy, PartialEq)]
enum IfdNamespace {
    Exif,
    Gps,
}

/// Reads `count` consecutive RATIONAL (u32/u32) pairs starting at
/// `value_offset`.
fn read_rationals(
    data: &[u8],
    value_offset: usize,
    count: u32,
    big_endian: bool,
) -> Option<Vec<(u32, u32)>> {
    let mut rationals = Vec::with_capacity(count as usize);
    for i in 0..count {
        let offset = value_offset + (i as usize) * 8;
        let numerator = read_exif_u32(data, offset, big_endian)?;
        let denominator = read_exif_u32(data, offset + 4, big_endian)?;
        rationals.push((numerator, denominator));
    }
    Some(rationals)
}

fn rational_to_f64((numerator, denominator): (u32, u32)) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Formats a GPSLatitude/GPSLongitude/GPSDestLatitude/GPSDestLongitude
/// value: 3 RATIONALs (degrees, minutes, seconds) into both DMS and decimal
/// degrees, e.g. `37°25'19.07" (37.421964°)`.
fn gps_dms_summary(rationals: &[(u32, u32)]) -> Option<String> {
    let [deg, min, sec] = rationals else {
        return None;
    };
    let degrees = rational_to_f64(*deg);
    let minutes = rational_to_f64(*min);
    let seconds = rational_to_f64(*sec);
    let decimal = degrees + minutes / 60.0 + seconds / 3600.0;
    Some(format!(
        "{degrees:.0}\u{b0}{minutes:.0}'{seconds:.2}\" ({decimal:.6}\u{b0})"
    ))
}

/// Formats a GPSTimeStamp value: 3 RATIONALs (hour, minute, second) as
/// `HH:MM:SS.sss` UTC.
fn gps_timestamp_summary(rationals: &[(u32, u32)]) -> Option<String> {
    let [hour, minute, second] = rationals else {
        return None;
    };
    Some(format!(
        "{:02.0}:{:02.0}:{:05.2} UTC",
        rational_to_f64(*hour),
        rational_to_f64(*minute),
        rational_to_f64(*second)
    ))
}

/// GPS-namespace tag names, per <https://exiv2.org/tags.html> (GPS Info
/// IFD table).
fn gps_tag_name(tag: u16) -> &'static str {
    match tag {
        0x0000 => "GPSVersionID",
        0x0001 => "GPSLatitudeRef",
        0x0002 => "GPSLatitude",
        0x0003 => "GPSLongitudeRef",
        0x0004 => "GPSLongitude",
        0x0005 => "GPSAltitudeRef",
        0x0006 => "GPSAltitude",
        0x0007 => "GPSTimeStamp",
        0x0008 => "GPSSatellites",
        0x0009 => "GPSStatus",
        0x000A => "GPSMeasureMode",
        0x000B => "GPSDOP",
        0x000C => "GPSSpeedRef",
        0x000D => "GPSSpeed",
        0x000E => "GPSTrackRef",
        0x000F => "GPSTrack",
        0x0010 => "GPSImgDirectionRef",
        0x0011 => "GPSImgDirection",
        0x0012 => "GPSMapDatum",
        0x0013 => "GPSDestLatitudeRef",
        0x0014 => "GPSDestLatitude",
        0x0015 => "GPSDestLongitudeRef",
        0x0016 => "GPSDestLongitude",
        0x0017 => "GPSDestBearingRef",
        0x0018 => "GPSDestBearing",
        0x0019 => "GPSDestDistanceRef",
        0x001A => "GPSDestDistance",
        0x001B => "GPSProcessingMethod",
        0x001C => "GPSAreaInformation",
        0x001D => "GPSDateStamp",
        0x001E => "GPSDifferential",
        0x001F => "GPSHPositioningError",
        _ => "",
    }
}

/// Friendly names for GPS SHORT/BYTE/ASCII enum-like fields.
fn gps_enum_value(tag: u16, value: &str) -> Option<&'static str> {
    match (tag, value) {
        (0x0001, "N") => Some("North"),
        (0x0001, "S") => Some("South"),
        (0x0003, "E") => Some("East"),
        (0x0003, "W") => Some("West"),
        (0x0005, "0") => Some("Above sea level"),
        (0x0005, "1") => Some("Below sea level"),
        (0x0009, "A") => Some("Measurement in progress"),
        (0x0009, "V") => Some("Measurement interoperability"),
        (0x000A, "2") => Some("2-dimensional"),
        (0x000A, "3") => Some("3-dimensional"),
        (0x000C, "K") => Some("Kilometers per hour"),
        (0x000C, "M") => Some("Miles per hour"),
        (0x000C, "N") => Some("Knots"),
        (0x000E | 0x0010 | 0x0017, "T") => Some("True direction"),
        (0x000E | 0x0010 | 0x0017, "M") => Some("Magnetic direction"),
        _ => None,
    }
}

/// Parses one IFD (Image File Directory) at `ifd_offset` (relative to
/// `tiff_start`) into a Block, recursively following the Exif SubIFD, GPS,
/// and Interoperability IFD pointer tags up to `MAX_IFD_DEPTH`.
/// Bounds-checked throughout; returns `None` if the entry count or offsets
/// fall outside `data`.
fn ifd_block(
    data: &[u8],
    tiff_start: usize,
    ifd_offset: u32,
    big_endian: bool,
    label: &str,
    namespace: IfdNamespace,
    depth: u32,
) -> Option<Block> {
    let ifd_start = tiff_start.checked_add(ifd_offset as usize)?;
    let entry_count = read_exif_u16(data, ifd_start, big_endian)?;

    let mut children = Vec::new();
    let mut pos = ifd_start + 2;

    for _ in 0..entry_count {
        if data.len() < pos + 12 {
            break;
        }
        let tag = read_exif_u16(data, pos, big_endian)?;
        let field_type = read_exif_u16(data, pos + 2, big_endian)?;
        let count = read_exif_u32(data, pos + 4, big_endian)?;
        let value_field_offset = pos + 8;
        let total_size = exif_type_size(field_type).saturating_mul(count);

        let name = match namespace {
            IfdNamespace::Exif => exif_tag_name(tag),
            IfdNamespace::Gps => gps_tag_name(tag),
        };
        let tag_label = if name.is_empty() {
            format!("Tag {tag:#06x}")
        } else {
            name.to_string()
        };

        let value_offset = if total_size <= 4 {
            value_field_offset
        } else {
            read_exif_u32(data, value_field_offset, big_endian)
                .map(|rel| tiff_start + rel as usize)
                .unwrap_or(value_field_offset)
        };

        // GPS coordinate/timestamp fields are 3 RATIONALs that need
        // degrees/minutes/seconds (or hour/minute/second) formatting rather
        // than the generic single-RATIONAL summary below.
        let gps_summary = (namespace == IfdNamespace::Gps && field_type == 5 && count == 3)
            .then(|| read_rationals(data, value_offset, count, big_endian))
            .flatten()
            .and_then(|rationals| match tag {
                0x0002 | 0x0004 | 0x0014 | 0x0016 => gps_dms_summary(&rationals),
                0x0007 => gps_timestamp_summary(&rationals),
                _ => None,
            });

        let summary = gps_summary.or_else(|| {
            exif_value_summary(
                data,
                tiff_start,
                big_endian,
                field_type,
                count,
                value_field_offset,
                total_size,
            )
        });

        // Enum-like fields (Exif SHORT enums, GPS ref/status/mode strings)
        // get a friendly name instead of the raw value, when known.
        let summary = match namespace {
            IfdNamespace::Exif if field_type == 3 && count == 1 => {
                let enum_name = summary
                    .as_ref()
                    .and_then(|value| value.parse::<u16>().ok())
                    .and_then(|numeric| {
                        exif_enum_value(tag, numeric).map(|name| format!("{name} ({numeric})"))
                    });
                enum_name.or(summary)
            }
            IfdNamespace::Gps => {
                let enum_name = summary
                    .as_ref()
                    .and_then(|value| gps_enum_value(tag, value))
                    .map(|name| format!("{name} ({})", summary.as_ref().unwrap()));
                enum_name.or(summary)
            }
            _ => summary,
        };

        let entry_label = match &summary {
            Some(value) => format!("{tag_label}: {value}"),
            None => format!(
                "{tag_label} ({}, count {count})",
                exif_type_name(field_type)
            ),
        };

        let entry_range = ByteRange::new(pos as u64, (pos + 12) as u64);

        let sub_ifd = match (namespace, tag) {
            (IfdNamespace::Exif, 0x8769) => Some(("Exif SubIFD", IfdNamespace::Exif)),
            (IfdNamespace::Exif, 0xA005) => Some(("Interoperability IFD", IfdNamespace::Exif)),
            (IfdNamespace::Exif, 0x8825) => Some(("GPS IFD", IfdNamespace::Gps)),
            _ => None,
        };
        if let (Some((sub_label, sub_namespace)), true) = (sub_ifd, depth < MAX_IFD_DEPTH) {
            if let Some(sub_offset) = read_exif_u32(data, value_field_offset, big_endian) {
                if let Some(sub_ifd_block) = ifd_block(
                    data,
                    tiff_start,
                    sub_offset,
                    big_endian,
                    sub_label,
                    sub_namespace,
                    depth + 1,
                ) {
                    children.push(sub_ifd_block);
                    pos += 12;
                    continue;
                }
            }
        }

        children.push(Block::leaf(entry_label, entry_range));
        pos += 12;
    }

    Some(Block::node(
        label.to_string(),
        ByteRange::new(ifd_start as u64, pos as u64),
        children,
    ))
}

/// Parses an APP1 "Exif\0\0"-prefixed segment: the 6-byte identifier
/// followed by a TIFF header (byte order, magic, IFD0 offset) and IFD0's
/// entries. Falls back to a generic data leaf if the TIFF header is
/// malformed.
fn exif_children(data: &[u8], data_start: u64, data_end: u64) -> Vec<Block> {
    let tiff_start = data_start as usize + EXIF_IDENTIFIER.len();

    let big_endian = match data.get(tiff_start..tiff_start + 2) {
        Some(b"II") => false,
        Some(b"MM") => true,
        _ => return generic_data_children_labeled(data_start, data_end, "Exif data"),
    };

    let Some(magic) = read_exif_u16(data, tiff_start + 2, big_endian) else {
        return generic_data_children_labeled(data_start, data_end, "Exif data");
    };
    if magic != 42 {
        return generic_data_children_labeled(data_start, data_end, "Exif data");
    }
    let Some(ifd0_offset) = read_exif_u32(data, tiff_start + 4, big_endian) else {
        return generic_data_children_labeled(data_start, data_end, "Exif data");
    };

    let mut children = vec![
        Block::leaf(
            "Identifier: Exif",
            ByteRange::new(data_start, data_start + EXIF_IDENTIFIER.len() as u64),
        ),
        Block::leaf(
            format!(
                "Byte order: {}",
                if big_endian {
                    "big-endian (MM)"
                } else {
                    "little-endian (II)"
                }
            ),
            ByteRange::new(tiff_start as u64, tiff_start as u64 + 2),
        ),
    ];

    match ifd_block(
        data,
        tiff_start,
        ifd0_offset,
        big_endian,
        "IFD0",
        IfdNamespace::Exif,
        0,
    ) {
        Some(ifd0) => children.push(ifd0.expanded()),
        None => children.push(Block::leaf(
            "IFD0 (unparseable)",
            ByteRange::new(data_start, data_end),
        )),
    }

    children
}

/// Scans entropy-coded scan data starting at `offset`, stopping just before
/// the next real marker (a 0xFF byte followed by something other than 0x00
/// stuffing or a 0xD0-0xD7 restart marker). Returns the end offset of the
/// scan data (i.e. the start of the next marker, or end of data).
fn scan_data_end(data: &[u8], offset: u64) -> u64 {
    let mut pos = offset as usize;
    while pos < data.len() {
        if data[pos] == 0xFF {
            match data.get(pos + 1) {
                Some(&0x00) => {
                    pos += 2;
                    continue;
                }
                Some(&next) if (0xD0..=0xD7).contains(&next) => {
                    pos += 2;
                    continue;
                }
                Some(_) => return pos as u64,
                None => return pos as u64,
            }
        }
        pos += 1;
    }
    data.len() as u64
}

fn sos_block(data: &[u8], offset: u64) -> Option<Block> {
    let (data_start, header_end) = marker_payload(data, offset)?;

    let off = data_start as usize;
    let mut children = Vec::new();

    let num_components = *data.get(off)?;
    children.push(Block::leaf(
        format!("Number of components: {num_components}"),
        ByteRange::new(data_start, data_start + 1),
    ));

    let mut pos = off + 1;
    for _ in 0..num_components {
        if data.len() < pos + 2 {
            break;
        }
        let selector = data[pos];
        let tables = data[pos + 1];
        let start = pos as u64;
        children.push(Block::node(
            format!("Component {selector}"),
            ByteRange::new(start, start + 2),
            vec![
                Block::leaf(
                    format!("Component selector: {selector}"),
                    ByteRange::new(start, start + 1),
                ),
                Block::leaf(
                    format!("Huffman table selectors: {:#04x}", tables),
                    ByteRange::new(start + 1, start + 2),
                ),
            ],
        ));
        pos += 2;
    }

    if data.len() >= pos + 3 {
        let start = pos as u64;
        children.push(Block::leaf(
            "Spectral selection / approximation",
            ByteRange::new(start, start + 3),
        ));
        pos += 3;
    }

    // pos should line up with header_end, but use whichever is further along
    // defensively in case component parsing stopped early.
    let scan_start = header_end.max(pos as u64);
    let scan_end = scan_data_end(data, scan_start);

    if scan_end > scan_start {
        children.push(Block::leaf(
            "Entropy-coded scan data",
            ByteRange::new(scan_start, scan_end),
        ));
    }

    Some(Block::node(
        "SOS",
        ByteRange::new(offset, scan_end),
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

    /// Builds a minimal synthetic JPEG: SOI, a minimal SOF0 marker (tiny
    /// width/height, 1 component), a minimal SOS marker (1 component) with a
    /// few bytes of fake entropy-coded scan data, then EOI.
    fn build_jpeg() -> Vec<u8> {
        let mut data = Vec::new();

        // SOI
        push_bytes(&mut data, &[0xFF, SOI]);

        // SOF0
        let mut sof = Vec::new();
        sof.push(8); // precision
        push_bytes(&mut sof, &20u16.to_be_bytes()); // height
        push_bytes(&mut sof, &10u16.to_be_bytes()); // width
        sof.push(1); // num components
        sof.push(1); // component id
        sof.push(0x11); // sampling factors
        sof.push(0); // quant table selector

        push_bytes(&mut data, &[0xFF, 0xC0]);
        push_bytes(&mut data, &((sof.len() + 2) as u16).to_be_bytes());
        push_bytes(&mut data, &sof);

        // SOS
        let mut sos = Vec::new();
        sos.push(1); // num components
        sos.push(1); // component selector
        sos.push(0x00); // huffman table selectors
        sos.push(0); // spectral start
        sos.push(63); // spectral end
        sos.push(0); // approximation

        push_bytes(&mut data, &[0xFF, SOS]);
        push_bytes(&mut data, &((sos.len() + 2) as u16).to_be_bytes());
        push_bytes(&mut data, &sos);

        // fake entropy-coded scan data
        push_bytes(&mut data, &[0x12, 0x34, 0x56, 0x78]);

        // EOI
        push_bytes(&mut data, &[0xFF, EOI]);

        data
    }

    #[test]
    fn matches_jpeg_magic() {
        let data = build_jpeg();
        assert!(JpegDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_jpeg_data() {
        assert!(!JpegDissector.matches(b"not a jpeg file"));
        assert!(!JpegDissector.matches(b""));
        assert!(!JpegDissector.matches(&[0xFF, 0xD9]));
    }

    #[test]
    fn dissect_returns_graceful_result_for_truncated_header() {
        let blocks = JpegDissector.dissect(&[0xFF, SOI]);
        assert_eq!(blocks.len(), 1);

        let blocks = JpegDissector.dissect(&[0xFF]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn dissect_parses_full_structure() {
        let data = build_jpeg();
        let blocks = JpegDissector.dissect(&data);

        find_block(&blocks, "SOI");

        let sof = find_block(&blocks, "SOF0 marker");
        assert!(sof.children.iter().any(|b| b.label == "Width: 10"));
        assert!(sof.children.iter().any(|b| b.label == "Height: 20"));
        assert!(sof.default_expanded);

        let sos = find_block(&blocks, "SOS");
        assert!(
            sos.children
                .iter()
                .any(|b| b.label == "Entropy-coded scan data")
        );

        find_block(&blocks, "EOI");
    }

    /// Builds a minimal little-endian Exif APP1 payload (identifier + TIFF
    /// header + IFD0 with a Make ASCII tag and an Orientation SHORT tag, no
    /// next-IFD).
    fn build_exif_app1() -> Vec<u8> {
        let mut tiff = Vec::new();
        push_bytes(&mut tiff, b"II"); // little-endian
        push_bytes(&mut tiff, &42u16.to_le_bytes()); // magic
        push_bytes(&mut tiff, &8u32.to_le_bytes()); // IFD0 offset (right after header)

        let make = b"Acme\0";
        // IFD0 starts at tiff offset 8: 2-byte count, 2 entries * 12 bytes, 4-byte next-IFD offset
        let ifd_start = tiff.len() as u32;
        assert_eq!(ifd_start, 8);
        let make_value_offset = ifd_start + 2 + 2 * 12 + 4;

        push_bytes(&mut tiff, &2u16.to_le_bytes()); // entry count

        // Make (ASCII, count 5, offset since 5 > 4 bytes)
        push_bytes(&mut tiff, &0x010Fu16.to_le_bytes()); // tag
        push_bytes(&mut tiff, &2u16.to_le_bytes()); // type ASCII
        push_bytes(&mut tiff, &(make.len() as u32).to_le_bytes()); // count
        push_bytes(&mut tiff, &make_value_offset.to_le_bytes()); // offset

        // Orientation (SHORT, count 1, inline)
        push_bytes(&mut tiff, &0x0112u16.to_le_bytes()); // tag
        push_bytes(&mut tiff, &3u16.to_le_bytes()); // type SHORT
        push_bytes(&mut tiff, &1u32.to_le_bytes()); // count
        push_bytes(&mut tiff, &1u16.to_le_bytes()); // inline value
        push_bytes(&mut tiff, &0u16.to_le_bytes()); // padding to fill 4-byte field

        push_bytes(&mut tiff, &0u32.to_le_bytes()); // next IFD offset (none)

        push_bytes(&mut tiff, make);

        let mut app1 = Vec::new();
        push_bytes(&mut app1, EXIF_IDENTIFIER);
        push_bytes(&mut app1, &tiff);
        app1
    }

    fn wrap_marker(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        push_bytes(&mut data, &[0xFF, marker]);
        push_bytes(&mut data, &((payload.len() + 2) as u16).to_be_bytes());
        push_bytes(&mut data, payload);
        data
    }

    /// Builds an APP0 JFIF payload: identifier, version 1.02, density units
    /// = pixels per inch, 72x72 density, a tiny 2x1 RGB thumbnail.
    fn build_jfif_app0() -> Vec<u8> {
        let mut app0 = Vec::new();
        push_bytes(&mut app0, JFIF_IDENTIFIER);
        app0.push(1); // major version
        app0.push(2); // minor version
        app0.push(1); // density units: pixels per inch
        push_bytes(&mut app0, &72u16.to_be_bytes()); // x density
        push_bytes(&mut app0, &72u16.to_be_bytes()); // y density
        app0.push(2); // thumbnail width
        app0.push(1); // thumbnail height
        push_bytes(&mut app0, &[0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00]); // 2 RGB pixels
        app0
    }

    #[test]
    fn dissect_parses_jfif_app0_segment() {
        let mut data = Vec::new();
        push_bytes(&mut data, &[0xFF, SOI]);
        push_bytes(&mut data, &wrap_marker(APP0, &build_jfif_app0()));
        push_bytes(&mut data, &[0xFF, EOI]);

        let blocks = JpegDissector.dissect(&data);
        let app0 = find_block(&blocks, "APP0 marker (JFIF)");
        assert!(app0.default_expanded);

        assert!(app0.children.iter().any(|b| b.label == "Version: 1.02"));
        assert!(
            app0.children
                .iter()
                .any(|b| b.label == "Density units: Pixels per inch (1)")
        );
        assert!(app0.children.iter().any(|b| b.label == "X density: 72"));
        assert!(app0.children.iter().any(|b| b.label == "Y density: 72"));
        assert!(
            app0.children
                .iter()
                .any(|b| b.label == "Thumbnail width: 2")
        );

        let thumbnail = app0
            .children
            .iter()
            .find(|b| b.label == "Thumbnail data (RGB)")
            .expect("thumbnail data block");
        assert_eq!(thumbnail.range.end - thumbnail.range.start, 6); // 2x1 RGB pixels
    }

    #[test]
    fn does_not_treat_non_jfif_app0_as_jfif() {
        let mut data = Vec::new();
        push_bytes(&mut data, &[0xFF, SOI]);
        push_bytes(&mut data, &wrap_marker(APP0, b"not jfif"));
        push_bytes(&mut data, &[0xFF, EOI]);

        let blocks = JpegDissector.dissect(&data);
        let app0 = find_block(&blocks, "APP0 marker");
        assert!(!app0.default_expanded);
        assert!(app0.children.iter().any(|b| b.label == "Data"));
    }

    #[test]
    fn dissect_parses_exif_app1_segment() {
        let mut data = Vec::new();
        push_bytes(&mut data, &[0xFF, SOI]);
        push_bytes(&mut data, &wrap_marker(APP1, &build_exif_app1()));
        push_bytes(&mut data, &[0xFF, EOI]);

        let blocks = JpegDissector.dissect(&data);
        let app1 = find_block(&blocks, "APP1 marker (Exif)");
        assert!(app1.default_expanded);

        let ifd0 = find_block(&app1.children, "IFD0");
        assert!(ifd0.children.iter().any(|b| b.label == "Make: Acme"));
        assert!(
            ifd0.children
                .iter()
                .any(|b| b.label == "Orientation: Horizontal (normal) (1)")
        );
    }

    /// Builds a minimal little-endian Exif APP1 payload whose IFD0 contains
    /// only a GPS IFD pointer, and whose GPS IFD has GPSLatitudeRef ("N",
    /// inline ASCII) and GPSLatitude (37 deg, 25 min, 19.07 sec, offset
    /// RATIONAL[3]).
    fn build_gps_exif_app1() -> Vec<u8> {
        let mut tiff = Vec::new();
        push_bytes(&mut tiff, b"II");
        push_bytes(&mut tiff, &42u16.to_le_bytes());
        push_bytes(&mut tiff, &8u32.to_le_bytes()); // IFD0 offset

        let ifd0_start = tiff.len() as u32;
        assert_eq!(ifd0_start, 8);
        let gps_ifd_offset = ifd0_start + 2 + 12 + 4;

        push_bytes(&mut tiff, &1u16.to_le_bytes()); // IFD0 entry count

        // GPS IFD pointer (LONG, count 1, inline offset)
        push_bytes(&mut tiff, &0x8825u16.to_le_bytes());
        push_bytes(&mut tiff, &4u16.to_le_bytes());
        push_bytes(&mut tiff, &1u32.to_le_bytes());
        push_bytes(&mut tiff, &gps_ifd_offset.to_le_bytes());

        push_bytes(&mut tiff, &0u32.to_le_bytes()); // IFD0 next-IFD offset (none)
        assert_eq!(tiff.len() as u32, gps_ifd_offset);

        let gps_ifd_start = tiff.len() as u32;
        let latitude_value_offset = gps_ifd_start + 2 + 2 * 12 + 4;

        push_bytes(&mut tiff, &2u16.to_le_bytes()); // GPS IFD entry count

        // GPSLatitudeRef (ASCII, count 2, inline "N\0")
        push_bytes(&mut tiff, &0x0001u16.to_le_bytes());
        push_bytes(&mut tiff, &2u16.to_le_bytes());
        push_bytes(&mut tiff, &2u32.to_le_bytes());
        push_bytes(&mut tiff, b"N\0\0\0");

        // GPSLatitude (RATIONAL, count 3, offset)
        push_bytes(&mut tiff, &0x0002u16.to_le_bytes());
        push_bytes(&mut tiff, &5u16.to_le_bytes());
        push_bytes(&mut tiff, &3u32.to_le_bytes());
        push_bytes(&mut tiff, &latitude_value_offset.to_le_bytes());

        push_bytes(&mut tiff, &0u32.to_le_bytes()); // GPS IFD next-IFD offset (none)
        assert_eq!(tiff.len() as u32, latitude_value_offset);

        // 37 deg, 25 min, 19.07 sec
        push_bytes(&mut tiff, &37u32.to_le_bytes());
        push_bytes(&mut tiff, &1u32.to_le_bytes());
        push_bytes(&mut tiff, &25u32.to_le_bytes());
        push_bytes(&mut tiff, &1u32.to_le_bytes());
        push_bytes(&mut tiff, &1907u32.to_le_bytes());
        push_bytes(&mut tiff, &100u32.to_le_bytes());

        let mut app1 = Vec::new();
        push_bytes(&mut app1, EXIF_IDENTIFIER);
        push_bytes(&mut app1, &tiff);
        app1
    }

    #[test]
    fn dissect_parses_gps_ifd() {
        let mut data = Vec::new();
        push_bytes(&mut data, &[0xFF, SOI]);
        push_bytes(&mut data, &wrap_marker(APP1, &build_gps_exif_app1()));
        push_bytes(&mut data, &[0xFF, EOI]);

        let blocks = JpegDissector.dissect(&data);
        let app1 = find_block(&blocks, "APP1 marker (Exif)");
        let ifd0 = find_block(&app1.children, "IFD0");
        let gps = find_block(&ifd0.children, "GPS IFD");
        assert!(!gps.default_expanded);

        assert!(
            gps.children
                .iter()
                .any(|b| b.label == "GPSLatitudeRef: North (N)")
        );

        let latitude = gps
            .children
            .iter()
            .find(|b| b.label.starts_with("GPSLatitude:"))
            .expect("GPSLatitude entry");
        assert!(latitude.label.contains("37"));
        assert!(latitude.label.contains("37.421964"));
    }

    #[test]
    fn gps_tag_names_and_enum_values_resolve() {
        assert_eq!(gps_tag_name(0x0001), "GPSLatitudeRef");
        assert_eq!(gps_tag_name(0x0007), "GPSTimeStamp");
        assert_eq!(gps_tag_name(0xFFFF), "");
        assert_eq!(gps_enum_value(0x0001, "N"), Some("North"));
        assert_eq!(gps_enum_value(0x0003, "W"), Some("West"));
        assert_eq!(gps_enum_value(0x0005, "1"), Some("Below sea level"));
        assert_eq!(gps_enum_value(0x0009, "A"), Some("Measurement in progress"));
    }

    #[test]
    fn exif_enum_values_decode_known_fields() {
        assert_eq!(exif_enum_value(0x0112, 1), Some("Horizontal (normal)"));
        assert_eq!(exif_enum_value(0x0112, 6), Some("Rotated 90 CW (Vertical)"));
        assert_eq!(exif_enum_value(0x0128, 2), Some("Inches"));
        assert_eq!(exif_enum_value(0x0128, 3), Some("Centimeters"));
        assert_eq!(exif_enum_value(0x9209, 0x00), Some("No flash"));
        assert_eq!(exif_enum_value(0x0112, 200), None);
    }

    #[test]
    fn exif_tag_names_cover_extended_registry() {
        assert_eq!(exif_tag_name(0x9010), "OffsetTime");
        assert_eq!(exif_tag_name(0x9011), "OffsetTimeOriginal");
        assert_eq!(exif_tag_name(0x9012), "OffsetTimeDigitized");
        assert_eq!(exif_tag_name(0xA432), "LensSpecification");
        assert_eq!(exif_tag_name(0xA005), "Interoperability IFD pointer");
        assert_eq!(exif_tag_name(0xFFFF), "");
    }

    #[test]
    fn identify_reports_jpeg() {
        let data = build_jpeg();
        assert_eq!(super::super::identify(&data), "JPEG");
    }
}
