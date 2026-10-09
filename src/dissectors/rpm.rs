use super::{Block, ByteRange, Dissector};

const RPM_MAGIC: &[u8] = &[0xED, 0xAB, 0xEE, 0xDB];
const HEADER_MAGIC: &[u8] = &[0x8E, 0xAD, 0xE8];

const LEAD_LEN: usize = 96;
const LEAD_NAME_LEN: usize = 66;
const HEADER_INTRO_LEN: usize = 16;
const INDEX_ENTRY_LEN: usize = 16;

/// Most index entries shown per header; the rest are summarised in one block.
const MAX_ENTRIES: usize = 256;
/// Most array elements decoded into a label.
const MAX_ARRAY_ITEMS: usize = 3;
/// Longest BIN value shown as hex in a label.
const MAX_HEX_BYTES: usize = 32;
/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;

const TYPE_NULL: u32 = 0;
const TYPE_CHAR: u32 = 1;
const TYPE_INT8: u32 = 2;
const TYPE_INT16: u32 = 3;
const TYPE_INT32: u32 = 4;
const TYPE_INT64: u32 = 5;
const TYPE_STRING: u32 = 6;
const TYPE_BIN: u32 = 7;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

pub struct RpmDissector;

impl Dissector for RpmDissector {
    fn name(&self) -> &'static str {
        "RPM"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= LEAD_LEN && data.starts_with(RPM_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < LEAD_LEN {
            return blocks;
        }
        blocks.push(lead_block(data));

        let Some(sig) = parse_header(data, LEAD_LEN) else {
            if data.len() > LEAD_LEN {
                blocks.push(Block::leaf("Unparsed data", span(LEAD_LEN, data.len())));
            }
            return blocks;
        };
        blocks.push(header_block(data, &sig, "Signature header", sig_tag_name));

        let mut pos = sig.end;
        if pos > data.len() {
            return blocks;
        }
        let padded = pos.next_multiple_of(8);
        if padded > pos && pos < data.len() {
            let pad_end = padded.min(data.len());
            blocks.push(Block::leaf(
                format!("Signature padding ({} bytes)", padded - pos),
                span(pos, pad_end),
            ));
            pos = padded;
        }
        if pos >= data.len() {
            return blocks;
        }

        let Some(main) = parse_header(data, pos) else {
            blocks.push(Block::leaf("Unparsed data", span(pos, data.len())));
            return blocks;
        };
        blocks.push(header_block(data, &main, "Header", header_tag_name));

        let payload_start = main.end;
        if payload_start < data.len() {
            let payload = &data[payload_start..];
            let compressor = main
                .string_value(data, TAG_PAYLOADCOMPRESSOR)
                .or_else(|| sniff_compressor(payload).map(str::to_string))
                .unwrap_or_else(|| "unknown compression".to_string());
            let label = match main.string_value(data, TAG_PAYLOADFORMAT) {
                Some(format) => format!(
                    "Payload ({}, {}, {} bytes)",
                    display(&format),
                    display(&compressor),
                    payload.len()
                ),
                None => format!(
                    "Payload ({}, {} bytes)",
                    display(&compressor),
                    payload.len()
                ),
            };
            blocks.push(Block::leaf(label, span(payload_start, data.len())));
        }

        blocks
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64_be(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn display(text: &str) -> String {
    let single_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = single_line.trim();
    if trimmed.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = trimmed.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        trimmed.to_string()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn package_type_name(value: u16) -> &'static str {
    match value {
        0 => "binary",
        1 => "source",
        _ => "unknown",
    }
}

fn os_name(value: u16) -> &'static str {
    match value {
        1 => "Linux",
        _ => "unknown",
    }
}

fn signature_type_name(value: u16) -> &'static str {
    match value {
        5 => "header-style",
        _ => "unknown",
    }
}

fn type_name(value: u32) -> &'static str {
    match value {
        TYPE_NULL => "NULL",
        TYPE_CHAR => "CHAR",
        TYPE_INT8 => "INT8",
        TYPE_INT16 => "INT16",
        TYPE_INT32 => "INT32",
        TYPE_INT64 => "INT64",
        TYPE_STRING => "STRING",
        TYPE_BIN => "BIN",
        TYPE_STRING_ARRAY => "STRING_ARRAY",
        TYPE_I18NSTRING => "I18NSTRING",
        _ => "unknown",
    }
}

fn region_tag_name(tag: u32) -> Option<&'static str> {
    match tag {
        61 => Some("HEADERIMAGE"),
        62 => Some("HEADERSIGNATURES"),
        63 => Some("HEADERIMMUTABLE"),
        64 => Some("HEADERREGIONS"),
        100 => Some("HEADERI18NTABLE"),
        _ => None,
    }
}

fn sig_tag_name(tag: u32) -> Option<&'static str> {
    if let Some(name) = region_tag_name(tag) {
        return Some(name);
    }
    Some(match tag {
        264 => "BADSHA1_1",
        265 => "BADSHA1_2",
        266 => "PUBKEYS",
        267 => "DSA",
        268 => "RSA",
        269 => "SHA1",
        270 => "LONGSIZE",
        271 => "LONGARCHIVESIZE",
        273 => "SHA256",
        274 => "FILESIGNATURES",
        275 => "FILESIGNATURELENGTH",
        276 => "VERITYSIGNATURES",
        277 => "VERITYSIGNATUREALGO",
        278 => "OPENPGP",
        279 => "SHA3_256",
        999 => "RESERVED",
        1000 => "SIZE",
        1001 => "LEMD5_1",
        1002 => "PGP",
        1003 => "LEMD5_2",
        1004 => "MD5",
        1005 => "GPG",
        1006 => "PGP5",
        1007 => "PAYLOADSIZE",
        1008 => "RESERVEDSPACE",
        _ => return None,
    })
}

fn header_tag_name(tag: u32) -> Option<&'static str> {
    if let Some(name) = region_tag_name(tag) {
        return Some(name);
    }
    Some(match tag {
        1000 => "NAME",
        1001 => "VERSION",
        1002 => "RELEASE",
        1003 => "EPOCH",
        1004 => "SUMMARY",
        1005 => "DESCRIPTION",
        1006 => "BUILDTIME",
        1007 => "BUILDHOST",
        1008 => "INSTALLTIME",
        1009 => "SIZE",
        1010 => "DISTRIBUTION",
        1011 => "VENDOR",
        1012 => "GIF",
        1013 => "XPM",
        1014 => "LICENSE",
        1015 => "PACKAGER",
        1016 => "GROUP",
        1017 => "CHANGELOG",
        1018 => "SOURCE",
        1019 => "PATCH",
        1020 => "URL",
        1021 => "OS",
        1022 => "ARCH",
        1023 => "PREIN",
        1024 => "POSTIN",
        1025 => "PREUN",
        1026 => "POSTUN",
        1027 => "OLDFILENAMES",
        1028 => "FILESIZES",
        1029 => "FILESTATES",
        1030 => "FILEMODES",
        1031 => "FILEUIDS",
        1032 => "FILEGIDS",
        1033 => "FILERDEVS",
        1034 => "FILEMTIMES",
        1035 => "FILEDIGESTS",
        1036 => "FILELINKTOS",
        1037 => "FILEFLAGS",
        1038 => "ROOT",
        1039 => "FILEUSERNAME",
        1040 => "FILEGROUPNAME",
        1043 => "ICON",
        1044 => "SOURCERPM",
        1045 => "FILEVERIFYFLAGS",
        1046 => "ARCHIVESIZE",
        1047 => "PROVIDENAME",
        1048 => "REQUIREFLAGS",
        1049 => "REQUIRENAME",
        1050 => "REQUIREVERSION",
        1051 => "NOSOURCE",
        1052 => "NOPATCH",
        1053 => "CONFLICTFLAGS",
        1054 => "CONFLICTNAME",
        1055 => "CONFLICTVERSION",
        1059 => "EXCLUDEARCH",
        1060 => "EXCLUDEOS",
        1061 => "EXCLUSIVEARCH",
        1062 => "EXCLUSIVEOS",
        1064 => "RPMVERSION",
        1065 => "TRIGGERSCRIPTS",
        1066 => "TRIGGERNAME",
        1067 => "TRIGGERVERSION",
        1068 => "TRIGGERFLAGS",
        1069 => "TRIGGERINDEX",
        1079 => "VERIFYSCRIPT",
        1080 => "CHANGELOGTIME",
        1081 => "CHANGELOGNAME",
        1082 => "CHANGELOGTEXT",
        1085 => "PREINPROG",
        1086 => "POSTINPROG",
        1087 => "PREUNPROG",
        1088 => "POSTUNPROG",
        1089 => "BUILDARCHS",
        1090 => "OBSOLETENAME",
        1091 => "VERIFYSCRIPTPROG",
        1092 => "TRIGGERSCRIPTPROG",
        1094 => "COOKIE",
        1095 => "FILEDEVICES",
        1096 => "FILEINODES",
        1097 => "FILELANGS",
        1098 => "PREFIXES",
        1099 => "INSTPREFIXES",
        1106 => "SOURCEPACKAGE",
        1112 => "PROVIDEFLAGS",
        1113 => "PROVIDEVERSION",
        1114 => "OBSOLETEFLAGS",
        1115 => "OBSOLETEVERSION",
        1116 => "DIRINDEXES",
        1117 => "BASENAMES",
        1118 => "DIRNAMES",
        1122 => "OPTFLAGS",
        1123 => "DISTURL",
        1124 => "PAYLOADFORMAT",
        1125 => "PAYLOADCOMPRESSOR",
        1126 => "PAYLOADFLAGS",
        1127 => "INSTALLCOLOR",
        1128 => "INSTALLTID",
        1129 => "REMOVETID",
        1131 => "RHNPLATFORM",
        1132 => "PLATFORM",
        1140 => "FILECOLORS",
        1141 => "FILECLASS",
        1142 => "CLASSDICT",
        1143 => "FILEDEPENDSX",
        1144 => "FILEDEPENDSN",
        1145 => "DEPENDSDICT",
        1146 => "SOURCEPKGID",
        1147 => "FILECONTEXTS",
        1151 => "PRETRANS",
        1152 => "POSTTRANS",
        1153 => "PRETRANSPROG",
        1154 => "POSTTRANSPROG",
        1155 => "DISTTAG",
        5008 => "LONGFILESIZES",
        5009 => "LONGSIZE",
        5010 => "FILECAPS",
        5011 => "FILEDIGESTALGO",
        5012 => "BUGURL",
        5017 => "HEADERCOLOR",
        5020 => "PREINFLAGS",
        5021 => "POSTINFLAGS",
        5022 => "PREUNFLAGS",
        5023 => "POSTUNFLAGS",
        5024 => "PRETRANSFLAGS",
        5025 => "POSTTRANSFLAGS",
        5034 => "VCS",
        5035 => "ORDERNAME",
        5036 => "ORDERVERSION",
        5037 => "ORDERFLAGS",
        5046 => "RECOMMENDNAME",
        5047 => "RECOMMENDVERSION",
        5048 => "RECOMMENDFLAGS",
        5049 => "SUGGESTNAME",
        5050 => "SUGGESTVERSION",
        5051 => "SUGGESTFLAGS",
        5052 => "SUPPLEMENTNAME",
        5053 => "SUPPLEMENTVERSION",
        5054 => "SUPPLEMENTFLAGS",
        5055 => "ENHANCENAME",
        5056 => "ENHANCEVERSION",
        5057 => "ENHANCEFLAGS",
        5062 => "ENCODING",
        5066 => "FILETRIGGERSCRIPTS",
        5067 => "FILETRIGGERSCRIPTPROG",
        5068 => "FILETRIGGERSCRIPTFLAGS",
        5069 => "FILETRIGGERNAME",
        5070 => "FILETRIGGERINDEX",
        5071 => "FILETRIGGERVERSION",
        5072 => "FILETRIGGERFLAGS",
        5090 => "FILESIGNATURES",
        5091 => "FILESIGNATURELENGTH",
        5092 => "PAYLOADDIGEST",
        5093 => "PAYLOADDIGESTALGO",
        5096 => "MODULARITYLABEL",
        5097 => "PAYLOADDIGESTALT",
        5098 => "ARCHSUFFIX",
        5099 => "SPEC",
        5100 => "TRANSLATIONURL",
        5101 => "UPSTREAMRELEASES",
        5109 => "SYSUSERS",
        5112 => "PAYLOADSIZE",
        5113 => "PAYLOADSIZEALT",
        5114 => "RPMFORMAT",
        5118 => "PACKAGEDIGESTS",
        5119 => "PACKAGEDIGESTALGOS",
        5120 => "SOURCENEVR",
        _ => return None,
    })
}

fn tag_label(tag: u32, names: fn(u32) -> Option<&'static str>) -> String {
    match names(tag) {
        Some(name) => name.to_string(),
        None => format!("Tag {tag}"),
    }
}

fn sniff_compressor(payload: &[u8]) -> Option<&'static str> {
    if payload.starts_with(&[0x1F, 0x8B]) {
        Some("gzip")
    } else if payload.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if payload.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Some("zstd")
    } else if payload.starts_with(b"BZh") {
        Some("bzip2")
    } else if payload.starts_with(&[0x5D, 0x00, 0x00]) {
        Some("lzma")
    } else if payload.starts_with(b"070701") || payload.starts_with(b"070702") {
        Some("uncompressed")
    } else {
        None
    }
}

fn lead_block(data: &[u8]) -> Block {
    let major = read_u8(data, 4).unwrap_or(0);
    let minor = read_u8(data, 5).unwrap_or(0);
    let kind = read_u16_be(data, 6).unwrap_or(0);
    let arch = read_u16_be(data, 8).unwrap_or(0);
    let name_bytes = &data[10..10 + LEAD_NAME_LEN];
    let name_len = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(LEAD_NAME_LEN);
    let name = String::from_utf8_lossy(&name_bytes[..name_len]);
    let os = read_u16_be(data, 76).unwrap_or(0);
    let sig_type = read_u16_be(data, 78).unwrap_or(0);

    Block::node(
        "Lead",
        span(0, LEAD_LEN),
        vec![
            Block::leaf("Magic: ED AB EE DB", span(0, 4)),
            Block::leaf(format!("Version: {major}.{minor}"), span(4, 6)),
            Block::leaf(
                format!("Type: {} ({kind})", package_type_name(kind)),
                span(6, 8),
            ),
            Block::leaf(format!("Arch number: {arch}"), span(8, 10)),
            Block::leaf(format!("Name: {}", display(&name)), span(10, 76)),
            Block::leaf(format!("OS number: {} ({os})", os_name(os)), span(76, 78)),
            Block::leaf(
                format!(
                    "Signature type: {} ({sig_type})",
                    signature_type_name(sig_type)
                ),
                span(78, 80),
            ),
            Block::leaf("Reserved", span(80, LEAD_LEN)),
        ],
    )
    .expanded()
}

#[derive(Clone, Copy)]
struct Entry {
    tag: u32,
    kind: u32,
    offset: u32,
    count: u32,
}

struct Header {
    start: usize,
    /// Number of index entries declared in the header.
    declared: u32,
    store_size: u32,
    /// Index entries present in the file (not capped).
    entries: Vec<Entry>,
    store_start: usize,
    /// Declared end of the data store, which may lie past the end of the file.
    end: usize,
}

impl Header {
    fn store<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let end = self.end.min(data.len());
        data.get(self.store_start..end).unwrap_or(&[])
    }

    fn string_value(&self, data: &[u8], tag: u32) -> Option<String> {
        let entry = self.entries.iter().find(|e| e.tag == tag)?;
        if !matches!(
            entry.kind,
            TYPE_STRING | TYPE_I18NSTRING | TYPE_STRING_ARRAY
        ) {
            return None;
        }
        let strings = read_strings(self.store(data), entry.offset as usize, 1);
        strings.into_iter().next()
    }
}

fn parse_header(data: &[u8], start: usize) -> Option<Header> {
    if data.get(start..start + 3)? != HEADER_MAGIC {
        return None;
    }
    let declared = read_u32_be(data, start + 8)?;
    let store_size = read_u32_be(data, start + 12)?;
    let index_start = start + HEADER_INTRO_LEN;
    let index_end = index_start.saturating_add((declared as usize).saturating_mul(INDEX_ENTRY_LEN));
    let store_start = index_end;
    let end = store_start.saturating_add(store_size as usize);

    let available = data.len().saturating_sub(index_start) / INDEX_ENTRY_LEN;
    let present = (declared as usize).min(available);
    let entries = (0..present)
        .filter_map(|i| {
            let off = index_start + i * INDEX_ENTRY_LEN;
            Some(Entry {
                tag: read_u32_be(data, off)?,
                kind: read_u32_be(data, off + 4)?,
                offset: read_u32_be(data, off + 8)?,
                count: read_u32_be(data, off + 12)?,
            })
        })
        .collect();

    Some(Header {
        start,
        declared,
        store_size,
        entries,
        store_start,
        end,
    })
}

/// Reads up to `count` NUL-terminated strings starting at `offset` in `store`.
fn read_strings(store: &[u8], offset: usize, count: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut pos = offset;
    while strings.len() < count && pos < store.len() {
        let rest = &store[pos..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        strings.push(String::from_utf8_lossy(&rest[..len]).into_owned());
        pos += len + 1;
    }
    strings
}

/// Byte range of an entry's value relative to the data store, clamped to it.
fn entry_extent(store: &[u8], entry: &Entry) -> Option<(usize, usize)> {
    let start = entry.offset as usize;
    if start >= store.len() {
        return None;
    }
    let count = entry.count as usize;
    let len = match entry.kind {
        TYPE_NULL => 0,
        TYPE_CHAR | TYPE_INT8 | TYPE_BIN => count,
        TYPE_INT16 => count.saturating_mul(2),
        TYPE_INT32 => count.saturating_mul(4),
        TYPE_INT64 => count.saturating_mul(8),
        TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING => {
            let wanted = if entry.kind == TYPE_STRING { 1 } else { count };
            let mut pos = start;
            let mut seen = 0;
            while seen < wanted && pos < store.len() {
                let len = store[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(store.len() - pos, |n| n + 1);
                pos += len;
                seen += 1;
            }
            pos - start
        }
        _ => return None,
    };
    if len == 0 {
        return None;
    }
    Some((start, start.saturating_add(len).min(store.len())))
}

fn format_list(items: Vec<String>, total: usize) -> String {
    if total == 1 && items.len() == 1 {
        return items.into_iter().next().unwrap_or_default();
    }
    let mut out = format!("[{}", items.join(", "));
    if total > items.len() {
        out.push_str(", …");
    }
    out.push_str(&format!("] ({total} items)"));
    out
}

fn decode_value(store: &[u8], entry: &Entry) -> Option<String> {
    let start = entry.offset as usize;
    if start >= store.len() {
        return None;
    }
    let count = entry.count as usize;
    let shown = count.min(MAX_ARRAY_ITEMS);
    let ints = |size: usize| -> Option<String> {
        let items: Vec<String> = (0..shown)
            .map_while(|i| {
                let off = start.checked_add(i.checked_mul(size)?)?;
                match size {
                    1 => read_u8(store, off).map(|v| v.to_string()),
                    2 => read_u16_be(store, off).map(|v| v.to_string()),
                    4 => read_u32_be(store, off).map(|v| v.to_string()),
                    _ => read_u64_be(store, off).map(|v| v.to_string()),
                }
            })
            .collect();
        if items.is_empty() {
            None
        } else {
            Some(format_list(items, count))
        }
    };
    let value = match entry.kind {
        TYPE_NULL => return None,
        TYPE_CHAR => {
            let end = start.saturating_add(count).min(store.len());
            String::from_utf8_lossy(&store[start..end]).into_owned()
        }
        TYPE_INT8 => ints(1)?,
        TYPE_INT16 => ints(2)?,
        TYPE_INT32 => ints(4)?,
        TYPE_INT64 => ints(8)?,
        TYPE_STRING => read_strings(store, start, 1).into_iter().next()?,
        TYPE_STRING_ARRAY | TYPE_I18NSTRING => {
            let items = read_strings(store, start, shown);
            if items.is_empty() {
                return None;
            }
            if entry.kind == TYPE_I18NSTRING || count == 1 {
                // I18N strings hold one translation per locale; show the first.
                items.into_iter().next()?
            } else {
                let quoted = items.iter().map(|s| format!("\"{s}\"")).collect();
                format_list(quoted, count)
            }
        }
        TYPE_BIN => {
            if count <= MAX_HEX_BYTES && start + count <= store.len() {
                hex(&store[start..start + count])
            } else {
                format!("{count} bytes")
            }
        }
        _ => return None,
    };
    Some(display(&value))
}

fn header_block(
    data: &[u8],
    header: &Header,
    title: &str,
    names: fn(u32) -> Option<&'static str>,
) -> Block {
    let start = header.start;
    let data_len = data.len();
    let mut children = vec![
        Block::leaf("Magic: 8E AD E8", span(start, start + 3)),
        Block::leaf(
            format!("Header version: {}", read_u8(data, start + 3).unwrap_or(0)),
            span(start + 3, start + 4),
        ),
        Block::leaf("Reserved", span(start + 4, start + 8)),
        Block::leaf(
            format!("Index entry count: {}", header.declared),
            span(start + 8, start + 12),
        ),
        Block::leaf(
            format!("Data store size: {}", header.store_size),
            span(start + 12, start + 16),
        ),
    ];

    let store = header.store(data);
    let index_start = start + HEADER_INTRO_LEN;
    let shown = header.entries.len().min(MAX_ENTRIES);

    if !header.entries.is_empty() {
        let mut entry_blocks: Vec<Block> = header.entries[..shown]
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let off = index_start + i * INDEX_ENTRY_LEN;
                let name = tag_label(entry.tag, names);
                let label = match decode_value(store, entry) {
                    Some(value) => format!("{name}: {value}"),
                    None => name,
                };
                Block::node(
                    label,
                    span(off, off + INDEX_ENTRY_LEN),
                    vec![
                        Block::leaf(
                            format!("Tag: {} ({})", entry.tag, tag_label(entry.tag, names)),
                            span(off, off + 4),
                        ),
                        Block::leaf(
                            format!("Type: {} ({})", type_name(entry.kind), entry.kind),
                            span(off + 4, off + 8),
                        ),
                        Block::leaf(format!("Offset: {}", entry.offset), span(off + 8, off + 12)),
                        Block::leaf(format!("Count: {}", entry.count), span(off + 12, off + 16)),
                    ],
                )
            })
            .collect();
        let index_end = (header.store_start).min(data_len);
        let shown_end = index_start + shown * INDEX_ENTRY_LEN;
        if index_end > shown_end {
            let more = header.declared as usize - shown;
            entry_blocks.push(Block::leaf(
                format!("… {more} more entries"),
                span(shown_end, index_end),
            ));
        }
        children.push(
            Block::node(
                format!("Index ({} entries)", header.declared),
                span(index_start, index_end),
                entry_blocks,
            )
            .expanded(),
        );
    }

    if !store.is_empty() {
        let mut values: Vec<(usize, usize, String)> = header.entries[..shown]
            .iter()
            .filter_map(|entry| {
                let (s, e) = entry_extent(store, entry)?;
                Some((s, e, tag_label(entry.tag, names)))
            })
            .collect();
        values.sort_by_key(|&(s, e, _)| (s, e));
        let base = header.store_start;
        let value_blocks = values
            .into_iter()
            .map(|(s, e, name)| Block::leaf(name, span(base + s, base + e)))
            .collect();
        children.push(Block::node(
            format!("Data store ({} bytes)", header.store_size),
            span(base, base + store.len()),
            value_blocks,
        ));
    }

    Block::node(title, span(start, header.end.min(data_len)), children).expanded()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_lead(name: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(RPM_MAGIC);
        data.extend_from_slice(&[3, 0]); // version 3.0
        data.extend_from_slice(&0u16.to_be_bytes()); // binary
        data.extend_from_slice(&1u16.to_be_bytes()); // archnum
        let mut name_field = [0u8; LEAD_NAME_LEN];
        name_field[..name.len()].copy_from_slice(name.as_bytes());
        data.extend_from_slice(&name_field);
        data.extend_from_slice(&1u16.to_be_bytes()); // osnum
        data.extend_from_slice(&5u16.to_be_bytes()); // signature type
        data.extend_from_slice(&[0u8; 16]);
        assert_eq!(data.len(), LEAD_LEN);
        data
    }

    enum Value<'a> {
        Int32(u32),
        Str(&'a str),
        Bin(&'a [u8]),
        StrArray(&'a [&'a str]),
    }

    fn build_header(entries: &[(u32, Value)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store: Vec<u8> = Vec::new();
        for (tag, value) in entries {
            let (kind, count) = match value {
                Value::Int32(_) => {
                    while store.len() % 4 != 0 {
                        store.push(0);
                    }
                    (TYPE_INT32, 1)
                }
                Value::Str(_) => (TYPE_STRING, 1),
                Value::Bin(b) => (TYPE_BIN, b.len() as u32),
                Value::StrArray(a) => (TYPE_STRING_ARRAY, a.len() as u32),
            };
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&kind.to_be_bytes());
            index.extend_from_slice(&(store.len() as u32).to_be_bytes());
            index.extend_from_slice(&count.to_be_bytes());
            match value {
                Value::Int32(v) => store.extend_from_slice(&v.to_be_bytes()),
                Value::Str(s) => {
                    store.extend_from_slice(s.as_bytes());
                    store.push(0);
                }
                Value::Bin(b) => store.extend_from_slice(b),
                Value::StrArray(a) => {
                    for s in *a {
                        store.extend_from_slice(s.as_bytes());
                        store.push(0);
                    }
                }
            }
        }
        let mut data = vec![0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];
        data.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        data.extend_from_slice(&(store.len() as u32).to_be_bytes());
        data.extend_from_slice(&index);
        data.extend_from_slice(&store);
        data
    }

    /// Returns the file plus the offsets where the signature header, main
    /// header and payload start.
    fn build_rpm(payload: &[u8], compressor: Option<&str>) -> (Vec<u8>, usize, usize, usize) {
        let mut data = build_lead("hello-1.0-1");
        let sig_start = data.len();
        data.extend_from_slice(&build_header(&[
            (1000, Value::Int32(1234)),
            (1004, Value::Bin(&[0xAB; 16])),
            (273, Value::Str("deadbeef")),
        ]));
        while data.len() % 8 != 0 {
            data.push(0);
        }
        let main_start = data.len();
        let mut main = vec![
            (1000, Value::Str("hello")),
            (1001, Value::Str("1.0")),
            (1022, Value::Str("x86_64")),
            (1047, Value::StrArray(&["hello", "hello(x86-64)"])),
            (1124, Value::Str("cpio")),
        ];
        if let Some(c) = compressor {
            main.push((1125, Value::Str(c)));
        }
        data.extend_from_slice(&build_header(&main));
        let payload_start = data.len();
        data.extend_from_slice(payload);
        (data, sig_start, main_start, payload_start)
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    const XZ_PAYLOAD: &[u8] = &[0xFD, b'7', b'z', b'X', b'Z', 0x00, 1, 2, 3];

    #[test]
    fn matches_rpm_magic() {
        let (data, ..) = build_rpm(XZ_PAYLOAD, None);
        assert!(RpmDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_rpm_data() {
        assert!(!RpmDissector.matches(b""));
        assert!(!RpmDissector.matches(b"not an rpm package at all"));
        assert!(!RpmDissector.matches(RPM_MAGIC));
        let lead = build_lead("x");
        assert!(!RpmDissector.matches(&lead[..LEAD_LEN - 1]));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let (data, ..) = build_rpm(XZ_PAYLOAD, Some("xz"));
        let full = RpmDissector.dissect(&data).len();
        for len in 0..data.len() {
            let blocks = RpmDissector.dissect(&data[..len]);
            assert!(blocks.len() <= full);
        }
        assert!(RpmDissector.dissect(&data[..50]).is_empty());
    }

    #[test]
    fn dissect_parses_lead() {
        let (data, ..) = build_rpm(XZ_PAYLOAD, None);
        let blocks = RpmDissector.dissect(&data);
        let lead = find_block(&blocks, "Lead");
        assert_eq!(lead.range, ByteRange::new(0, 96));
        let c = &lead.children;
        assert_eq!(
            find_block(c, "Magic: ED AB EE DB").range,
            ByteRange::new(0, 4)
        );
        find_block(c, "Version: 3.0");
        find_block(c, "Type: binary (0)");
        find_block(c, "Arch number: 1");
        assert_eq!(
            find_block(c, "Name: hello-1.0-1").range,
            ByteRange::new(10, 76)
        );
        find_block(c, "OS number: Linux (1)");
        find_block(c, "Signature type: header-style (5)");
        assert_eq!(find_block(c, "Reserved").range, ByteRange::new(80, 96));
    }

    #[test]
    fn dissect_parses_signature_header_and_padding() {
        let (data, sig_start, main_start, _) = build_rpm(XZ_PAYLOAD, None);
        let blocks = RpmDissector.dissect(&data);
        // 16 intro + 3*16 index + 4 + 16 + 9 store = 93 bytes.
        let sig_end = sig_start + 93;
        let sig = find_block(&blocks, "Signature header");
        assert_eq!(sig.range, ByteRange::new(sig_start as u64, sig_end as u64));
        let c = &sig.children;
        find_block(c, "Index entry count: 3");
        find_block(c, "Data store size: 29");

        let index = find_block(c, "Index (3 entries)");
        assert_eq!(
            index.range,
            ByteRange::new(sig_start as u64 + 16, sig_start as u64 + 64)
        );
        let size = find_block(&index.children, "SIZE: 1234");
        assert_eq!(
            size.range,
            ByteRange::new(sig_start as u64 + 16, sig_start as u64 + 32)
        );
        find_block(&size.children, "Tag: 1000 (SIZE)");
        find_block(&size.children, "Type: INT32 (4)");
        find_block(&size.children, "Offset: 0");
        find_block(&size.children, "Count: 1");
        find_block(&index.children, &format!("MD5: {}", "ab".repeat(16)));
        find_block(&index.children, "SHA256: deadbeef");

        let store = find_block(c, "Data store (29 bytes)");
        let store_start = sig_start as u64 + 64;
        assert_eq!(store.range, ByteRange::new(store_start, sig_end as u64));
        assert_eq!(
            find_block(&store.children, "MD5").range,
            ByteRange::new(store_start + 4, store_start + 20)
        );
        assert_eq!(
            find_block(&store.children, "SHA256").range,
            ByteRange::new(store_start + 20, store_start + 29)
        );

        let pad = find_block(&blocks, "Signature padding (3 bytes)");
        assert_eq!(pad.range, ByteRange::new(sig_end as u64, main_start as u64));
    }

    #[test]
    fn dissect_parses_main_header_and_payload() {
        let (data, _, main_start, payload_start) = build_rpm(XZ_PAYLOAD, Some("xz"));
        let blocks = RpmDissector.dissect(&data);
        let header = find_block(&blocks, "Header");
        assert_eq!(
            header.range,
            ByteRange::new(main_start as u64, payload_start as u64)
        );
        let index = find_block(&header.children, "Index (6 entries)");
        find_block(&index.children, "NAME: hello");
        find_block(&index.children, "VERSION: 1.0");
        find_block(&index.children, "ARCH: x86_64");
        let provides = find_block(
            &index.children,
            "PROVIDENAME: [\"hello\", \"hello(x86-64)\"] (2 items)",
        );
        find_block(&provides.children, "Type: STRING_ARRAY (8)");
        find_block(&index.children, "PAYLOADFORMAT: cpio");
        find_block(&index.children, "PAYLOADCOMPRESSOR: xz");

        let payload = find_block(&blocks, "Payload (cpio, xz, 9 bytes)");
        assert_eq!(
            payload.range,
            ByteRange::new(payload_start as u64, data.len() as u64)
        );
    }

    #[test]
    fn payload_compressor_is_sniffed_when_not_declared() {
        for (payload, name) in [
            (&[0x1F, 0x8B, 8, 0][..], "gzip"),
            (XZ_PAYLOAD, "xz"),
            (&[0x28, 0xB5, 0x2F, 0xFD, 0][..], "zstd"),
            (&b"BZh91AY&SY"[..], "bzip2"),
            (&b"????"[..], "unknown compression"),
        ] {
            let (data, ..) = build_rpm(payload, None);
            let blocks = RpmDissector.dissect(&data);
            find_block(
                &blocks,
                &format!("Payload (cpio, {name}, {} bytes)", payload.len()),
            );
        }
    }

    #[test]
    fn entries_are_capped() {
        let entries: Vec<(u32, Value)> = (0..MAX_ENTRIES as u32 + 10)
            .map(|i| (2000 + i, Value::Int32(i)))
            .collect();
        let mut data = build_lead("big");
        data.extend_from_slice(&build_header(&entries));
        let blocks = RpmDissector.dissect(&data);
        let sig = find_block(&blocks, "Signature header");
        let index = find_block(&sig.children, "Index (266 entries)");
        assert_eq!(index.children.len(), MAX_ENTRIES + 1);
        let more = find_block(&index.children, "… 10 more entries");
        let shown_end = 96 + 16 + MAX_ENTRIES as u64 * 16;
        assert_eq!(more.range, ByteRange::new(shown_end, shown_end + 160));
        find_block(&index.children, "Tag 2000: 0");
    }

    #[test]
    fn identify_reports_rpm() {
        let (data, ..) = build_rpm(XZ_PAYLOAD, None);
        assert_eq!(super::super::identify(&data), "RPM");
    }
}
