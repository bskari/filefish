use super::{Block, ByteRange, Dissector};

const CLASS_MAGIC: u32 = 0xCAFE_BABE;

/// Lowest major version of any Java class file (JDK 1.0.2 / 1.1).
const MIN_MAJOR: u16 = 45;
/// Generous upper bound on the major version. Mach-O fat (universal)
/// binaries share the 0xCAFEBABE magic but store a small big-endian
/// `nfat_arch` count at bytes 4..8, so bytes 6..8 are a small number
/// (well below 45) for them.
const MAX_MAJOR: u16 = 255;

/// Longest label value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

/// Nesting limit for attributes inside `Code` attributes.
const MAX_ATTRIBUTE_DEPTH: usize = 4;

pub struct JavaClassDissector;

impl Dissector for JavaClassDissector {
    fn name(&self) -> &'static str {
        "Java class"
    }

    fn matches(&self, data: &[u8]) -> bool {
        // Require the constant pool count too, so a bare 8-byte header
        // doesn't match.
        if data.len() < 10 || read_u32(data, 0) != Some(CLASS_MAGIC) {
            return false;
        }
        matches!(read_u16(data, 6), Some(major) if (MIN_MAJOR..=MAX_MAJOR).contains(&major))
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let (Some(magic), Some(minor), Some(major)) =
            (read_u32(data, 0), read_u16(data, 4), read_u16(data, 6))
        else {
            return blocks;
        };

        blocks.push(
            Block::node(
                "Header",
                span(0, 8),
                vec![
                    Block::leaf(format!("Magic: 0x{magic:08X}"), span(0, 4)),
                    Block::leaf(format!("Minor version: {minor}"), span(4, 6)),
                    Block::leaf(
                        format!(
                            "Major version: {major} ({})",
                            java_version_name(major, minor)
                        ),
                        span(6, 8),
                    ),
                ],
            )
            .expanded(),
        );

        let Some(cp) = constant_pool_block(data, 8) else {
            return blocks;
        };
        blocks.push(cp.block);
        if !cp.complete {
            push_unparsed(&mut blocks, data, cp.end);
            return blocks;
        }
        let pool = cp.pool;
        let mut off = cp.end;

        let (class_block, end, complete) = class_info_block(data, off, &pool);
        if let Some(b) = class_block {
            blocks.push(b);
        }
        if !complete {
            return blocks;
        }
        off = end;

        for kind in [MemberKind::Field, MemberKind::Method] {
            let (block, end, complete) = members_block(data, off, &pool, kind);
            if let Some(b) = block {
                blocks.push(b);
            }
            if !complete {
                return blocks;
            }
            off = end;
        }

        let (children, end, complete) = attributes(data, off, data.len(), &pool, 0);
        if !children.is_empty() {
            let count = read_u16(data, off).unwrap_or(0);
            blocks.push(Block::node(
                format!("Attributes ({count})"),
                span(off, end),
                children,
            ));
        }
        if complete && end < data.len() {
            blocks.push(Block::leaf(
                format!("Trailing data ({} bytes)", data.len() - end),
                span(end, data.len()),
            ));
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

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn truncate(s: &str) -> String {
    if s.chars().count() > MAX_LABEL_CHARS {
        let mut short: String = s.chars().take(MAX_LABEL_CHARS).collect();
        short.push('…');
        short
    } else {
        s.to_string()
    }
}

fn push_unparsed(blocks: &mut Vec<Block>, data: &[u8], start: usize) {
    if start < data.len() {
        blocks.push(Block::leaf(
            format!("Unparsed data ({} bytes)", data.len() - start),
            span(start, data.len()),
        ));
    }
}

fn java_version_name(major: u16, minor: u16) -> String {
    let base = match major {
        45 if minor < 3 => "JDK 1.0.2".to_string(),
        45 => "JDK 1.1".to_string(),
        46 => "JDK 1.2".to_string(),
        47 => "JDK 1.3".to_string(),
        48 => "JDK 1.4".to_string(),
        49 => "Java SE 5".to_string(),
        50.. => format!("Java SE {}", major - 44),
        _ => "unknown".to_string(),
    };
    if major >= 56 && minor == 0xFFFF {
        format!("{base}, preview features")
    } else {
        base
    }
}

// ---------------------------------------------------------------------------
// Constant pool

#[derive(Clone)]
enum CpEntry {
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class(u16),
    String(u16),
    /// Fieldref, Methodref or InterfaceMethodref: class index, name-and-type index.
    Ref(u16, u16),
    NameAndType(u16, u16),
    MethodHandle(u8, u16),
    MethodType(u16),
    /// Dynamic or InvokeDynamic: bootstrap method index, name-and-type index.
    Dynamic(u16, u16),
    Module(u16),
    Package(u16),
}

fn cp_tag_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        1 => "Utf8",
        3 => "Integer",
        4 => "Float",
        5 => "Long",
        6 => "Double",
        7 => "Class",
        8 => "String",
        9 => "Fieldref",
        10 => "Methodref",
        11 => "InterfaceMethodref",
        12 => "NameAndType",
        15 => "MethodHandle",
        16 => "MethodType",
        17 => "Dynamic",
        18 => "InvokeDynamic",
        19 => "Module",
        20 => "Package",
        _ => return None,
    })
}

fn reference_kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "getField",
        2 => "getStatic",
        3 => "putField",
        4 => "putStatic",
        5 => "invokeVirtual",
        6 => "invokeStatic",
        7 => "invokeSpecial",
        8 => "newInvokeSpecial",
        9 => "invokeInterface",
        _ => "unknown",
    }
}

struct Pool(Vec<Option<CpEntry>>);

impl Pool {
    fn get(&self, index: u16) -> Option<&CpEntry> {
        self.0.get(index as usize)?.as_ref()
    }

    fn utf8(&self, index: u16) -> Option<&str> {
        match self.get(index)? {
            CpEntry::Utf8(s) => Some(s),
            _ => None,
        }
    }

    /// Resolves an entry to a short human-readable string, following
    /// references a few levels deep.
    fn resolve(&self, index: u16) -> Option<String> {
        self.resolve_depth(index, 0)
    }

    fn resolve_depth(&self, index: u16, depth: usize) -> Option<String> {
        if depth > 4 {
            return None;
        }
        let d = depth + 1;
        Some(match self.get(index)? {
            CpEntry::Utf8(s) => s.clone(),
            CpEntry::Integer(v) => v.to_string(),
            CpEntry::Float(v) => v.to_string(),
            CpEntry::Long(v) => v.to_string(),
            CpEntry::Double(v) => v.to_string(),
            CpEntry::Class(i) | CpEntry::Module(i) | CpEntry::Package(i) => {
                self.utf8(*i)?.to_string()
            }
            CpEntry::String(i) => format!("{:?}", self.utf8(*i)?),
            CpEntry::MethodType(i) => self.utf8(*i)?.to_string(),
            CpEntry::Ref(class, nat) => format!(
                "{}.{}",
                self.resolve_depth(*class, d)?,
                self.resolve_depth(*nat, d)?
            ),
            CpEntry::NameAndType(name, desc) => {
                format!("{}:{}", self.utf8(*name)?, self.utf8(*desc)?)
            }
            CpEntry::MethodHandle(kind, r) => format!(
                "{} {}",
                reference_kind_name(*kind),
                self.resolve_depth(*r, d)?
            ),
            CpEntry::Dynamic(bsm, nat) => {
                format!("#{bsm}:{}", self.resolve_depth(*nat, d)?)
            }
        })
    }

    /// `#index (value)` for display, or just `#index` if unresolvable.
    fn describe(&self, index: u16) -> String {
        match self.resolve(index) {
            Some(s) => truncate(&format!("#{index} ({s})")),
            None => format!("#{index}"),
        }
    }
}

struct ConstantPool {
    block: Block,
    pool: Pool,
    end: usize,
    /// False if the pool was truncated or held an unknown tag, in which case
    /// the rest of the file cannot be located.
    complete: bool,
}

fn constant_pool_block(data: &[u8], start: usize) -> Option<ConstantPool> {
    let count = read_u16(data, start)?;
    let mut children = vec![Block::leaf(
        format!("Constant pool count: {count}"),
        span(start, start + 2),
    )];
    let mut pool = Pool(vec![None; count.max(1) as usize]);
    let mut off = start + 2;
    let mut complete = true;

    // Entries may reference later ones, so labels are built after the whole
    // pool has been read.
    let mut parsed: Vec<(u16, u8, usize, usize)> = Vec::new();
    let mut unknown: Option<Block> = None;
    let mut index: u16 = 1;
    while index < count {
        let Some(tag) = read_u8(data, off) else {
            complete = false;
            break;
        };
        if cp_tag_name(tag).is_none() {
            unknown = Some(Block::leaf(
                format!("#{index} Unknown tag {tag}"),
                span(off, off + 1),
            ));
            complete = false;
            off += 1;
            break;
        }
        let Some((entry, len)) = parse_cp_entry(data, off, tag) else {
            complete = false;
            break;
        };
        pool.0[index as usize] = Some(entry);
        parsed.push((index, tag, off, off + len));
        off += len;
        // Long and Double occupy two constant pool slots.
        index = index.saturating_add(if tag == 5 || tag == 6 { 2 } else { 1 });
    }

    for (index, tag, entry_start, entry_end) in parsed {
        let tag_name = cp_tag_name(tag).unwrap_or("Unknown");
        let value = match tag {
            1 => pool.utf8(index).map(|s| format!("{s:?}")),
            _ => pool.resolve(index),
        };
        let label = match value {
            Some(v) => truncate(&format!("#{index} {tag_name}: {v}")),
            None => format!("#{index} {tag_name}"),
        };
        children.push(Block::leaf(label, span(entry_start, entry_end)));
    }
    children.extend(unknown);

    let label = if complete {
        format!("Constant pool ({} entries)", count.saturating_sub(1))
    } else {
        format!(
            "Constant pool ({} entries, truncated)",
            count.saturating_sub(1)
        )
    };
    let end = off.min(data.len());
    Some(ConstantPool {
        block: Block::node(label, span(start, end), children),
        pool,
        end,
        complete,
    })
}

/// Parses one constant pool entry at `off` (pointing at its tag byte).
/// Returns the entry and its total length including the tag.
fn parse_cp_entry(data: &[u8], off: usize, tag: u8) -> Option<(CpEntry, usize)> {
    let p = off + 1;
    Some(match tag {
        1 => {
            let len = read_u16(data, p)? as usize;
            let bytes = data.get(p + 2..p + 2 + len)?;
            // Modified UTF-8; lossy standard UTF-8 decoding is close enough
            // for display.
            (
                CpEntry::Utf8(String::from_utf8_lossy(bytes).into_owned()),
                3 + len,
            )
        }
        3 => (CpEntry::Integer(read_u32(data, p)? as i32), 5),
        4 => (CpEntry::Float(f32::from_bits(read_u32(data, p)?)), 5),
        5 => (CpEntry::Long(read_u64(data, p)? as i64), 9),
        6 => (CpEntry::Double(f64::from_bits(read_u64(data, p)?)), 9),
        7 => (CpEntry::Class(read_u16(data, p)?), 3),
        8 => (CpEntry::String(read_u16(data, p)?), 3),
        9..=11 => (CpEntry::Ref(read_u16(data, p)?, read_u16(data, p + 2)?), 5),
        12 => (
            CpEntry::NameAndType(read_u16(data, p)?, read_u16(data, p + 2)?),
            5,
        ),
        15 => (
            CpEntry::MethodHandle(read_u8(data, p)?, read_u16(data, p + 1)?),
            4,
        ),
        16 => (CpEntry::MethodType(read_u16(data, p)?), 3),
        17 | 18 => (
            CpEntry::Dynamic(read_u16(data, p)?, read_u16(data, p + 2)?),
            5,
        ),
        19 => (CpEntry::Module(read_u16(data, p)?), 3),
        20 => (CpEntry::Package(read_u16(data, p)?), 3),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Access flags

const CLASS_FLAGS: &[(u16, &str)] = &[
    (0x0001, "ACC_PUBLIC"),
    (0x0010, "ACC_FINAL"),
    (0x0020, "ACC_SUPER"),
    (0x0200, "ACC_INTERFACE"),
    (0x0400, "ACC_ABSTRACT"),
    (0x1000, "ACC_SYNTHETIC"),
    (0x2000, "ACC_ANNOTATION"),
    (0x4000, "ACC_ENUM"),
    (0x8000, "ACC_MODULE"),
];

const FIELD_FLAGS: &[(u16, &str)] = &[
    (0x0001, "ACC_PUBLIC"),
    (0x0002, "ACC_PRIVATE"),
    (0x0004, "ACC_PROTECTED"),
    (0x0008, "ACC_STATIC"),
    (0x0010, "ACC_FINAL"),
    (0x0040, "ACC_VOLATILE"),
    (0x0080, "ACC_TRANSIENT"),
    (0x1000, "ACC_SYNTHETIC"),
    (0x4000, "ACC_ENUM"),
];

const METHOD_FLAGS: &[(u16, &str)] = &[
    (0x0001, "ACC_PUBLIC"),
    (0x0002, "ACC_PRIVATE"),
    (0x0004, "ACC_PROTECTED"),
    (0x0008, "ACC_STATIC"),
    (0x0010, "ACC_FINAL"),
    (0x0020, "ACC_SYNCHRONIZED"),
    (0x0040, "ACC_BRIDGE"),
    (0x0080, "ACC_VARARGS"),
    (0x0100, "ACC_NATIVE"),
    (0x0400, "ACC_ABSTRACT"),
    (0x0800, "ACC_STRICT"),
    (0x1000, "ACC_SYNTHETIC"),
];

fn access_flags_label(flags: u16, table: &[(u16, &str)]) -> String {
    let mut names: Vec<String> = table
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    let known = table.iter().fold(0u16, |acc, (bit, _)| acc | bit);
    if flags & !known != 0 {
        names.push(format!("0x{:04X}", flags & !known));
    }
    if names.is_empty() {
        format!("Access flags: 0x{flags:04X}")
    } else {
        format!("Access flags: 0x{flags:04X} ({})", names.join(" | "))
    }
}

// ---------------------------------------------------------------------------
// Class info and interfaces

fn class_info_block(data: &[u8], start: usize, pool: &Pool) -> (Option<Block>, usize, bool) {
    let (Some(flags), Some(this_class), Some(super_class)) = (
        read_u16(data, start),
        read_u16(data, start + 2),
        read_u16(data, start + 4),
    ) else {
        return (None, start, false);
    };

    let mut children = vec![
        Block::leaf(
            access_flags_label(flags, CLASS_FLAGS),
            span(start, start + 2),
        ),
        Block::leaf(
            format!("This class: {}", pool.describe(this_class)),
            span(start + 2, start + 4),
        ),
        Block::leaf(
            if super_class == 0 {
                "Super class: none".to_string()
            } else {
                format!("Super class: {}", pool.describe(super_class))
            },
            span(start + 4, start + 6),
        ),
    ];

    let mut off = start + 6;
    let mut complete = false;
    if let Some(count) = read_u16(data, off) {
        children.push(Block::leaf(
            format!("Interfaces count: {count}"),
            span(off, off + 2),
        ));
        off += 2;
        let list_start = off;
        let mut interfaces = Vec::new();
        complete = true;
        for _ in 0..count {
            let Some(index) = read_u16(data, off) else {
                complete = false;
                break;
            };
            interfaces.push(Block::leaf(
                format!("Interface: {}", pool.describe(index)),
                span(off, off + 2),
            ));
            off += 2;
        }
        if !interfaces.is_empty() {
            children.push(Block::node(
                format!("Interfaces ({count})"),
                span(list_start, off),
                interfaces,
            ));
        }
    }

    let label = match pool.resolve(this_class) {
        Some(name) => truncate(&format!("Class: {name}")),
        None => "Class".to_string(),
    };
    (
        Some(Block::node(label, span(start, off), children).expanded()),
        off,
        complete,
    )
}

// ---------------------------------------------------------------------------
// Fields and methods

#[derive(Clone, Copy)]
enum MemberKind {
    Field,
    Method,
}

impl MemberKind {
    fn singular(self) -> &'static str {
        match self {
            MemberKind::Field => "Field",
            MemberKind::Method => "Method",
        }
    }

    fn plural(self) -> &'static str {
        match self {
            MemberKind::Field => "Fields",
            MemberKind::Method => "Methods",
        }
    }

    fn flags(self) -> &'static [(u16, &'static str)] {
        match self {
            MemberKind::Field => FIELD_FLAGS,
            MemberKind::Method => METHOD_FLAGS,
        }
    }
}

fn members_block(
    data: &[u8],
    start: usize,
    pool: &Pool,
    kind: MemberKind,
) -> (Option<Block>, usize, bool) {
    let Some(count) = read_u16(data, start) else {
        return (None, start, false);
    };
    let mut children = vec![Block::leaf(
        format!("{} count: {count}", kind.plural()),
        span(start, start + 2),
    )];
    let mut off = start + 2;
    let mut complete = true;
    for _ in 0..count {
        let (member, end, ok) = member_block(data, off, pool, kind);
        if let Some(m) = member {
            children.push(m);
        }
        off = end;
        if !ok {
            complete = false;
            break;
        }
    }
    (
        Some(Block::node(
            format!("{} ({count})", kind.plural()),
            span(start, off),
            children,
        )),
        off,
        complete,
    )
}

fn member_block(
    data: &[u8],
    start: usize,
    pool: &Pool,
    kind: MemberKind,
) -> (Option<Block>, usize, bool) {
    let (Some(flags), Some(name), Some(desc)) = (
        read_u16(data, start),
        read_u16(data, start + 2),
        read_u16(data, start + 4),
    ) else {
        return (None, start, false);
    };
    let mut children = vec![
        Block::leaf(
            access_flags_label(flags, kind.flags()),
            span(start, start + 2),
        ),
        Block::leaf(
            format!("Name: {}", pool.describe(name)),
            span(start + 2, start + 4),
        ),
        Block::leaf(
            format!("Descriptor: {}", pool.describe(desc)),
            span(start + 4, start + 6),
        ),
    ];
    let (attrs, end, complete) = attributes(data, start + 6, data.len(), pool, 0);
    children.extend(attrs);

    let label = match (pool.utf8(name), pool.utf8(desc)) {
        (Some(n), Some(d)) => truncate(&format!("{}: {n} {d}", kind.singular())),
        _ => kind.singular().to_string(),
    };
    (
        Some(Block::node(label, span(start, end), children)),
        end,
        complete,
    )
}

// ---------------------------------------------------------------------------
// Attributes

/// Parses an `attributes_count` followed by that many attributes, none of
/// which may extend past `limit`. Returns the count leaf plus one node per
/// attribute, the end offset, and whether parsing completed.
fn attributes(
    data: &[u8],
    start: usize,
    limit: usize,
    pool: &Pool,
    depth: usize,
) -> (Vec<Block>, usize, bool) {
    let mut blocks = Vec::new();
    let Some(count) = read_u16(data, start).filter(|_| start + 2 <= limit) else {
        return (blocks, start, false);
    };
    blocks.push(Block::leaf(
        format!("Attributes count: {count}"),
        span(start, start + 2),
    ));
    let mut off = start + 2;
    for _ in 0..count {
        let (Some(name_index), Some(length)) = (read_u16(data, off), read_u32(data, off + 2))
        else {
            return (blocks, off, false);
        };
        let info_start = off + 6;
        let info_end = info_start.saturating_add(length as usize);
        let truncated = info_start > limit || info_end > limit;
        let end = info_end.min(limit).max(info_start.min(limit));

        let name = pool.utf8(name_index);
        let mut children = vec![
            Block::leaf(
                format!("Name: {}", pool.describe(name_index)),
                span(off, off + 2),
            ),
            Block::leaf(format!("Length: {length}"), span(off + 2, off + 6)),
        ];
        if !truncated {
            children.extend(attribute_details(
                data, name, info_start, info_end, pool, depth,
            ));
        } else if end > info_start {
            children.push(Block::leaf(
                format!("Info ({} of {length} bytes, truncated)", end - info_start),
                span(info_start, end),
            ));
        }
        let label = match name {
            Some(n) => truncate(&format!("Attribute: {n}")),
            None => "Attribute".to_string(),
        };
        blocks.push(Block::node(label, span(off, end), children));
        off = end;
        if truncated {
            return (blocks, off, false);
        }
    }
    (blocks, off, true)
}

fn attribute_details(
    data: &[u8],
    name: Option<&str>,
    start: usize,
    end: usize,
    pool: &Pool,
    depth: usize,
) -> Vec<Block> {
    let decoded = match name {
        Some("Code") => code_details(data, start, end, pool, depth),
        Some(n @ ("SourceFile" | "Signature" | "ConstantValue")) if end - start == 2 => {
            read_u16(data, start).map(|index| {
                let label = match n {
                    "SourceFile" => "Source file",
                    "Signature" => "Signature",
                    _ => "Value",
                };
                vec![Block::leaf(
                    format!("{label}: {}", pool.describe(index)),
                    span(start, end),
                )]
            })
        }
        Some("Exceptions") => exceptions_details(data, start, end, pool),
        _ => None,
    };
    match decoded {
        Some(blocks) => blocks,
        None if end > start => vec![Block::leaf(
            format!("Info ({} bytes)", end - start),
            span(start, end),
        )],
        None => Vec::new(),
    }
}

fn exceptions_details(data: &[u8], start: usize, end: usize, pool: &Pool) -> Option<Vec<Block>> {
    let count = read_u16(data, start)? as usize;
    if start + 2 + count * 2 != end {
        return None;
    }
    let mut blocks = vec![Block::leaf(
        format!("Number of exceptions: {count}"),
        span(start, start + 2),
    )];
    for i in 0..count {
        let off = start + 2 + i * 2;
        blocks.push(Block::leaf(
            format!("Exception: {}", pool.describe(read_u16(data, off)?)),
            span(off, off + 2),
        ));
    }
    Some(blocks)
}

fn code_details(
    data: &[u8],
    start: usize,
    end: usize,
    pool: &Pool,
    depth: usize,
) -> Option<Vec<Block>> {
    let max_stack = read_u16(data, start)?;
    let max_locals = read_u16(data, start + 2)?;
    let code_len = read_u32(data, start + 4)? as usize;
    let code_start = start + 8;
    let code_end = code_start.checked_add(code_len)?;
    if code_end + 2 > end {
        return None;
    }
    let mut blocks = vec![
        Block::leaf(format!("Max stack: {max_stack}"), span(start, start + 2)),
        Block::leaf(
            format!("Max locals: {max_locals}"),
            span(start + 2, start + 4),
        ),
        Block::leaf(
            format!("Code length: {code_len}"),
            span(start + 4, start + 8),
        ),
    ];
    if code_len > 0 {
        blocks.push(Block::leaf(
            format!("Bytecode ({code_len} bytes)"),
            span(code_start, code_end),
        ));
    }

    let ex_count = read_u16(data, code_end)? as usize;
    let ex_start = code_end + 2;
    let ex_end = ex_start + ex_count * 8;
    if ex_end > end {
        return None;
    }
    blocks.push(Block::leaf(
        format!("Exception table length: {ex_count}"),
        span(code_end, ex_start),
    ));
    if ex_count > 0 {
        let mut entries = Vec::new();
        for i in 0..ex_count {
            let off = ex_start + i * 8;
            let start_pc = read_u16(data, off)?;
            let end_pc = read_u16(data, off + 2)?;
            let handler_pc = read_u16(data, off + 4)?;
            let catch_type = read_u16(data, off + 6)?;
            let catch = if catch_type == 0 {
                "any".to_string()
            } else {
                pool.describe(catch_type)
            };
            entries.push(Block::leaf(
                truncate(&format!(
                    "pc {start_pc}..{end_pc} -> {handler_pc}, catch {catch}"
                )),
                span(off, off + 8),
            ));
        }
        blocks.push(Block::node(
            format!("Exception table ({ex_count})"),
            span(ex_start, ex_end),
            entries,
        ));
    }

    if depth >= MAX_ATTRIBUTE_DEPTH {
        if ex_end < end {
            blocks.push(Block::leaf(
                format!("Attributes ({} bytes)", end - ex_end),
                span(ex_end, end),
            ));
        }
        return Some(blocks);
    }
    let (attrs, attrs_end, complete) = attributes(data, ex_end, end, pool, depth + 1);
    if !complete || attrs_end != end {
        return None;
    }
    blocks.extend(attrs);
    Some(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pool used by `build_class`:
    ///  #1 Class -> #2
    ///  #2 Utf8 "Hello"
    ///  #3 Class -> #4
    ///  #4 Utf8 "java/lang/Object"
    ///  #5 Utf8 "x"
    ///  #6 Utf8 "I"
    ///  #7 Utf8 "main"
    ///  #8 Utf8 "([Ljava/lang/String;)V"
    ///  #9 Utf8 "Code"
    /// #10 Long 42 (occupies #10 and #11)
    /// #12 Methodref -> #13, #14   (forward reference)
    /// #13 Class -> #4
    /// #14 NameAndType -> #7, #8
    /// #15 Utf8 "SourceFile"
    /// #16 Utf8 "Hello.java"
    /// #17 String -> #16
    fn constant_pool() -> Vec<u8> {
        let mut cp = Vec::new();
        let utf8 = |cp: &mut Vec<u8>, s: &str| {
            cp.push(1);
            cp.extend_from_slice(&(s.len() as u16).to_be_bytes());
            cp.extend_from_slice(s.as_bytes());
        };
        let u16_entry = |cp: &mut Vec<u8>, tag: u8, v: u16| {
            cp.push(tag);
            cp.extend_from_slice(&v.to_be_bytes());
        };
        u16_entry(&mut cp, 7, 2);
        utf8(&mut cp, "Hello");
        u16_entry(&mut cp, 7, 4);
        utf8(&mut cp, "java/lang/Object");
        utf8(&mut cp, "x");
        utf8(&mut cp, "I");
        utf8(&mut cp, "main");
        utf8(&mut cp, "([Ljava/lang/String;)V");
        utf8(&mut cp, "Code");
        cp.push(5);
        cp.extend_from_slice(&42i64.to_be_bytes());
        cp.push(10);
        cp.extend_from_slice(&13u16.to_be_bytes());
        cp.extend_from_slice(&14u16.to_be_bytes());
        u16_entry(&mut cp, 7, 4);
        cp.push(12);
        cp.extend_from_slice(&7u16.to_be_bytes());
        cp.extend_from_slice(&8u16.to_be_bytes());
        utf8(&mut cp, "SourceFile");
        utf8(&mut cp, "Hello.java");
        u16_entry(&mut cp, 8, 16);
        cp
    }

    const CP_COUNT: u16 = 18;

    fn build_class(major: u16) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        d.extend_from_slice(&0u16.to_be_bytes());
        d.extend_from_slice(&major.to_be_bytes());
        d.extend_from_slice(&CP_COUNT.to_be_bytes());
        d.extend_from_slice(&constant_pool());
        d.extend_from_slice(&0x0021u16.to_be_bytes()); // public super
        d.extend_from_slice(&1u16.to_be_bytes()); // this
        d.extend_from_slice(&3u16.to_be_bytes()); // super
        d.extend_from_slice(&0u16.to_be_bytes()); // interfaces

        // One field: private static int x
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&0x000Au16.to_be_bytes());
        d.extend_from_slice(&5u16.to_be_bytes());
        d.extend_from_slice(&6u16.to_be_bytes());
        d.extend_from_slice(&0u16.to_be_bytes());

        // One method: public static main with a Code attribute
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&0x0009u16.to_be_bytes());
        d.extend_from_slice(&7u16.to_be_bytes());
        d.extend_from_slice(&8u16.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        let code = [0xB1u8]; // return
        d.extend_from_slice(&9u16.to_be_bytes());
        let code_attr_len = 2 + 2 + 4 + code.len() + 2 + 2;
        d.extend_from_slice(&(code_attr_len as u32).to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes()); // max stack
        d.extend_from_slice(&1u16.to_be_bytes()); // max locals
        d.extend_from_slice(&(code.len() as u32).to_be_bytes());
        d.extend_from_slice(&code);
        d.extend_from_slice(&0u16.to_be_bytes()); // exception table
        d.extend_from_slice(&0u16.to_be_bytes()); // attributes

        // Class attributes: SourceFile
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&15u16.to_be_bytes());
        d.extend_from_slice(&2u32.to_be_bytes());
        d.extend_from_slice(&16u16.to_be_bytes());
        d
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
    fn matches_class_file() {
        assert!(JavaClassDissector.matches(&build_class(52)));
        assert!(JavaClassDissector.matches(&build_class(45)));
        assert!(JavaClassDissector.matches(&build_class(69)));
    }

    #[test]
    fn does_not_match_other_data() {
        assert!(!JavaClassDissector.matches(b""));
        assert!(!JavaClassDissector.matches(b"not a class file"));
        assert!(!JavaClassDissector.matches(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0]));
        assert!(!JavaClassDissector.matches(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]));
        assert!(!JavaClassDissector.matches(&build_class(44)));
    }

    #[test]
    fn does_not_match_mach_o_fat_binary() {
        // fat_header: magic, nfat_arch = 2, then fat_arch entries.
        let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2];
        data.extend_from_slice(&[0u8; 40]);
        assert!(!JavaClassDissector.matches(&data));
        assert_ne!(super::super::identify(&data), "Java class");
    }

    #[test]
    fn identify_reports_java_class() {
        assert_eq!(super::super::identify(&build_class(52)), "Java class");
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        assert!(JavaClassDissector.dissect(b"").is_empty());
        assert!(JavaClassDissector.dissect(&[0xCA, 0xFE]).is_empty());
        let full = build_class(52);
        let full_count = JavaClassDissector.dissect(&full).len();
        for len in 0..full.len() {
            let blocks = JavaClassDissector.dissect(&full[..len]);
            assert!(blocks.len() <= full_count);
            check_ranges(&blocks, None, len as u64);
        }
    }

    fn check_ranges(blocks: &[Block], parent: Option<ByteRange>, len: u64) {
        for b in blocks {
            assert!(b.range.start <= b.range.end, "{}", b.label);
            assert!(b.range.end <= len, "{} past end", b.label);
            if let Some(p) = parent {
                assert!(
                    b.range.start >= p.start && b.range.end <= p.end,
                    "{} outside parent",
                    b.label
                );
            }
            check_ranges(&b.children, Some(b.range), len);
        }
    }

    #[test]
    fn dissect_parses_header() {
        let data = build_class(52);
        let blocks = JavaClassDissector.dissect(&data);
        check_ranges(&blocks, None, data.len() as u64);

        let header = find_block(&blocks, "Header");
        assert_eq!(header.range, ByteRange::new(0, 8));
        assert_eq!(
            find_block(&header.children, "Major version: 52 (Java SE 8)").range,
            ByteRange::new(6, 8)
        );
        find_block(&header.children, "Magic: 0xCAFEBABE");
        find_block(&header.children, "Minor version: 0");
    }

    #[test]
    fn dissect_parses_constant_pool() {
        let data = build_class(52);
        let blocks = JavaClassDissector.dissect(&data);
        let cp_len = constant_pool().len() as u64;
        let cp = find_block(&blocks, "Constant pool (17 entries)");
        assert_eq!(cp.range, ByteRange::new(8, 10 + cp_len));
        find_block(&cp.children, "Constant pool count: 18");
        assert_eq!(
            find_block(&cp.children, "#1 Class: Hello").range,
            ByteRange::new(10, 13)
        );
        assert_eq!(
            find_block(&cp.children, "#2 Utf8: \"Hello\"").range,
            ByteRange::new(13, 21)
        );
        find_block(&cp.children, "#10 Long: 42");
        find_block(
            &cp.children,
            "#12 Methodref: java/lang/Object.main:([Ljava/lang/String;)V",
        );
        find_block(&cp.children, "#17 String: \"Hello.java\"");
        // Long takes two slots, so there is no #11.
        assert!(!cp.children.iter().any(|b| b.label.starts_with("#11 ")));
    }

    #[test]
    fn dissect_parses_class_members_and_attributes() {
        let data = build_class(52);
        let blocks = JavaClassDissector.dissect(&data);
        let class_start = 10 + constant_pool().len() as u64;

        let class = find_block(&blocks, "Class: Hello");
        assert_eq!(class.range, ByteRange::new(class_start, class_start + 8));
        assert_eq!(
            find_block(
                &class.children,
                "Access flags: 0x0021 (ACC_PUBLIC | ACC_SUPER)"
            )
            .range,
            ByteRange::new(class_start, class_start + 2)
        );
        find_block(&class.children, "This class: #1 (Hello)");
        find_block(&class.children, "Super class: #3 (java/lang/Object)");
        find_block(&class.children, "Interfaces count: 0");

        let fields = find_block(&blocks, "Fields (1)");
        let field = find_block(&fields.children, "Field: x I");
        assert_eq!(
            field.range,
            ByteRange::new(class_start + 10, class_start + 18)
        );
        find_block(
            &field.children,
            "Access flags: 0x000A (ACC_PRIVATE | ACC_STATIC)",
        );
        find_block(&field.children, "Name: #5 (x)");
        find_block(&field.children, "Descriptor: #6 (I)");

        let methods = find_block(&blocks, "Methods (1)");
        let method = find_block(&methods.children, "Method: main ([Ljava/lang/String;)V");
        find_block(
            &method.children,
            "Access flags: 0x0009 (ACC_PUBLIC | ACC_STATIC)",
        );
        let code = find_block(&method.children, "Attribute: Code");
        find_block(&code.children, "Length: 13");
        find_block(&code.children, "Max stack: 1");
        let bytecode = find_block(&code.children, "Bytecode (1 bytes)");
        assert_eq!(bytecode.range.end - bytecode.range.start, 1);
        assert_eq!(data[bytecode.range.start as usize], 0xB1);

        let attrs = find_block(&blocks, "Attributes (1)");
        let len = data.len() as u64;
        assert_eq!(attrs.range, ByteRange::new(len - 10, len));
        let source = find_block(&attrs.children, "Attribute: SourceFile");
        assert_eq!(
            find_block(&source.children, "Source file: #16 (Hello.java)").range,
            ByteRange::new(len - 2, len)
        );
        assert!(!blocks.iter().any(|b| b.label.starts_with("Trailing")));
    }

    #[test]
    fn dissect_reports_unknown_tag_and_stops() {
        let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 3, 99, 1, 2, 3];
        data.extend_from_slice(&[0u8; 4]);
        let blocks = JavaClassDissector.dissect(&data);
        let cp = find_block(&blocks, "Constant pool (2 entries, truncated)");
        find_block(&cp.children, "#1 Unknown tag 99");
        let rest = find_block(&blocks, "Unparsed data (7 bytes)");
        assert_eq!(rest.range, ByteRange::new(11, data.len() as u64));
    }

    #[test]
    fn version_names() {
        assert_eq!(java_version_name(45, 3), "JDK 1.1");
        assert_eq!(java_version_name(49, 0), "Java SE 5");
        assert_eq!(java_version_name(61, 0), "Java SE 17");
        assert_eq!(
            java_version_name(65, 0xFFFF),
            "Java SE 21, preview features"
        );
    }
}
