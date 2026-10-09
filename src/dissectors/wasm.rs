use super::{Block, ByteRange, Dissector};

const WASM_MAGIC: &[u8] = b"\0asm";
const HEADER_LEN: usize = 8;

/// Components can nest modules and components; cap recursion on hostile input.
const MAX_NESTING: usize = 8;

/// Longest name shown in a label before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct WasmDissector;

impl Dissector for WasmDissector {
    fn name(&self) -> &'static str {
        "WebAssembly"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.len() >= HEADER_LEN && data.starts_with(WASM_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        binary_blocks(data, 0, data.len(), 0)
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

/// Bounds-checked cursor over `data[pos..end]` that reports absolute offsets.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self {
            data,
            pos,
            end: end.min(data.len()),
        }
    }

    fn byte(&mut self) -> Option<u8> {
        if self.pos >= self.end {
            return None;
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Some(b)
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.end {
            return None;
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Some(bytes)
    }

    /// Unsigned LEB128 of at most `bits` bits.
    fn uleb(&mut self, bits: u32) -> Option<u64> {
        let mut result = 0u64;
        for i in 0..bits.div_ceil(7) {
            let b = self.byte()?;
            result |= u64::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                if bits < 64 && result >> bits != 0 {
                    return None;
                }
                return Some(result);
            }
        }
        None
    }

    fn u32(&mut self) -> Option<u32> {
        self.uleb(32).map(|v| v as u32)
    }

    /// Signed LEB128 of at most `bits` bits.
    fn sleb(&mut self, bits: u32) -> Option<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        for _ in 0..bits.div_ceil(7) {
            let b = self.byte()?;
            result |= i64::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
        }
        None
    }

    fn name(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        Some(display_name(self.bytes(len)?))
    }
}

fn display_name(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let escaped: String = text.escape_debug().collect();
    if escaped.chars().count() > MAX_LABEL_CHARS {
        let truncated: String = escaped.chars().take(MAX_LABEL_CHARS).collect();
        format!("{truncated}…")
    } else {
        escaped
    }
}

/// Parses a module or component occupying `data[start..end]`.
fn binary_blocks(data: &[u8], start: usize, end: usize, depth: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let end = end.min(data.len());
    let header_end = start + HEADER_LEN;
    if header_end > end || data.get(start..start + 4) != Some(WASM_MAGIC) {
        return blocks;
    }

    let version = read_u16_le(data, start + 4).unwrap_or(0);
    let layer = read_u16_le(data, start + 6).unwrap_or(0);
    let is_component = layer == 1;
    let mut header = vec![Block::leaf("Magic: \\0asm", span(start, start + 4))];
    if layer == 0 {
        header.push(Block::leaf(
            format!("Version: {version} (module)"),
            span(start + 4, header_end),
        ));
    } else {
        header.push(Block::leaf(
            format!("Version: {version:#x}"),
            span(start + 4, start + 6),
        ));
        let kind = if is_component { " (component)" } else { "" };
        header.push(Block::leaf(
            format!("Layer: {layer}{kind}"),
            span(start + 6, header_end),
        ));
    }
    blocks.push(Block::node("Header", span(start, header_end), header).expanded());

    let mut ctx = ModuleContext::default();
    let mut offset = header_end;
    while offset < end {
        match section_block(data, offset, end, is_component, depth, &mut ctx) {
            Some(section) => {
                offset = section.range.end as usize;
                blocks.push(section);
            }
            None => {
                blocks.push(Block::leaf("Truncated section header", span(offset, end)));
                break;
            }
        }
    }
    blocks
}

#[derive(Default)]
struct ModuleContext {
    imported_funcs: u32,
}

fn core_section_name(id: u8) -> Option<(&'static str, &'static str)> {
    Some(match id {
        0 => ("custom", "Custom"),
        1 => ("type", "Type"),
        2 => ("import", "Import"),
        3 => ("function", "Function"),
        4 => ("table", "Table"),
        5 => ("memory", "Memory"),
        6 => ("global", "Global"),
        7 => ("export", "Export"),
        8 => ("start", "Start"),
        9 => ("element", "Element"),
        10 => ("code", "Code"),
        11 => ("data", "Data"),
        12 => ("datacount", "Data count"),
        13 => ("tag", "Tag"),
        _ => return None,
    })
}

fn component_section_name(id: u8) -> Option<(&'static str, &'static str)> {
    Some(match id {
        0 => ("custom", "Custom"),
        1 => ("core module", "Core module"),
        2 => ("core instance", "Core instance"),
        3 => ("core type", "Core type"),
        4 => ("component", "Component"),
        5 => ("instance", "Instance"),
        6 => ("alias", "Alias"),
        7 => ("type", "Type"),
        8 => ("canon", "Canon"),
        9 => ("start", "Start"),
        10 => ("import", "Import"),
        11 => ("export", "Export"),
        12 => ("value", "Value"),
        _ => return None,
    })
}

/// Parses one section starting at `offset`. Returns `None` only if the
/// section's id/size header itself is truncated or malformed.
fn section_block(
    data: &[u8],
    offset: usize,
    end: usize,
    is_component: bool,
    depth: usize,
    ctx: &mut ModuleContext,
) -> Option<Block> {
    let mut r = Reader::new(data, offset, end);
    let id = r.byte()?;
    let size = r.u32()? as usize;
    let content_start = r.pos;
    let declared_end = content_start.checked_add(size)?;
    let content_end = declared_end.min(end);
    let truncated = declared_end > end;

    let names = if is_component {
        component_section_name(id)
    } else {
        core_section_name(id)
    };
    let id_label = match names {
        Some((short, _)) => format!("ID: {id} ({short})"),
        None => format!("ID: {id} (unknown)"),
    };
    let mut children = vec![
        Block::leaf(id_label, span(offset, offset + 1)),
        Block::leaf(
            format!(
                "Size: {size}{}",
                if truncated { " (truncated)" } else { "" }
            ),
            span(offset + 1, content_start),
        ),
    ];

    let mut label = match names {
        Some((_, title)) => format!("{title} section"),
        None => format!("Unknown section (id {id})"),
    };

    let mut c = Reader::new(data, content_start, content_end);
    let parsed = match (id, is_component) {
        (0, _) => {
            let name_start = c.pos;
            match c.name() {
                Some(name) => {
                    children.push(Block::leaf(
                        format!("Name: \"{name}\""),
                        span(name_start, c.pos),
                    ));
                    label = format!("Custom section: \"{name}\"");
                    if c.pos < content_end {
                        children.push(Block::leaf("Payload", span(c.pos, content_end)));
                        c.pos = content_end;
                    }
                    Some(())
                }
                None => None,
            }
        }
        (1 | 4, true) if depth < MAX_NESTING => {
            let nested = binary_blocks(data, content_start, content_end, depth + 1);
            if !nested.is_empty() {
                children.extend(nested);
                c.pos = content_end;
            }
            Some(())
        }
        (_, true) => Some(()),
        (_, false) => core_section_contents(id, &mut c, &mut children, ctx),
    };

    if c.pos < content_end {
        let what = if parsed.is_none() {
            "Unparsed data"
        } else if c.pos == content_start {
            "Contents"
        } else {
            "Trailing bytes"
        };
        children.push(Block::leaf(what, span(c.pos, content_end)));
    }

    Some(Block::node(label, span(offset, content_end), children))
}

fn core_section_contents(
    id: u8,
    r: &mut Reader,
    out: &mut Vec<Block>,
    ctx: &mut ModuleContext,
) -> Option<()> {
    match id {
        1 => vector(r, out, type_entry),
        2 => vector(r, out, |r, i| import_entry(r, i, ctx)),
        3 => vector(r, out, |r, i| {
            let s = r.pos;
            let ty = r.u32()?;
            Some(Block::leaf(
                format!(
                    "Function {}: type {ty}",
                    ctx.imported_funcs as u64 + i as u64
                ),
                span(s, r.pos),
            ))
        }),
        4 => vector(r, out, table_entry),
        5 => vector(r, out, |r, i| {
            let s = r.pos;
            let limits = limits(r)?;
            Some(Block::leaf(format!("Memory {i}: {limits}"), span(s, r.pos)))
        }),
        6 => vector(r, out, global_entry),
        7 => vector(r, out, export_entry),
        8 => {
            let s = r.pos;
            let func = r.u32()?;
            out.push(Block::leaf(
                format!("Start function: {func}"),
                span(s, r.pos),
            ));
            Some(())
        }
        9 => vector(r, out, element_entry),
        10 => vector(r, out, |r, i| code_entry(r, i, ctx)),
        11 => vector(r, out, data_entry),
        12 => {
            let s = r.pos;
            let count = r.u32()?;
            out.push(Block::leaf(format!("Data count: {count}"), span(s, r.pos)));
            Some(())
        }
        13 => vector(r, out, |r, i| {
            let s = r.pos;
            let ty = tag_type(r)?;
            Some(Block::leaf(format!("Tag {i}: {ty}"), span(s, r.pos)))
        }),
        // Unknown section: shown as opaque contents.
        _ => Some(()),
    }
}

/// Parses a `vec(entry)`: a count followed by entries. On a malformed entry
/// the reader is rewound to that entry's start and `None` is returned.
fn vector(
    r: &mut Reader,
    out: &mut Vec<Block>,
    mut entry: impl FnMut(&mut Reader, u32) -> Option<Block>,
) -> Option<()> {
    let s = r.pos;
    let count = r.u32()?;
    out.push(Block::leaf(format!("Count: {count}"), span(s, r.pos)));
    for i in 0..count {
        let entry_start = r.pos;
        match entry(r, i) {
            Some(block) if r.pos > entry_start => out.push(block),
            _ => {
                r.pos = entry_start;
                return None;
            }
        }
    }
    Some(())
}

fn abstract_heap_type(b: u8) -> Option<(&'static str, &'static str)> {
    Some(match b {
        0x69 => ("exn", "exnref"),
        0x6A => ("array", "arrayref"),
        0x6B => ("struct", "structref"),
        0x6C => ("i31", "i31ref"),
        0x6D => ("eq", "eqref"),
        0x6E => ("any", "anyref"),
        0x6F => ("extern", "externref"),
        0x70 => ("func", "funcref"),
        0x71 => ("none", "nullref"),
        0x72 => ("noextern", "nullexternref"),
        0x73 => ("nofunc", "nullfuncref"),
        0x74 => ("noexn", "nullexnref"),
        _ => return None,
    })
}

fn heap_type(r: &mut Reader) -> Option<String> {
    let v = r.sleb(33)?;
    if v >= 0 {
        return Some(v.to_string());
    }
    if v < -64 {
        return None;
    }
    abstract_heap_type((v + 0x80) as u8).map(|(name, _)| name.to_string())
}

fn val_type(r: &mut Reader) -> Option<String> {
    let b = r.byte()?;
    let name = match b {
        0x7F => "i32",
        0x7E => "i64",
        0x7D => "f32",
        0x7C => "f64",
        0x7B => "v128",
        0x63 => return Some(format!("(ref null {})", heap_type(r)?)),
        0x64 => return Some(format!("(ref {})", heap_type(r)?)),
        _ => abstract_heap_type(b)?.1,
    };
    Some(name.to_string())
}

fn val_types(r: &mut Reader) -> Option<Vec<String>> {
    let count = r.u32()?;
    let mut types = Vec::new();
    for _ in 0..count {
        types.push(val_type(r)?);
    }
    Some(types)
}

fn limits(r: &mut Reader) -> Option<String> {
    let flags = r.byte()?;
    if flags > 7 {
        return None;
    }
    let is64 = flags & 0x04 != 0;
    let bits = if is64 { 64 } else { 32 };
    let mut text = format!("min {}", r.uleb(bits)?);
    if flags & 0x01 != 0 {
        text += &format!(", max {}", r.uleb(bits)?);
    }
    if flags & 0x02 != 0 {
        text += ", shared";
    }
    if is64 {
        text += ", 64-bit";
    }
    Some(text)
}

fn table_type(r: &mut Reader) -> Option<String> {
    let ty = val_type(r)?;
    Some(format!("{ty}, {}", limits(r)?))
}

fn global_type(r: &mut Reader) -> Option<String> {
    let ty = val_type(r)?;
    match r.byte()? {
        0 => Some(ty),
        1 => Some(format!("mut {ty}")),
        _ => None,
    }
}

fn tag_type(r: &mut Reader) -> Option<String> {
    let attribute = r.byte()?;
    let ty = r.u32()?;
    match attribute {
        0 => Some(format!("exception, type {ty}")),
        _ => Some(format!("attribute {attribute}, type {ty}")),
    }
}

/// Decodes a constant expression up to and including its `end` opcode.
fn const_expr(r: &mut Reader) -> Option<String> {
    let mut ops = Vec::new();
    loop {
        let op = match r.byte()? {
            0x0B => break,
            0x23 => format!("global.get {}", r.u32()?),
            0x41 => format!("i32.const {}", r.sleb(32)?),
            0x42 => format!("i64.const {}", r.sleb(64)?),
            0x43 => format!(
                "f32.const {}",
                f32::from_le_bytes(r.bytes(4)?.try_into().ok()?)
            ),
            0x44 => format!(
                "f64.const {}",
                f64::from_le_bytes(r.bytes(8)?.try_into().ok()?)
            ),
            0x6A => "i32.add".to_string(),
            0x6B => "i32.sub".to_string(),
            0x6C => "i32.mul".to_string(),
            0x7C => "i64.add".to_string(),
            0x7D => "i64.sub".to_string(),
            0x7E => "i64.mul".to_string(),
            0xD0 => format!("ref.null {}", heap_type(r)?),
            0xD2 => format!("ref.func {}", r.u32()?),
            0xFD if r.u32()? == 12 => {
                r.bytes(16)?;
                "v128.const".to_string()
            }
            _ => return None,
        };
        ops.push(op);
    }
    if ops.is_empty() {
        Some("(empty)".to_string())
    } else {
        Some(ops.join(", "))
    }
}

fn result_list(types: &[String]) -> String {
    if types.len() == 1 {
        types[0].clone()
    } else {
        format!("({})", types.join(", "))
    }
}

fn type_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    // Only plain function types; GC rec/sub/struct/array types are left unparsed.
    if r.byte()? != 0x60 {
        return None;
    }
    let mut children = vec![Block::leaf("Form: func (0x60)", span(s, r.pos))];
    let params_start = r.pos;
    let params = val_types(r)?;
    children.push(Block::leaf(
        format!("Params: ({})", params.join(", ")),
        span(params_start, r.pos),
    ));
    let results_start = r.pos;
    let results = val_types(r)?;
    children.push(Block::leaf(
        format!("Results: {}", result_list(&results)),
        span(results_start, r.pos),
    ));
    Some(Block::node(
        format!(
            "Type {index}: ({}) -> {}",
            params.join(", "),
            result_list(&results)
        ),
        span(s, r.pos),
        children,
    ))
}

fn external_kind(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "func",
        1 => "table",
        2 => "memory",
        3 => "global",
        4 => "tag",
        _ => return None,
    })
}

fn import_entry(r: &mut Reader, index: u32, ctx: &mut ModuleContext) -> Option<Block> {
    let s = r.pos;
    let module = r.name()?;
    let mut children = vec![Block::leaf(format!("Module: \"{module}\""), span(s, r.pos))];
    let field_start = r.pos;
    let field = r.name()?;
    children.push(Block::leaf(
        format!("Name: \"{field}\""),
        span(field_start, r.pos),
    ));
    let kind_start = r.pos;
    let kind_byte = r.byte()?;
    let kind = external_kind(kind_byte)?;
    children.push(Block::leaf(
        format!("Kind: {kind_byte} ({kind})"),
        span(kind_start, r.pos),
    ));
    let desc_start = r.pos;
    let desc = match kind_byte {
        0 => format!("type {}", r.u32()?),
        1 => table_type(r)?,
        2 => limits(r)?,
        3 => global_type(r)?,
        _ => tag_type(r)?,
    };
    children.push(Block::leaf(
        format!("Type: {desc}"),
        span(desc_start, r.pos),
    ));
    if kind_byte == 0 {
        ctx.imported_funcs = ctx.imported_funcs.saturating_add(1);
    }
    Some(Block::node(
        format!("Import {index}: \"{module}\".\"{field}\" ({kind} {desc})"),
        span(s, r.pos),
        children,
    ))
}

fn table_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    // 0x40 0x00 prefixes a table type with an explicit initializer expression.
    if r.data.get(r.pos..r.pos + 2) == Some(&[0x40, 0x00]) && r.pos + 2 <= r.end {
        r.pos += 2;
        let ty = table_type(r)?;
        let init = const_expr(r)?;
        return Some(Block::leaf(
            format!("Table {index}: {ty}, init {init}"),
            span(s, r.pos),
        ));
    }
    let ty = table_type(r)?;
    Some(Block::leaf(format!("Table {index}: {ty}"), span(s, r.pos)))
}

fn global_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    let ty = global_type(r)?;
    let mut children = vec![Block::leaf(format!("Type: {ty}"), span(s, r.pos))];
    let init_start = r.pos;
    let init = const_expr(r)?;
    children.push(Block::leaf(
        format!("Init: {init}"),
        span(init_start, r.pos),
    ));
    Some(Block::node(
        format!("Global {index}: {ty} = {init}"),
        span(s, r.pos),
        children,
    ))
}

fn export_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    let name = r.name()?;
    let mut children = vec![Block::leaf(format!("Name: \"{name}\""), span(s, r.pos))];
    let kind_start = r.pos;
    let kind_byte = r.byte()?;
    let kind = external_kind(kind_byte)?;
    children.push(Block::leaf(
        format!("Kind: {kind_byte} ({kind})"),
        span(kind_start, r.pos),
    ));
    let index_start = r.pos;
    let item = r.u32()?;
    children.push(Block::leaf(
        format!("Index: {item}"),
        span(index_start, r.pos),
    ));
    Some(Block::node(
        format!("Export {index}: \"{name}\" ({kind} {item})"),
        span(s, r.pos),
        children,
    ))
}

fn element_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    let flags = r.u32()?;
    if flags > 7 {
        return None;
    }
    let passive_or_declarative = flags & 0x01 != 0;
    let explicit_table = !passive_or_declarative && flags & 0x02 != 0;
    let uses_exprs = flags & 0x04 != 0;
    let mode = match (passive_or_declarative, flags & 0x02 != 0) {
        (false, _) => "active",
        (true, false) => "passive",
        (true, true) => "declarative",
    };
    let mut children = vec![Block::leaf(
        format!("Flags: {flags} ({mode})"),
        span(s, r.pos),
    )];
    let mut summary = mode.to_string();

    if !passive_or_declarative {
        let mut table = 0;
        if explicit_table {
            let t = r.pos;
            table = r.u32()?;
            children.push(Block::leaf(format!("Table: {table}"), span(t, r.pos)));
        }
        let o = r.pos;
        let offset = const_expr(r)?;
        children.push(Block::leaf(format!("Offset: {offset}"), span(o, r.pos)));
        summary += &format!(", table {table}, offset {offset}");
    }

    // Flags 0 and 4 have an implicit funcref element type.
    if flags & 0x03 != 0 {
        let k = r.pos;
        if uses_exprs {
            let ty = val_type(r)?;
            children.push(Block::leaf(format!("Reference type: {ty}"), span(k, r.pos)));
        } else {
            let kind = r.byte()?;
            if kind != 0 {
                return None;
            }
            children.push(Block::leaf("Element kind: funcref", span(k, r.pos)));
        }
    }

    let items_start = r.pos;
    let count = r.u32()?;
    let mut items = vec![Block::leaf(
        format!("Count: {count}"),
        span(items_start, r.pos),
    )];
    for i in 0..count {
        let item_start = r.pos;
        let item = if uses_exprs {
            const_expr(r)?
        } else {
            format!("func {}", r.u32()?)
        };
        items.push(Block::leaf(
            format!("[{i}] {item}"),
            span(item_start, r.pos),
        ));
    }
    children.push(Block::node(
        format!("Elements: {count}"),
        span(items_start, r.pos),
        items,
    ));
    Some(Block::node(
        format!("Element segment {index}: {summary}, {count} elements"),
        span(s, r.pos),
        children,
    ))
}

fn code_entry(r: &mut Reader, index: u32, ctx: &ModuleContext) -> Option<Block> {
    let s = r.pos;
    let size = r.u32()? as usize;
    let body_start = r.pos;
    let body_end = body_start.checked_add(size)?;
    if body_end > r.end {
        return None;
    }
    let mut children = vec![Block::leaf(
        format!("Body size: {size}"),
        span(s, body_start),
    )];

    let mut b = Reader::new(r.data, body_start, body_end);
    let locals = (|| {
        let count = b.u32()?;
        let mut decls = Vec::new();
        for _ in 0..count {
            let d = b.pos;
            let n = b.u32()?;
            let ty = val_type(&mut b)?;
            decls.push(Block::leaf(format!("{n} x {ty}"), span(d, b.pos)));
        }
        Some((count, decls))
    })();
    match locals {
        Some((count, decls)) => {
            let label = format!("Locals: {count} declarations");
            let range = span(body_start, b.pos);
            children.push(if decls.is_empty() {
                Block::leaf(label, range)
            } else {
                Block::node(label, range, decls)
            });
            if b.pos < body_end {
                children.push(Block::leaf("Instructions", span(b.pos, body_end)));
            }
        }
        None if body_end > body_start => {
            children.push(Block::leaf("Unparsed body", span(body_start, body_end)));
        }
        None => {}
    }
    r.pos = body_end;

    let func = ctx.imported_funcs as u64 + index as u64;
    Some(Block::node(
        format!("Function body {index} (func {func})"),
        span(s, body_end),
        children,
    ))
}

fn data_entry(r: &mut Reader, index: u32) -> Option<Block> {
    let s = r.pos;
    let flags = r.u32()?;
    let mode = match flags {
        0 | 2 => "active",
        1 => "passive",
        _ => return None,
    };
    let mut children = vec![Block::leaf(
        format!("Flags: {flags} ({mode})"),
        span(s, r.pos),
    )];
    let mut summary = mode.to_string();
    if flags != 1 {
        let mut memory = 0;
        if flags == 2 {
            let m = r.pos;
            memory = r.u32()?;
            children.push(Block::leaf(format!("Memory: {memory}"), span(m, r.pos)));
        }
        let o = r.pos;
        let offset = const_expr(r)?;
        children.push(Block::leaf(format!("Offset: {offset}"), span(o, r.pos)));
        summary += &format!(", memory {memory}, offset {offset}");
    }
    let size_start = r.pos;
    let size = r.u32()? as usize;
    children.push(Block::leaf(
        format!("Size: {size}"),
        span(size_start, r.pos),
    ));
    let data_start = r.pos;
    r.bytes(size)?;
    if size > 0 {
        children.push(Block::leaf("Data", span(data_start, r.pos)));
    }
    Some(Block::node(
        format!("Data segment {index}: {summary}, {size} bytes"),
        span(s, r.pos),
        children,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn name(s: &str) -> Vec<u8> {
        let mut out = uleb(s.len() as u64);
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = uleb(items.len() as u64);
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn section(id: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(uleb(contents.len() as u64));
        out.extend_from_slice(contents);
        out
    }

    fn build_wasm(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        for s in sections {
            out.extend_from_slice(s);
        }
        out
    }

    /// A small module exercising every core section.
    fn sample_sections() -> Vec<Vec<u8>> {
        vec![
            // (i32, i32) -> i32 and () -> ()
            section(
                1,
                &vec_of(&[vec![0x60, 2, 0x7F, 0x7F, 1, 0x7F], vec![0x60, 0, 0]]),
            ),
            // import "env"."log" (func type 1)
            section(
                2,
                &vec_of(&[[name("env"), name("log"), vec![0x00, 0x01]].concat()]),
            ),
            section(3, &vec_of(&[vec![0x00], vec![0x01]])),
            section(4, &vec_of(&[vec![0x70, 0x01, 0x01, 0x02]])),
            section(5, &vec_of(&[vec![0x01, 0x01, 0x10]])),
            // mut i32 = i32.const 1024
            section(6, &vec_of(&[vec![0x7F, 0x01, 0x41, 0x80, 0x08, 0x0B]])),
            section(
                7,
                &vec_of(&[
                    [name("add"), vec![0x00, 0x01]].concat(),
                    [name("memory"), vec![0x02, 0x00]].concat(),
                ]),
            ),
            section(8, &uleb(2)),
            // active, offset i32.const 0, funcs [1, 2]
            section(9, &vec_of(&[vec![0x00, 0x41, 0x00, 0x0B, 2, 1, 2]])),
            section(12, &uleb(1)),
            section(
                10,
                &vec_of(&[
                    // 1 local decl of 1 x i64; local.get 0 local.get 1 i32.add end
                    [uleb(9), vec![1, 1, 0x7E, 0x20, 0, 0x20, 1, 0x6A, 0x0B]].concat(),
                    [uleb(2), vec![0, 0x0B]].concat(),
                ]),
            ),
            // active, memory 0, offset i32.const 8, "hi"
            section(11, &vec_of(&[vec![0x00, 0x41, 0x08, 0x0B, 2, b'h', b'i']])),
            section(0, &[name("producers"), vec![1, 2, 3]].concat()),
        ]
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn range(b: &Block) -> (u64, u64) {
        (b.range.start, b.range.end)
    }

    fn assert_nested(block: &Block) {
        for child in &block.children {
            assert!(
                child.range.start >= block.range.start && child.range.end <= block.range.end,
                "{:?} {:?} escapes {:?} {:?}",
                child.label,
                child.range,
                block.label,
                block.range
            );
            assert_nested(child);
        }
    }

    #[test]
    fn matches_wasm_magic() {
        assert!(WasmDissector.matches(&build_wasm(&[])));
        assert!(WasmDissector.matches(&build_wasm(&sample_sections())));
    }

    #[test]
    fn does_not_match_non_wasm_data() {
        assert!(!WasmDissector.matches(b""));
        assert!(!WasmDissector.matches(b"not a wasm file"));
        assert!(!WasmDissector.matches(b"\0asm\x01\0\0"));
        assert!(!WasmDissector.matches(b"\0ASM\x01\0\0\0"));
    }

    #[test]
    fn dissect_returns_empty_for_truncated_header() {
        assert!(WasmDissector.dissect(b"\0asm\x01").is_empty());
        assert!(WasmDissector.dissect(b"").is_empty());
    }

    #[test]
    fn dissect_parses_header() {
        let data = build_wasm(&[]);
        let blocks = WasmDissector.dissect(&data);
        assert_eq!(blocks.len(), 1);
        let header = find_block(&blocks, "Header");
        assert_eq!(range(header), (0, 8));
        assert!(header.default_expanded);
        assert_eq!(range(find_block(&header.children, "Magic: \\0asm")), (0, 4));
        assert_eq!(
            range(find_block(&header.children, "Version: 1 (module)")),
            (4, 8)
        );
    }

    #[test]
    fn dissect_parses_all_core_sections() {
        let data = build_wasm(&sample_sections());
        let blocks = WasmDissector.dissect(&data);
        assert_eq!(blocks.len(), 14);
        assert_eq!(blocks.last().unwrap().range.end, data.len() as u64);
        for block in &blocks {
            assert_nested(block);
            assert!(
                !block
                    .children
                    .iter()
                    .any(|c| c.label == "Unparsed data" || c.label == "Trailing bytes"),
                "{} not fully parsed",
                block.label
            );
        }

        let types = find_block(&blocks, "Type section");
        assert_eq!(range(types), (8, 20));
        assert_eq!(range(find_block(&types.children, "ID: 1 (type)")), (8, 9));
        assert_eq!(range(find_block(&types.children, "Size: 10")), (9, 10));
        assert_eq!(range(find_block(&types.children, "Count: 2")), (10, 11));
        let t0 = find_block(&types.children, "Type 0: (i32, i32) -> i32");
        assert_eq!(range(t0), (11, 17));
        assert_eq!(
            range(find_block(&t0.children, "Params: (i32, i32)")),
            (12, 15)
        );
        assert_eq!(range(find_block(&t0.children, "Results: i32")), (15, 17));
        find_block(&types.children, "Type 1: () -> ()");

        let imports = find_block(&blocks, "Import section");
        let import = find_block(&imports.children, "Import 0: \"env\".\"log\" (func type 1)");
        find_block(&import.children, "Module: \"env\"");
        find_block(&import.children, "Kind: 0 (func)");

        // Function indices account for the imported function.
        let funcs = find_block(&blocks, "Function section");
        find_block(&funcs.children, "Function 1: type 0");
        find_block(&funcs.children, "Function 2: type 1");

        let tables = find_block(&blocks, "Table section");
        find_block(&tables.children, "Table 0: funcref, min 1, max 2");
        let memories = find_block(&blocks, "Memory section");
        find_block(&memories.children, "Memory 0: min 1, max 16");
        let globals = find_block(&blocks, "Global section");
        find_block(&globals.children, "Global 0: mut i32 = i32.const 1024");

        let exports = find_block(&blocks, "Export section");
        find_block(&exports.children, "Export 0: \"add\" (func 1)");
        find_block(&exports.children, "Export 1: \"memory\" (memory 0)");

        let start = find_block(&blocks, "Start section");
        find_block(&start.children, "Start function: 2");

        let elements = find_block(&blocks, "Element section");
        let seg = find_block(
            &elements.children,
            "Element segment 0: active, table 0, offset i32.const 0, 2 elements",
        );
        let items = find_block(&seg.children, "Elements: 2");
        find_block(&items.children, "[1] func 2");

        let datacount = find_block(&blocks, "Data count section");
        find_block(&datacount.children, "ID: 12 (datacount)");
        find_block(&datacount.children, "Data count: 1");

        let code = find_block(&blocks, "Code section");
        let body = find_block(&code.children, "Function body 0 (func 1)");
        let body_start = body.range.start;
        assert_eq!(range(body), (body_start, body_start + 10));
        assert_eq!(
            range(find_block(&body.children, "Body size: 9")),
            (body_start, body_start + 1)
        );
        let locals = find_block(&body.children, "Locals: 1 declarations");
        assert_eq!(range(locals), (body_start + 1, body_start + 4));
        find_block(&locals.children, "1 x i64");
        assert_eq!(
            range(find_block(&body.children, "Instructions")),
            (body_start + 4, body_start + 10)
        );
        let body1 = find_block(&code.children, "Function body 1 (func 2)");
        find_block(&body1.children, "Locals: 0 declarations");

        let data_sec = find_block(&blocks, "Data section");
        let seg = find_block(
            &data_sec.children,
            "Data segment 0: active, memory 0, offset i32.const 8, 2 bytes",
        );
        let payload = find_block(&seg.children, "Data");
        assert_eq!(
            &data[payload.range.start as usize..payload.range.end as usize],
            b"hi"
        );

        let custom = find_block(&blocks, "Custom section: \"producers\"");
        find_block(&custom.children, "Name: \"producers\"");
        let payload = find_block(&custom.children, "Payload");
        assert_eq!(payload.range.end, data.len() as u64);
        assert_eq!(payload.range.end - payload.range.start, 3);
    }

    #[test]
    fn dissect_handles_truncation_without_panicking() {
        let data = build_wasm(&sample_sections());
        for len in 0..data.len() {
            let blocks = WasmDissector.dissect(&data[..len]);
            for block in &blocks {
                assert!(block.range.end <= len as u64);
                assert_nested(block);
            }
        }
        let full = WasmDissector.dissect(&data).len();
        assert!(WasmDissector.dissect(&data[..20]).len() < full);
    }

    #[test]
    fn dissect_marks_truncated_section() {
        let mut data = build_wasm(&[section(1, &vec_of(&[vec![0x60, 0, 0]]))]);
        data.truncate(data.len() - 1);
        let blocks = WasmDissector.dissect(&data);
        let types = find_block(&blocks, "Type section");
        assert_eq!(types.range.end, data.len() as u64);
        find_block(&types.children, "Size: 4 (truncated)");
        assert!(types.children.iter().any(|c| c.label == "Unparsed data"));
    }

    #[test]
    fn dissect_reports_malformed_section_header() {
        // Section id followed by an unterminated LEB128 size.
        let mut data = build_wasm(&[]);
        data.extend_from_slice(&[0x01, 0x80, 0x80]);
        let blocks = WasmDissector.dissect(&data);
        let bad = find_block(&blocks, "Truncated section header");
        assert_eq!(range(bad), (8, 11));
    }

    #[test]
    fn dissect_shows_unknown_sections_opaquely() {
        let data = build_wasm(&[section(0x2A, &[1, 2, 3])]);
        let blocks = WasmDissector.dissect(&data);
        let unknown = find_block(&blocks, "Unknown section (id 42)");
        assert_eq!(range(find_block(&unknown.children, "Contents")), (10, 13));
    }

    #[test]
    fn leb128_rejects_overlong_and_out_of_range_values() {
        let max = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        assert_eq!(Reader::new(&max, 0, 5).u32(), Some(u32::MAX));
        let too_big = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        assert_eq!(Reader::new(&too_big, 0, 5).u32(), None);
        let overlong = [0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert_eq!(Reader::new(&overlong, 0, 6).u32(), None);
        // Reads never cross the reader's end, even if data continues.
        assert_eq!(Reader::new(&[0x80, 0x01], 0, 1).u32(), None);
        assert_eq!(Reader::new(&[0x7F], 0, 1).sleb(32), Some(-1));
        assert_eq!(Reader::new(&[0x80, 0x7F], 0, 2).sleb(32), Some(-128));
    }

    #[test]
    fn dissect_recurses_into_component_core_modules() {
        let module = build_wasm(&[section(1, &vec_of(&[vec![0x60, 0, 0]]))]);
        let mut data = b"\0asm\x0d\0\x01\0".to_vec();
        data.extend(section(1, &module));
        let blocks = WasmDissector.dissect(&data);
        let header = find_block(&blocks, "Header");
        find_block(&header.children, "Layer: 1 (component)");
        let core = find_block(&blocks, "Core module section");
        let nested_header = find_block(&core.children, "Header");
        assert_eq!(range(nested_header), (10, 18));
        let types = find_block(&core.children, "Type section");
        find_block(&types.children, "Type 0: () -> ()");
        assert_nested(core);
    }

    #[test]
    fn identify_reports_webassembly() {
        let data = build_wasm(&sample_sections());
        assert_eq!(super::super::identify(&data), "WebAssembly");
        assert_eq!(super::super::identify(&build_wasm(&[])), "WebAssembly");
    }
}
