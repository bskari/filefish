use super::{Block, ByteRange, Dissector};

const MTHD_MAGIC: &[u8] = b"MThd";
const MTRK_MAGIC: &[u8] = b"MTrk";
const RIFF_MAGIC: &[u8] = b"RIFF";
const RMID_MAGIC: &[u8] = b"RMID";

/// Events shown per track before collapsing the rest into one leaf.
const MAX_EVENTS_PER_TRACK: usize = 500;

/// Longest text value shown before truncating with an ellipsis.
const MAX_LABEL_CHARS: usize = 80;

pub struct MidiDissector;

impl Dissector for MidiDissector {
    fn name(&self) -> &'static str {
        "MIDI"
    }

    fn matches(&self, data: &[u8]) -> bool {
        is_smf(data, 0) || is_rmid(data)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        if data.len() < 8 {
            Vec::new()
        } else if is_rmid(data) {
            rmid_blocks(data)
        } else {
            smf_blocks(data, 0)
        }
    }
}

fn span(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start as u64, end as u64)
}

fn read_u16_be(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a MIDI variable-length quantity (at most 4 bytes). Returns the value
/// and the offset just past it.
fn read_vlq(data: &[u8], off: usize) -> Option<(u32, usize)> {
    let mut value = 0u32;
    for i in 0..4 {
        let b = *data.get(off + i)?;
        value = (value << 7) | u32::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Some((value, off + i + 1));
        }
    }
    None
}

fn is_smf(data: &[u8], off: usize) -> bool {
    data.get(off..off + 4) == Some(MTHD_MAGIC)
        && read_u32_be(data, off + 4).is_some_and(|len| len >= 6)
        && data.len() >= off + 14
}

fn is_rmid(data: &[u8]) -> bool {
    data.len() >= 12 && data.starts_with(RIFF_MAGIC) && &data[8..12] == RMID_MAGIC
}

fn chunk_id(bytes: &[u8]) -> String {
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

fn text_value(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out: String = text.chars().take(MAX_LABEL_CHARS).collect();
    if text.chars().count() > MAX_LABEL_CHARS {
        out.push('…');
    }
    format!("\"{out}\"")
}

// ---------------------------------------------------------------------------
// RIFF RMID wrapper
// ---------------------------------------------------------------------------

fn rmid_blocks(data: &[u8]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let riff_size = read_u32_le(data, 4).unwrap_or(0);
    blocks.push(
        Block::node(
            "RIFF header",
            span(0, 12),
            vec![
                Block::leaf("Chunk ID: RIFF", span(0, 4)),
                Block::leaf(format!("Chunk size: {riff_size}"), span(4, 8)),
                Block::leaf("Form type: RMID", span(8, 12)),
            ],
        )
        .expanded(),
    );

    let riff_end = (riff_size as usize).saturating_add(8).min(data.len());
    let mut off = 12;
    while off + 8 <= riff_end {
        let id = &data[off..off + 4];
        let size = read_u32_le(data, off + 4).unwrap_or(0) as usize;
        let body_start = off + 8;
        let body_end = body_start.saturating_add(size).min(riff_end);
        let mut children = vec![
            Block::leaf(format!("Chunk ID: {}", chunk_id(id)), span(off, off + 4)),
            Block::leaf(format!("Chunk size: {size}"), span(off + 4, off + 8)),
        ];
        let is_data = id == b"data";
        if is_data && is_smf(&data[..body_end], body_start) {
            children.push(
                Block::node(
                    "Standard MIDI File",
                    span(body_start, body_end),
                    smf_blocks(&data[..body_end], body_start),
                )
                .expanded(),
            );
        } else if body_end > body_start {
            children.push(Block::leaf("Chunk data", span(body_start, body_end)));
        }
        // RIFF chunks are padded to an even length.
        let mut next = body_end;
        if size % 2 == 1 && next < riff_end && body_start + size == body_end {
            children.push(Block::leaf("Padding", span(next, next + 1)));
            next += 1;
        }
        blocks.push(
            Block::node(format!("{} chunk", chunk_id(id)), span(off, next), children)
                .expanded_if(is_data),
        );
        off = next;
    }
    if off < data.len() {
        blocks.push(Block::leaf("Trailing data", span(off, data.len())));
    }
    blocks
}

// ---------------------------------------------------------------------------
// Standard MIDI File
// ---------------------------------------------------------------------------

/// Dissects a Standard MIDI File starting at `start`. `data` must end where
/// the SMF ends; ranges are absolute offsets into `data`.
fn smf_blocks(data: &[u8], start: usize) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut off = start;
    let mut track_index = 0usize;

    while off + 8 <= data.len() {
        let id = &data[off..off + 4];
        let len = read_u32_be(data, off + 4).unwrap_or(0) as usize;
        let body_start = off + 8;
        let body_end = body_start.saturating_add(len).min(data.len());
        let header_leaves = vec![
            Block::leaf(format!("Chunk ID: {}", chunk_id(id)), span(off, off + 4)),
            Block::leaf(format!("Length: {len}"), span(off + 4, off + 8)),
        ];

        let block = if id == MTHD_MAGIC {
            header_chunk(data, off, body_start, body_end, header_leaves)
        } else if id == MTRK_MAGIC {
            track_index += 1;
            track_chunk(data, off, body_start, body_end, track_index, header_leaves)
        } else {
            let mut children = header_leaves;
            if body_end > body_start {
                children.push(Block::leaf("Chunk data", span(body_start, body_end)));
            }
            Block::node(
                format!("Unknown chunk: {}", chunk_id(id)),
                span(off, body_end),
                children,
            )
        };
        blocks.push(block);
        off = body_end;
    }
    if off < data.len() {
        blocks.push(Block::leaf("Trailing data", span(off, data.len())));
    }
    blocks
}

fn header_chunk(
    data: &[u8],
    off: usize,
    body_start: usize,
    body_end: usize,
    mut children: Vec<Block>,
) -> Block {
    let field = |rel: usize| -> Option<u16> {
        let pos = body_start + rel;
        if pos + 2 <= body_end {
            read_u16_be(data, pos)
        } else {
            None
        }
    };

    if let Some(format) = field(0) {
        let name = match format {
            0 => "single track",
            1 => "multi-track",
            2 => "multi-song",
            _ => "unknown",
        };
        children.push(Block::leaf(
            format!("Format: {format} ({name})"),
            span(body_start, body_start + 2),
        ));
    }
    if let Some(ntrks) = field(2) {
        children.push(Block::leaf(
            format!("Track count: {ntrks}"),
            span(body_start + 2, body_start + 4),
        ));
    }
    if let Some(division) = field(4) {
        let label = if division & 0x8000 != 0 {
            let fps = -i32::from((division >> 8) as u8 as i8);
            let ticks = division & 0xFF;
            let fps_label = if fps == 29 {
                "29.97 (drop frame)".to_string()
            } else {
                fps.to_string()
            };
            format!("Division: SMPTE {fps_label} fps, {ticks} ticks/frame")
        } else {
            format!("Division: {division} ticks per quarter note")
        };
        children.push(Block::leaf(label, span(body_start + 4, body_start + 6)));
    }
    if body_end > body_start + 6 {
        children.push(Block::leaf(
            "Extra header data",
            span(body_start + 6, body_end),
        ));
    }
    Block::node("Header chunk (MThd)", span(off, body_end), children).expanded()
}

fn track_chunk(
    data: &[u8],
    off: usize,
    body_start: usize,
    body_end: usize,
    index: usize,
    mut children: Vec<Block>,
) -> Block {
    let track = &data[..body_end];
    let mut pos = body_start;
    let mut running: Option<u8> = None;
    let mut shown = 0usize;
    let mut hidden = 0usize;
    let mut hidden_start = 0usize;
    let mut track_name: Option<String> = None;

    while pos < body_end {
        match parse_event(track, pos, &mut running) {
            Ok(event) => {
                if track_name.is_none() {
                    track_name = event.track_name;
                }
                if shown < MAX_EVENTS_PER_TRACK {
                    children.push(event.block);
                    shown += 1;
                } else {
                    if hidden == 0 {
                        hidden_start = pos;
                    }
                    hidden += 1;
                }
                pos = event.end;
                if event.end_of_track {
                    break;
                }
            }
            Err(label) => {
                if hidden > 0 {
                    children.push(Block::leaf(
                        format!("({hidden} more events not shown)"),
                        span(hidden_start, pos),
                    ));
                    hidden = 0;
                }
                children.push(Block::leaf(label, span(pos, body_end)));
                pos = body_end;
            }
        }
    }
    if hidden > 0 {
        children.push(Block::leaf(
            format!("({hidden} more events not shown)"),
            span(hidden_start, pos),
        ));
    }
    if pos < body_end {
        children.push(Block::leaf("Data after End of Track", span(pos, body_end)));
    }

    let total = shown + hidden;
    let mut label = format!("Track {index} (MTrk)");
    if let Some(name) = track_name {
        label.push_str(&format!(": {name}"));
    }
    let noun = if total == 1 { "event" } else { "events" };
    label.push_str(&format!(" — {total} {noun}"));
    Block::node(label, span(off, body_end), children)
}

struct Event {
    block: Block,
    end: usize,
    end_of_track: bool,
    track_name: Option<String>,
}

fn parse_event(data: &[u8], start: usize, running: &mut Option<u8>) -> Result<Event, String> {
    let (delta, after_delta) =
        read_vlq(data, start).ok_or_else(|| "Truncated event (delta time)".to_string())?;
    let mut children = vec![Block::leaf(
        format!("Delta time: {delta}"),
        span(start, after_delta),
    )];

    let first = *data
        .get(after_delta)
        .ok_or_else(|| "Truncated event (missing status)".to_string())?;

    let (summary, end, end_of_track, track_name) = if (0x80..0xF0).contains(&first) {
        *running = Some(first);
        children.push(Block::leaf(
            format!("Status: 0x{first:02X} ({})", channel_status_name(first)),
            span(after_delta, after_delta + 1),
        ));
        let (summary, end) = channel_message(data, first, after_delta + 1, &mut children)?;
        (summary, end, false, None)
    } else if first < 0x80 {
        let status = running
            .ok_or_else(|| format!("Invalid data: byte 0x{first:02X} with no running status"))?;
        let (summary, end) = channel_message(data, status, after_delta, &mut children)?;
        (format!("{summary} (running status)"), end, false, None)
    } else if first == 0xF0 || first == 0xF7 {
        *running = None;
        let (summary, end) = sysex_event(data, first, after_delta, &mut children)?;
        (summary, end, false, None)
    } else if first == 0xFF {
        *running = None;
        meta_event(data, after_delta, &mut children)?
    } else {
        return Err(format!("Invalid status byte 0x{first:02X}"));
    };

    Ok(Event {
        block: Block::node(format!("Δ{delta}: {summary}"), span(start, end), children),
        end,
        end_of_track,
        track_name,
    })
}

fn channel_status_name(status: u8) -> String {
    let kind = match status & 0xF0 {
        0x80 => "Note Off",
        0x90 => "Note On",
        0xA0 => "Poly Aftertouch",
        0xB0 => "Control Change",
        0xC0 => "Program Change",
        0xD0 => "Channel Aftertouch",
        _ => "Pitch Bend",
    };
    format!("{kind}, channel {}", (status & 0x0F) + 1)
}

/// Decodes the data bytes of a channel voice message starting at `pos`.
/// Returns the summary label and the offset past the message.
fn channel_message(
    data: &[u8],
    status: u8,
    pos: usize,
    children: &mut Vec<Block>,
) -> Result<(String, usize), String> {
    let kind = status & 0xF0;
    let ch = (status & 0x0F) + 1;
    let n = if kind == 0xC0 || kind == 0xD0 { 1 } else { 2 };
    let bytes = data
        .get(pos..pos + n)
        .ok_or_else(|| "Truncated channel message".to_string())?;
    let a = bytes[0];
    let b = bytes.get(1).copied().unwrap_or(0);
    let r0 = span(pos, pos + 1);
    let r1 = span(pos + 1, pos + 2);

    let summary = match kind {
        0x80 | 0x90 => {
            let name = if kind == 0x80 { "Note Off" } else { "Note On" };
            children.push(Block::leaf(format!("Note: {} ({a})", note_name(a)), r0));
            children.push(Block::leaf(format!("Velocity: {b}"), r1));
            let suffix = if kind == 0x90 && b == 0 {
                " (= Note Off)"
            } else {
                ""
            };
            format!("{name} ch {ch} {} vel {b}{suffix}", note_name(a))
        }
        0xA0 => {
            children.push(Block::leaf(format!("Note: {} ({a})", note_name(a)), r0));
            children.push(Block::leaf(format!("Pressure: {b}"), r1));
            format!("Poly Aftertouch ch {ch} {} pressure {b}", note_name(a))
        }
        0xB0 => {
            let cname = controller_name(a);
            children.push(Block::leaf(format!("Controller: {a} ({cname})"), r0));
            children.push(Block::leaf(format!("Value: {b}"), r1));
            format!("Control Change ch {ch} {cname} = {b}")
        }
        0xC0 => {
            let inst = GM_INSTRUMENTS.get(a as usize).copied().unwrap_or("?");
            children.push(Block::leaf(format!("Program: {a} ({inst})"), r0));
            format!("Program Change ch {ch} {a} ({inst})")
        }
        0xD0 => {
            children.push(Block::leaf(format!("Pressure: {a}"), r0));
            format!("Channel Aftertouch ch {ch} pressure {a}")
        }
        _ => {
            let value = ((i32::from(b & 0x7F) << 7) | i32::from(a & 0x7F)) - 8192;
            children.push(Block::leaf(
                format!("Pitch bend: {value} (LSB {a}, MSB {b})"),
                span(pos, pos + 2),
            ));
            format!("Pitch Bend ch {ch} {value}")
        }
    };
    Ok((summary, pos + n))
}

fn sysex_event(
    data: &[u8],
    status: u8,
    pos: usize,
    children: &mut Vec<Block>,
) -> Result<(String, usize), String> {
    let kind = if status == 0xF0 {
        "SysEx"
    } else {
        "SysEx (escape/continuation)"
    };
    children.push(Block::leaf(
        format!("Status: 0x{status:02X} ({kind})"),
        span(pos, pos + 1),
    ));
    let (len, data_start) =
        read_vlq(data, pos + 1).ok_or_else(|| "Truncated SysEx length".to_string())?;
    children.push(Block::leaf(
        format!("Length: {len}"),
        span(pos + 1, data_start),
    ));
    let data_end = data_start.saturating_add(len as usize);
    if data_end > data.len() {
        return Err("Truncated SysEx data".to_string());
    }
    if len > 0 {
        children.push(Block::leaf("Data", span(data_start, data_end)));
    }
    Ok((format!("{kind}, {len} bytes"), data_end))
}

type MetaResult = (String, usize, bool, Option<String>);

fn meta_event(data: &[u8], pos: usize, children: &mut Vec<Block>) -> Result<MetaResult, String> {
    let ty = *data
        .get(pos + 1)
        .ok_or_else(|| "Truncated meta event".to_string())?;
    let name = meta_name(ty);
    children.push(Block::leaf("Status: 0xFF (Meta event)", span(pos, pos + 1)));
    children.push(Block::leaf(
        format!("Type: 0x{ty:02X} ({name})"),
        span(pos + 1, pos + 2),
    ));
    let (len, ds) =
        read_vlq(data, pos + 2).ok_or_else(|| "Truncated meta event length".to_string())?;
    children.push(Block::leaf(format!("Length: {len}"), span(pos + 2, ds)));
    let de = ds.saturating_add(len as usize);
    let body = data
        .get(ds..de)
        .ok_or_else(|| "Truncated meta event data".to_string())?;
    let whole = span(ds, de);
    let mut track_name = None;

    let summary = match (ty, body) {
        (0x00, [hi, lo]) => {
            let n = u16::from_be_bytes([*hi, *lo]);
            children.push(Block::leaf(format!("Sequence number: {n}"), whole));
            format!("{name}: {n}")
        }
        (0x01..=0x0F, _) => {
            let text = text_value(body);
            if ty == 0x03 {
                track_name = Some(text.clone());
            }
            children.push(Block::leaf(format!("Text: {text}"), whole));
            format!("{name}: {text}")
        }
        (0x20, [c]) => {
            children.push(Block::leaf(format!("Channel: {}", c + 1), whole));
            format!("{name}: channel {}", c + 1)
        }
        (0x21, [p]) => {
            children.push(Block::leaf(format!("Port: {p}"), whole));
            format!("{name}: {p}")
        }
        (0x2F, _) => name.to_string(),
        (0x51, [a, b, c]) => {
            let us = u32::from_be_bytes([0, *a, *b, *c]);
            let bpm = if us > 0 {
                60_000_000.0 / us as f64
            } else {
                0.0
            };
            let label = format!("{us} µs/quarter ({bpm:.2} BPM)");
            children.push(Block::leaf(format!("Tempo: {label}"), whole));
            format!("{name}: {label}")
        }
        (0x54, [hr, mn, se, fr, ff]) => {
            let rate = match (hr >> 5) & 0x03 {
                0 => "24",
                1 => "25",
                2 => "29.97",
                _ => "30",
            };
            let label = format!(
                "{:02}:{mn:02}:{se:02}:{fr:02}.{ff:02} @ {rate} fps",
                hr & 0x1F
            );
            children.push(Block::leaf(format!("Offset: {label}"), whole));
            format!("{name}: {label}")
        }
        (0x58, [nn, dd, cc, bb]) => {
            let denom = 1u64.checked_shl(u32::from(*dd)).unwrap_or(0);
            children.push(Block::leaf(
                format!("Time signature: {nn}/{denom}"),
                span(ds, ds + 2),
            ));
            children.push(Block::leaf(
                format!("MIDI clocks per metronome click: {cc}"),
                span(ds + 2, ds + 3),
            ));
            children.push(Block::leaf(
                format!("32nd notes per quarter note: {bb}"),
                span(ds + 3, ds + 4),
            ));
            format!("{name}: {nn}/{denom}")
        }
        (0x59, [sf, mi]) => {
            let key = key_name(*sf as i8, *mi);
            children.push(Block::leaf(
                format!("Sharps/flats: {}", *sf as i8),
                span(ds, ds + 1),
            ));
            children.push(Block::leaf(
                format!("Mode: {}", if *mi == 0 { "major" } else { "minor" }),
                span(ds + 1, ds + 2),
            ));
            format!("{name}: {key}")
        }
        (0x7F, _) => {
            if len > 0 {
                children.push(Block::leaf("Data", whole));
            }
            format!("{name}, {len} bytes")
        }
        _ => {
            if len > 0 {
                children.push(Block::leaf("Data", whole));
            }
            format!("{name}, {len} bytes")
        }
    };
    Ok((summary, de, ty == 0x2F, track_name))
}

fn meta_name(ty: u8) -> &'static str {
    match ty {
        0x00 => "Sequence Number",
        0x01 => "Text",
        0x02 => "Copyright",
        0x03 => "Track Name",
        0x04 => "Instrument Name",
        0x05 => "Lyric",
        0x06 => "Marker",
        0x07 => "Cue Point",
        0x08 => "Program Name",
        0x09 => "Device Name",
        0x0A..=0x0F => "Text (reserved)",
        0x20 => "Channel Prefix",
        0x21 => "MIDI Port",
        0x2F => "End of Track",
        0x51 => "Set Tempo",
        0x54 => "SMPTE Offset",
        0x58 => "Time Signature",
        0x59 => "Key Signature",
        0x7F => "Sequencer-Specific",
        _ => "Unknown meta",
    }
}

fn key_name(sf: i8, mi: u8) -> String {
    const MAJOR: [&str; 15] = [
        "Cb", "Gb", "Db", "Ab", "Eb", "Bb", "F", "C", "G", "D", "A", "E", "B", "F#", "C#",
    ];
    const MINOR: [&str; 15] = [
        "Ab", "Eb", "Bb", "F", "C", "G", "D", "A", "E", "B", "F#", "C#", "G#", "D#", "A#",
    ];
    let idx = i32::from(sf) + 7;
    if !(0..15).contains(&idx) {
        return format!("invalid ({sf} sharps/flats)");
    }
    if mi == 0 {
        format!("{} major", MAJOR[idx as usize])
    } else {
        format!("{} minor", MINOR[idx as usize])
    }
}

/// Note name using the convention that note 60 is middle C ("C4").
fn note_name(note: u8) -> String {
    const NAMES: [&str; 12] = [
        "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B",
    ];
    let octave = i32::from(note / 12) - 1;
    format!("{}{octave}", NAMES[(note % 12) as usize])
}

fn controller_name(cc: u8) -> &'static str {
    match cc {
        0 => "Bank Select MSB",
        1 => "Modulation",
        2 => "Breath Controller",
        4 => "Foot Controller",
        5 => "Portamento Time",
        6 => "Data Entry MSB",
        7 => "Volume",
        8 => "Balance",
        10 => "Pan",
        11 => "Expression",
        32 => "Bank Select LSB",
        38 => "Data Entry LSB",
        64 => "Sustain Pedal",
        65 => "Portamento",
        66 => "Sostenuto",
        67 => "Soft Pedal",
        68 => "Legato",
        71 => "Resonance",
        72 => "Release Time",
        73 => "Attack Time",
        74 => "Cutoff",
        84 => "Portamento Control",
        91 => "Reverb",
        92 => "Tremolo",
        93 => "Chorus",
        94 => "Detune",
        95 => "Phaser",
        96 => "Data Increment",
        97 => "Data Decrement",
        98 => "NRPN LSB",
        99 => "NRPN MSB",
        100 => "RPN LSB",
        101 => "RPN MSB",
        120 => "All Sound Off",
        121 => "Reset All Controllers",
        122 => "Local Control",
        123 => "All Notes Off",
        124 => "Omni Off",
        125 => "Omni On",
        126 => "Mono On",
        127 => "Poly On",
        _ => "Controller",
    }
}

const GM_INSTRUMENTS: [&str; 128] = [
    "Acoustic Grand Piano",
    "Bright Acoustic Piano",
    "Electric Grand Piano",
    "Honky-tonk Piano",
    "Electric Piano 1",
    "Electric Piano 2",
    "Harpsichord",
    "Clavinet",
    "Celesta",
    "Glockenspiel",
    "Music Box",
    "Vibraphone",
    "Marimba",
    "Xylophone",
    "Tubular Bells",
    "Dulcimer",
    "Drawbar Organ",
    "Percussive Organ",
    "Rock Organ",
    "Church Organ",
    "Reed Organ",
    "Accordion",
    "Harmonica",
    "Tango Accordion",
    "Acoustic Guitar (nylon)",
    "Acoustic Guitar (steel)",
    "Electric Guitar (jazz)",
    "Electric Guitar (clean)",
    "Electric Guitar (muted)",
    "Overdriven Guitar",
    "Distortion Guitar",
    "Guitar Harmonics",
    "Acoustic Bass",
    "Electric Bass (finger)",
    "Electric Bass (pick)",
    "Fretless Bass",
    "Slap Bass 1",
    "Slap Bass 2",
    "Synth Bass 1",
    "Synth Bass 2",
    "Violin",
    "Viola",
    "Cello",
    "Contrabass",
    "Tremolo Strings",
    "Pizzicato Strings",
    "Orchestral Harp",
    "Timpani",
    "String Ensemble 1",
    "String Ensemble 2",
    "Synth Strings 1",
    "Synth Strings 2",
    "Choir Aahs",
    "Voice Oohs",
    "Synth Voice",
    "Orchestra Hit",
    "Trumpet",
    "Trombone",
    "Tuba",
    "Muted Trumpet",
    "French Horn",
    "Brass Section",
    "Synth Brass 1",
    "Synth Brass 2",
    "Soprano Sax",
    "Alto Sax",
    "Tenor Sax",
    "Baritone Sax",
    "Oboe",
    "English Horn",
    "Bassoon",
    "Clarinet",
    "Piccolo",
    "Flute",
    "Recorder",
    "Pan Flute",
    "Blown Bottle",
    "Shakuhachi",
    "Whistle",
    "Ocarina",
    "Lead 1 (square)",
    "Lead 2 (sawtooth)",
    "Lead 3 (calliope)",
    "Lead 4 (chiff)",
    "Lead 5 (charang)",
    "Lead 6 (voice)",
    "Lead 7 (fifths)",
    "Lead 8 (bass + lead)",
    "Pad 1 (new age)",
    "Pad 2 (warm)",
    "Pad 3 (polysynth)",
    "Pad 4 (choir)",
    "Pad 5 (bowed)",
    "Pad 6 (metallic)",
    "Pad 7 (halo)",
    "Pad 8 (sweep)",
    "FX 1 (rain)",
    "FX 2 (soundtrack)",
    "FX 3 (crystal)",
    "FX 4 (atmosphere)",
    "FX 5 (brightness)",
    "FX 6 (goblins)",
    "FX 7 (echoes)",
    "FX 8 (sci-fi)",
    "Sitar",
    "Banjo",
    "Shamisen",
    "Koto",
    "Kalimba",
    "Bagpipe",
    "Fiddle",
    "Shanai",
    "Tinkle Bell",
    "Agogo",
    "Steel Drums",
    "Woodblock",
    "Taiko Drum",
    "Melodic Tom",
    "Synth Drum",
    "Reverse Cymbal",
    "Guitar Fret Noise",
    "Breath Noise",
    "Seashore",
    "Bird Tweet",
    "Telephone Ring",
    "Helicopter",
    "Applause",
    "Gunshot",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn build_midi(format: u16, division: u16, tracks: &[&[u8]]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&format.to_be_bytes());
        header.extend_from_slice(&(tracks.len() as u16).to_be_bytes());
        header.extend_from_slice(&division.to_be_bytes());
        let mut data = chunk(b"MThd", &header);
        for t in tracks {
            data.extend(chunk(b"MTrk", t));
        }
        data
    }

    fn sample_track() -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&[0x00, 0xFF, 0x03, 0x05]);
        t.extend_from_slice(b"Piano"); // track name: 0..9
        t.extend_from_slice(&[0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20]); // tempo: 9..16
        t.extend_from_slice(&[0x00, 0xFF, 0x58, 0x04, 0x04, 0x02, 0x18, 0x08]); // 16..24
        t.extend_from_slice(&[0x00, 0xFF, 0x59, 0x02, 0x02, 0x00]); // D major: 24..30
        t.extend_from_slice(&[0x00, 0xC0, 0x00]); // program change: 30..33
        t.extend_from_slice(&[0x00, 0x90, 0x3C, 0x64]); // note on C4: 33..37
        t.extend_from_slice(&[0x83, 0x60, 0x3C, 0x00]); // running status, Δ480: 37..41
        t.extend_from_slice(&[0x00, 0xB0, 0x07, 0x64]); // CC volume: 41..45
        t.extend_from_slice(&[0x00, 0xE0, 0x00, 0x40]); // pitch bend 0: 45..49
        t.extend_from_slice(&[0x00, 0xF0, 0x03, 0x7E, 0x7F, 0xF7]); // sysex: 49..55
        t.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]); // end of track: 55..59
        t
    }

    fn find_block<'a>(blocks: &'a [Block], label: &str) -> &'a Block {
        blocks.iter().find(|b| b.label == label).unwrap_or_else(|| {
            panic!(
                "block {label:?} not found; have {:?}",
                blocks.iter().map(|b| &b.label).collect::<Vec<_>>()
            )
        })
    }

    fn has_child(block: &Block, label: &str) -> bool {
        block.children.iter().any(|b| b.label == label)
    }

    #[test]
    fn matches_midi_magic() {
        let data = build_midi(1, 480, &[&sample_track()]);
        assert!(MidiDissector.matches(&data));
    }

    #[test]
    fn does_not_match_non_midi_data() {
        assert!(!MidiDissector.matches(b""));
        assert!(!MidiDissector.matches(b"not a midi file at all"));
        assert!(!MidiDissector.matches(b"MThd\x00\x00\x00\x06\x00"));
        assert!(!MidiDissector.matches(b"RIFF\x04\x00\x00\x00WAVE"));
    }

    #[test]
    fn dissect_truncated_input_does_not_panic() {
        let data = build_midi(1, 480, &[&sample_track()]);
        let full = MidiDissector.dissect(&data).len();
        for len in 0..data.len() {
            let blocks = MidiDissector.dissect(&data[..len]);
            assert!(blocks.len() <= full);
        }
        assert!(MidiDissector.dissect(b"MThd").is_empty());
    }

    #[test]
    fn dissect_parses_header() {
        let data = build_midi(1, 480, &[&sample_track()]);
        let blocks = MidiDissector.dissect(&data);
        let header = find_block(&blocks, "Header chunk (MThd)");
        assert_eq!(header.range, ByteRange::new(0, 14));
        assert!(has_child(header, "Chunk ID: MThd"));
        assert!(has_child(header, "Length: 6"));
        assert!(has_child(header, "Format: 1 (multi-track)"));
        assert!(has_child(header, "Track count: 1"));
        let div = find_block(&header.children, "Division: 480 ticks per quarter note");
        assert_eq!(div.range, ByteRange::new(12, 14));
    }

    #[test]
    fn dissect_parses_smpte_division() {
        let data = build_midi(0, 0xE728, &[]); // -25 fps, 40 ticks/frame
        let blocks = MidiDissector.dissect(&data);
        let header = find_block(&blocks, "Header chunk (MThd)");
        assert!(has_child(header, "Division: SMPTE 25 fps, 40 ticks/frame"));
    }

    #[test]
    fn dissect_parses_track_events() {
        let track = sample_track();
        let data = build_midi(0, 480, &[&track]);
        let blocks = MidiDissector.dissect(&data);
        let t = find_block(&blocks, "Track 1 (MTrk): \"Piano\" — 11 events");
        assert_eq!(t.range, ByteRange::new(14, 14 + 8 + track.len() as u64));
        let base = 22u64;
        let ev = |label: &str, s: u64, e: u64| {
            let b = find_block(&t.children, label);
            assert_eq!(b.range, ByteRange::new(base + s, base + e), "{label}");
            b
        };
        ev("Δ0: Track Name: \"Piano\"", 0, 9);
        let tempo = ev("Δ0: Set Tempo: 500000 µs/quarter (120.00 BPM)", 9, 16);
        assert!(has_child(tempo, "Type: 0x51 (Set Tempo)"));
        ev("Δ0: Time Signature: 4/4", 16, 24);
        ev("Δ0: Key Signature: D major", 24, 30);
        ev("Δ0: Program Change ch 1 0 (Acoustic Grand Piano)", 30, 33);
        let on = ev("Δ0: Note On ch 1 C4 vel 100", 33, 37);
        assert!(has_child(on, "Note: C4 (60)"));
        let off = ev(
            "Δ480: Note On ch 1 C4 vel 0 (= Note Off) (running status)",
            37,
            41,
        );
        assert_eq!(
            find_block(&off.children, "Delta time: 480").range,
            ByteRange::new(base + 37, base + 39)
        );
        ev("Δ0: Control Change ch 1 Volume = 100", 41, 45);
        ev("Δ0: Pitch Bend ch 1 0", 45, 49);
        ev("Δ0: SysEx, 3 bytes", 49, 55);
        ev("Δ0: End of Track", 55, 59);
    }

    #[test]
    fn dissect_caps_events_per_track() {
        let mut track = Vec::new();
        for _ in 0..(MAX_EVENTS_PER_TRACK + 10) {
            track.extend_from_slice(&[0x00, 0x90, 0x40, 0x40]);
        }
        track.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]);
        let data = build_midi(0, 96, &[&track]);
        let blocks = MidiDissector.dissect(&data);
        let t = &blocks[1];
        let more = find_block(&t.children, "(11 more events not shown)");
        let start = 22 + 4 * MAX_EVENTS_PER_TRACK as u64;
        assert_eq!(more.range, ByteRange::new(start, data.len() as u64));
    }

    #[test]
    fn dissect_shows_unknown_chunks() {
        let mut data = build_midi(0, 96, &[&[0x00, 0xFF, 0x2F, 0x00]]);
        data.extend(chunk(b"XFIH", &[1, 2, 3]));
        let blocks = MidiDissector.dissect(&data);
        let unk = find_block(&blocks, "Unknown chunk: XFIH");
        assert_eq!(unk.range, ByteRange::new(26, 37));
        assert_eq!(
            find_block(&unk.children, "Chunk data").range,
            ByteRange::new(34, 37)
        );
    }

    #[test]
    fn key_and_note_names() {
        assert_eq!(key_name(-3, 0), "Eb major");
        assert_eq!(key_name(0, 1), "A minor");
        assert_eq!(note_name(0), "C-1");
        assert_eq!(note_name(69), "A4");
    }

    #[test]
    fn dissect_parses_rmid_wrapper() {
        let smf = build_midi(0, 96, &[&[0x00, 0xFF, 0x2F, 0x00]]);
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&((4 + 8 + smf.len()) as u32).to_le_bytes());
        data.extend_from_slice(b"RMID");
        data.extend_from_slice(b"data");
        data.extend_from_slice(&(smf.len() as u32).to_le_bytes());
        data.extend_from_slice(&smf);
        assert!(MidiDissector.matches(&data));
        assert_eq!(super::super::identify(&data), "MIDI");

        let blocks = MidiDissector.dissect(&data);
        find_block(&blocks, "RIFF header");
        let data_chunk = find_block(&blocks, "data chunk");
        let smf_block = find_block(&data_chunk.children, "Standard MIDI File");
        assert_eq!(smf_block.range, ByteRange::new(20, data.len() as u64));
        let header = find_block(&smf_block.children, "Header chunk (MThd)");
        assert_eq!(header.range, ByteRange::new(20, 34));
        find_block(&smf_block.children, "Track 1 (MTrk) — 1 event");
    }

    #[test]
    fn identify_reports_midi() {
        let data = build_midi(1, 480, &[&sample_track()]);
        assert_eq!(super::super::identify(&data), "MIDI");
    }
}
