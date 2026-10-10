//! MS-DOS .COM executables.
//!
//! A .COM file has no header and no magic: DOS copies the raw image to
//! CS:0100h (after the 256-byte PSP) and jumps to its first byte. Detection
//! is therefore a deliberately conservative heuristic, and this dissector is
//! registered last, just before the generic fallback.

use super::{Block, ByteRange, Dissector};

/// The image must fit in one 64 KiB segment after the PSP, minus a little
/// room for the initial stack word.
const MAX_COM_SIZE: usize = 0xFF00;
/// Offset at which DOS loads the image within its segment.
const LOAD_OFFSET: usize = 0x100;
/// For entry instructions other than a jump, an INT 21h/20h must appear
/// within this many bytes of the start.
const EARLY_INT_WINDOW: usize = 32;
/// Files whose bytes are at least this percentage printable ASCII are text.
const MAX_PRINTABLE_PERCENT: usize = 90;
/// Maximum number of INT 21h sites listed.
const MAX_INT21_LISTED: usize = 64;

pub struct DosComDissector;

impl Dissector for DosComDissector {
    fn name(&self) -> &'static str {
        "DOS COM"
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < 2 || data.len() > MAX_COM_SIZE {
            return false;
        }
        // MZ/ZM files are EXEs even when named .COM; DOS checks this too.
        if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
            return false;
        }
        if mostly_printable(data) {
            return false;
        }
        let Some(entry) = decode_entry(data) else {
            return false;
        };
        match entry.target {
            // A jump must land inside the image, past itself.
            Some(target) => {
                target >= entry.len
                    && target < data.len()
                    && find_dos_int(data, data.len()).is_some()
            }
            // Anything else must reach an INT 21h/20h almost immediately.
            None => find_dos_int(data, EARLY_INT_WINDOW).is_some(),
        }
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        if data.is_empty() {
            return Vec::new();
        }
        let len = data.len();
        let mut children = Vec::new();

        let entry = decode_entry(data);
        match &entry {
            Some(entry) => children.push(Block::leaf(
                format!("Entry (CS:0100): {}", entry.text),
                span(0, entry.len.min(len)),
            )),
            None => children.push(Block::leaf(
                format!(
                    "Entry (CS:0100): unrecognised or truncated ({:02X}h …)",
                    data[0]
                ),
                span(0, 1),
            )),
        }

        if let Some(entry) = &entry
            && let Some(target) = entry.target
        {
            if target >= entry.len && target < len {
                if target > entry.len {
                    children.push(Block::leaf(
                        format!(
                            "Bytes skipped by entry jump ({:04X}h–{:04X}h, likely data)",
                            LOAD_OFFSET + entry.len,
                            LOAD_OFFSET + target - 1
                        ),
                        span(entry.len, target),
                    ));
                }
                children.push(Block::leaf(
                    format!(
                        "Jump target (CS:{:04X}h) onward, likely code",
                        LOAD_OFFSET + target
                    ),
                    span(target, len),
                ));
            } else {
                children.push(Block::leaf(
                    format!(
                        "Jump target CS:{:04X}h is outside the image",
                        (LOAD_OFFSET + target) & 0xFFFF
                    ),
                    span(0, entry.len.min(len)),
                ));
            }
        }

        if let Some(ints) = int21_block(data) {
            children.push(ints);
        }

        vec![
            Block::node(
                format!(
                    "Code/data image ({len} bytes, loaded at 0100h–{:04X}h)",
                    LOAD_OFFSET + len - 1
                ),
                span(0, len),
                children,
            )
            .expanded(),
        ]
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

fn mostly_printable(data: &[u8]) -> bool {
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    printable * 100 >= data.len() * MAX_PRINTABLE_PERCENT
}

/// Offset of the first INT 21h (CD 21) or INT 20h (CD 20) starting within
/// the first `limit` bytes.
fn find_dos_int(data: &[u8], limit: usize) -> Option<usize> {
    (0..limit.min(data.len().saturating_sub(1)))
        .find(|&i| data[i] == 0xCD && matches!(data[i + 1], 0x20 | 0x21))
}

/// The first instruction at CS:0100, for the recognised entry forms.
struct Entry {
    /// Instruction length in bytes.
    len: usize,
    text: String,
    /// File offset a JMP lands on, wrapped to the 64 KiB segment.
    target: Option<usize>,
}

const REG16: [&str; 8] = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"];
const REG8: [&str; 8] = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"];
const SREG: [&str; 4] = ["ES", "CS", "SS", "DS"];

fn decode_entry(data: &[u8]) -> Option<Entry> {
    let op = *data.first()?;
    let entry = |len: usize, text: String| Entry {
        len,
        text,
        target: None,
    };
    match op {
        0xE9 => {
            let rel = read_u16_le(data, 1)? as usize;
            let target = (3 + rel) & 0xFFFF;
            Some(Entry {
                len: 3,
                text: format!("JMP {:04X}h", (LOAD_OFFSET + target) & 0xFFFF),
                target: Some(target),
            })
        }
        0xEB => {
            let rel = *data.get(1)? as i8;
            let target = (2 + rel as isize) as usize & 0xFFFF;
            Some(Entry {
                len: 2,
                text: format!("JMP SHORT {:04X}h", (LOAD_OFFSET + target) & 0xFFFF),
                target: Some(target),
            })
        }
        0xB0..=0xB7 => {
            let imm = *data.get(1)?;
            Some(entry(
                2,
                format!("MOV {}, {imm:02X}h", REG8[(op - 0xB0) as usize]),
            ))
        }
        0xB8..=0xBF => {
            let imm = read_u16_le(data, 1)?;
            Some(entry(
                3,
                format!("MOV {}, {imm:04X}h", REG16[(op - 0xB8) as usize]),
            ))
        }
        // XOR/SUB reg16, same reg16 (register clear).
        0x31 | 0x33 | 0x29 | 0x2B => {
            let modrm = *data.get(1)?;
            let reg = (modrm >> 3) & 7;
            if modrm & 0xC0 != 0xC0 || modrm & 7 != reg {
                return None;
            }
            let mnemonic = if op & 0xF0 == 0x30 { "XOR" } else { "SUB" };
            let r = REG16[reg as usize];
            Some(entry(2, format!("{mnemonic} {r}, {r}")))
        }
        // MOV reg16, Sreg (typically MOV AX, CS).
        0x8C => {
            let modrm = *data.get(1)?;
            let sreg = ((modrm >> 3) & 7) as usize;
            if modrm & 0xC0 != 0xC0 || sreg >= SREG.len() {
                return None;
            }
            Some(entry(
                2,
                format!("MOV {}, {}", REG16[(modrm & 7) as usize], SREG[sreg]),
            ))
        }
        0x0E => Some(entry(1, "PUSH CS".into())),
        0x1E => Some(entry(1, "PUSH DS".into())),
        0xFA => Some(entry(1, "CLI".into())),
        0xFC => Some(entry(1, "CLD".into())),
        _ => None,
    }
}

fn int21_function_name(ah: u8) -> Option<&'static str> {
    Some(match ah {
        0x00 => "terminate program",
        0x01 => "read char with echo",
        0x02 => "write char",
        0x06 => "direct console I/O",
        0x07 => "direct char input",
        0x08 => "char input without echo",
        0x09 => "print string",
        0x0A => "buffered input",
        0x0B => "check input status",
        0x0C => "flush buffer and read",
        0x0E => "select disk",
        0x19 => "get current drive",
        0x1A => "set DTA",
        0x25 => "set interrupt vector",
        0x2A => "get date",
        0x2C => "get time",
        0x30 => "get DOS version",
        0x31 => "terminate and stay resident",
        0x35 => "get interrupt vector",
        0x36 => "get free disk space",
        0x39 => "create directory",
        0x3A => "remove directory",
        0x3B => "change directory",
        0x3C => "create file",
        0x3D => "open file",
        0x3E => "close file",
        0x3F => "read file",
        0x40 => "write file",
        0x41 => "delete file",
        0x42 => "seek",
        0x43 => "get/set attributes",
        0x44 => "IOCTL",
        0x47 => "get current directory",
        0x48 => "allocate memory",
        0x49 => "free memory",
        0x4A => "resize memory",
        0x4B => "exec",
        0x4C => "exit",
        0x4D => "get return code",
        0x4E => "find first",
        0x4F => "find next",
        0x56 => "rename file",
        0x57 => "get/set file date",
        _ => return None,
    })
}

/// Lists CD 21 byte pairs, naming the function when AH is set by an
/// immediately preceding MOV AH, imm8 or MOV AX, imm16.
fn int21_block(data: &[u8]) -> Option<Block> {
    let sites: Vec<usize> = data
        .windows(2)
        .enumerate()
        .filter(|(_, w)| w[0] == 0xCD && w[1] == 0x21)
        .map(|(i, _)| i)
        .collect();
    if sites.is_empty() {
        return None;
    }

    let mut children = Vec::new();
    for &i in sites.iter().take(MAX_INT21_LISTED) {
        let addr = LOAD_OFFSET + i;
        let (start, ah) = if i >= 2 && data[i - 2] == 0xB4 {
            (i - 2, Some(data[i - 1]))
        } else if i >= 3 && data[i - 3] == 0xB8 {
            (i - 3, Some(data[i - 1]))
        } else {
            (i, None)
        };
        let label = match ah {
            Some(ah) => match int21_function_name(ah) {
                Some(name) => format!("{addr:04X}h: possible INT 21h, AH={ah:02X}h ({name})"),
                None => format!("{addr:04X}h: possible INT 21h, AH={ah:02X}h"),
            },
            None => format!("{addr:04X}h: possible INT 21h"),
        };
        children.push(Block::leaf(label, span(start, i + 2)));
    }

    let first = children.first()?.range.start;
    let last = children.last()?.range.end;
    let label = if sites.len() > MAX_INT21_LISTED {
        format!(
            "Possible INT 21h calls ({}, first {MAX_INT21_LISTED} shown)",
            sites.len()
        )
    } else {
        format!("Possible INT 21h calls ({})", sites.len())
    };
    Some(Block::node(label, ByteRange::new(first, last), children))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A "hello" COM: JMP over the string, print it, then exit.
    fn build_com() -> Vec<u8> {
        let mut data = Vec::new();
        let msg = b"Hello$";
        // JMP to code after the string (offset 3 + msg.len()).
        data.push(0xE9);
        data.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        data.extend_from_slice(msg);
        // MOV DX, 0103h; MOV AH, 09h; INT 21h
        data.extend_from_slice(&[0xBA, 0x03, 0x01, 0xB4, 0x09, 0xCD, 0x21]);
        // MOV AX, 4C00h; INT 21h
        data.extend_from_slice(&[0xB8, 0x00, 0x4C, 0xCD, 0x21]);
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
    fn matches_jump_entry() {
        assert!(DosComDissector.matches(&build_com()));
    }

    #[test]
    fn matches_short_jump_entry() {
        // JMP SHORT +2; 2 data bytes; INT 20h
        let data = [0xEB, 0x02, 0x00, 0x00, 0xCD, 0x20];
        assert!(DosComDissector.matches(&data));
    }

    #[test]
    fn matches_mov_followed_by_int21() {
        // MOV AH, 09h; MOV DX, 0109h; INT 21h; INT 20h; "Hi$"
        let data = [
            0xB4, 0x09, 0xBA, 0x09, 0x01, 0xCD, 0x21, 0xCD, 0x20, b'H', b'i', b'$',
        ];
        assert!(DosComDissector.matches(&data));
    }

    #[test]
    fn rejects_jump_out_of_range() {
        let mut data = build_com();
        data[1] = 0x00;
        data[2] = 0x10; // JMP 1103h, beyond the file
        assert!(!DosComDissector.matches(&data));
        // Backwards short jump lands before 0100h.
        assert!(!DosComDissector.matches(&[0xEB, 0xFC, 0xCD, 0x20]));
    }

    #[test]
    fn rejects_without_dos_int() {
        let mut data = build_com();
        for b in data.iter_mut() {
            if *b == 0xCD {
                *b = 0x90;
            }
        }
        assert!(!DosComDissector.matches(&data));
    }

    #[test]
    fn rejects_mov_without_early_int() {
        let mut data = vec![0xB4, 0x09];
        data.extend(std::iter::repeat_n(0x90, 40));
        data.extend_from_slice(&[0xCD, 0x21]);
        assert!(!DosComDissector.matches(&data));
    }

    #[test]
    fn rejects_mz_empty_and_unrelated() {
        assert!(!DosComDissector.matches(b""));
        assert!(!DosComDissector.matches(&[0xE9]));
        assert!(!DosComDissector.matches(&[0xE9, 0x00]));
        let mut mz = build_com();
        mz[0] = b'M';
        mz[1] = b'Z';
        assert!(!DosComDissector.matches(&mz));
        assert!(!DosComDissector.matches(&[0x00, 0x01, 0xCD, 0x21]));
        let mut big = build_com();
        big.resize(MAX_COM_SIZE + 1, 0);
        assert!(!DosComDissector.matches(&big));
    }

    #[test]
    fn rejects_plain_text() {
        let text = b"Hello, world! This is a plain ASCII text file.\n\
            It has a few lines, and mentions CD 21 and MZ.\r\n";
        assert!(!DosComDissector.matches(text));
        assert_eq!(super::super::identify(text), "Data");
        // Even with a COM-like first byte, mostly-printable data is text.
        let mut latin1 = vec![0xE9, 0x03, 0x00];
        latin1.extend_from_slice(b"t\xCD! is an accented capital I, followed by lots of text...");
        assert!(!DosComDissector.matches(&latin1));
    }

    #[test]
    fn other_formats_are_not_com() {
        let samples: [(&[u8], &str); 4] = [
            (b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", "PDF"),
            (b"\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x03\xCD\x21", "gzip"),
            (b"BZh91AY&SY\xCD\x21\x00\x00\x00\x00", "bzip2"),
            (b"\x7FELF\x02\x01\x01\x00", "ELF"),
        ];
        for (data, _) in samples {
            assert_ne!(super::super::identify(data), "DOS COM");
        }
        // An MZ executable, even with a jump-like body, is never COM.
        let mut mz = vec![b'M', b'Z'];
        mz.extend_from_slice(&[0xE9, 0x00, 0x00, 0xCD, 0x21]);
        assert_ne!(super::super::identify(&mz), "DOS COM");
    }

    #[test]
    fn dissect_produces_expected_blocks() {
        let data = build_com();
        let blocks = DosComDissector.dissect(&data);
        assert_eq!(blocks.len(), 1);
        let image = &blocks[0];
        assert_eq!(
            image.label,
            format!(
                "Code/data image ({} bytes, loaded at 0100h–{:04X}h)",
                data.len(),
                0x100 + data.len() - 1
            )
        );
        assert_eq!(image.range, ByteRange::new(0, data.len() as u64));

        let entry = find_block(&image.children, "Entry (CS:0100): JMP 0109h");
        assert_eq!(entry.range, ByteRange::new(0, 3));
        let skipped = find_block(
            &image.children,
            "Bytes skipped by entry jump (0103h–0108h, likely data)",
        );
        assert_eq!(skipped.range, ByteRange::new(3, 9));
        let target = find_block(
            &image.children,
            "Jump target (CS:0109h) onward, likely code",
        );
        assert_eq!(target.range, ByteRange::new(9, data.len() as u64));

        let ints = find_block(&image.children, "Possible INT 21h calls (2)");
        assert_eq!(ints.range, ByteRange::new(12, data.len() as u64));
        let print = find_block(
            &ints.children,
            "010Eh: possible INT 21h, AH=09h (print string)",
        );
        assert_eq!(print.range, ByteRange::new(12, 16));
        let exit = find_block(&ints.children, "0113h: possible INT 21h, AH=4Ch (exit)");
        assert_eq!(exit.range, ByteRange::new(16, 21));
    }

    #[test]
    fn dissect_decodes_mov_entry() {
        let data = [0xB4, 0x09, 0xBA, 0x09, 0x01, 0xCD, 0x21, 0xCD, 0x20];
        let blocks = DosComDissector.dissect(&data);
        find_block(&blocks[0].children, "Entry (CS:0100): MOV AH, 09h");
        let data = [0xBC, 0xF0, 0x09, 0xB4, 0x19, 0xCD, 0x21];
        let blocks = DosComDissector.dissect(&data);
        find_block(&blocks[0].children, "Entry (CS:0100): MOV SP, 09F0h");
    }

    #[test]
    fn dissect_truncated_does_not_panic() {
        let data = build_com();
        for n in 0..data.len() {
            let blocks = DosComDissector.dissect(&data[..n]);
            if n == 0 {
                assert!(blocks.is_empty());
            } else {
                for block in &blocks[0].children {
                    assert!(block.range.end <= n as u64);
                }
            }
        }
        assert!(DosComDissector.dissect(&[0xE9]).len() == 1);
    }

    #[test]
    fn identify_reports_dos_com() {
        assert_eq!(super::super::identify(&build_com()), "DOS COM");
    }
}
