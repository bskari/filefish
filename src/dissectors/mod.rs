mod bmp;
mod bzip2;
mod dex;
mod dol;
mod elf;
mod flac;
mod generic;
mod gif;
mod gzip;
mod ico;
mod java_class;
mod jpeg;
mod macho;
mod matroska;
mod midi;
mod mp3;
mod mp4;
mod ne;
mod nro;
mod ogg;
mod pdf;
mod pe;
mod png;
mod psd;
mod pyc;
mod rar;
mod rpm;
mod sevenzip;
mod sqlite;
mod swf;
mod tar;
mod wasm;
mod wav;
mod webp;
mod xz;
mod zip;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64, // exclusive (half-open), like Rust's Range<u64>
}

impl ByteRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}

pub struct Block {
    pub label: String,
    pub range: ByteRange,
    pub expandable: bool,
    pub default_expanded: bool,
    pub children: Vec<Block>,
}

impl Block {
    pub fn leaf(label: impl Into<String>, range: ByteRange) -> Self {
        Self {
            label: label.into(),
            range,
            expandable: false,
            default_expanded: false,
            children: Vec::new(),
        }
    }

    pub fn node(label: impl Into<String>, range: ByteRange, children: Vec<Block>) -> Self {
        Self {
            label: label.into(),
            range,
            expandable: true,
            default_expanded: false,
            children,
        }
    }

    pub fn expanded(mut self) -> Self {
        self.default_expanded = true;
        self
    }

    pub fn expanded_if(mut self, condition: bool) -> Self {
        self.default_expanded = condition;
        self
    }
}

pub trait Dissector {
    fn name(&self) -> &'static str;
    fn matches(&self, data: &[u8]) -> bool;
    fn dissect(&self, data: &[u8]) -> Vec<Block>;
}

fn dissectors() -> Vec<Box<dyn Dissector>> {
    vec![
        Box::new(elf::ElfDissector),
        Box::new(pe::PeDissector),
        Box::new(ne::NeDissector),
        Box::new(macho::MachoDissector),
        Box::new(dex::DexDissector),
        Box::new(java_class::JavaClassDissector),
        Box::new(wasm::WasmDissector),
        Box::new(rpm::RpmDissector),
        Box::new(nro::NroDissector),
        Box::new(wav::WavDissector),
        Box::new(midi::MidiDissector),
        Box::new(mp4::Mp4Dissector),
        Box::new(ogg::OggDissector),
        Box::new(flac::FlacDissector),
        Box::new(matroska::MatroskaDissector),
        Box::new(webp::WebpDissector),
        Box::new(png::PngDissector),
        Box::new(bmp::BmpDissector),
        // DOL has no magic, but nearly every DOL starts with 00 00 01 00 (text 0
        // at offset 0x100), which is also the ICO magic. DOL's structural check
        // is strict enough to go first.
        Box::new(dol::DolDissector),
        Box::new(ico::IcoDissector),
        Box::new(psd::PsdDissector),
        Box::new(sqlite::SqliteDissector),
        Box::new(bzip2::Bzip2Dissector),
        Box::new(zip::ZipDissector),
        Box::new(xz::XzDissector),
        Box::new(sevenzip::SevenZipDissector),
        Box::new(rar::RarDissector),
        Box::new(tar::TarDissector),
        Box::new(gif::GifDissector),
        Box::new(jpeg::JpegDissector),
        Box::new(swf::SwfDissector),
        Box::new(pyc::PycDissector),
        Box::new(mp3::Mp3Dissector),
        Box::new(gzip::GzipDissector),
        Box::new(pdf::PdfDissector),
    ]
}

fn matched_dissector(data: &[u8]) -> Box<dyn Dissector> {
    for dissector in dissectors() {
        if dissector.matches(data) {
            return dissector;
        }
    }
    Box::new(generic::GenericDissector)
}

pub fn identify(data: &[u8]) -> &'static str {
    matched_dissector(data).name()
}

pub fn dissect(data: &[u8]) -> Vec<Block> {
    matched_dissector(data).dissect(data)
}
