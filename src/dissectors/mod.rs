mod bmp;
mod elf;
mod generic;
mod gif;
mod ico;
mod jpeg;
mod macho;
mod ogg;
mod pe;
mod png;
mod tar;
mod wav;
mod webp;
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
        Box::new(macho::MachoDissector),
        Box::new(wav::WavDissector),
        Box::new(ogg::OggDissector),
        Box::new(webp::WebpDissector),
        Box::new(png::PngDissector),
        Box::new(bmp::BmpDissector),
        Box::new(ico::IcoDissector),
        Box::new(zip::ZipDissector),
        Box::new(tar::TarDissector),
        Box::new(gif::GifDissector),
        Box::new(jpeg::JpegDissector),
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
