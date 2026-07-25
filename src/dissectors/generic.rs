use super::{Block, ByteRange, Dissector};

pub struct GenericDissector;

impl Dissector for GenericDissector {
    fn name(&self) -> &'static str {
        "Data"
    }

    fn matches(&self, _data: &[u8]) -> bool {
        true
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        vec![Block::leaf("Data", ByteRange::new(0, data.len() as u64))]
    }
}
