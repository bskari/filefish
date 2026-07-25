use crate::dissect;
use crate::dissectors::{self, Block};

#[cxx::bridge]
pub mod ffi {
    struct FileInfo {
        size: u64,
        file_type: String,
        hex_dump: String,
        blocks: Vec<FfiBlock>,
    }

    struct FfiBlock {
        parent: i32, // index into `blocks`, -1 for a root block
        label: String,
        start: u64,
        end: u64,
        expandable: bool,
    }

    unsafe extern "C++" {
        include!("mainwindow.h");

        fn run_app() -> i32;
    }

    extern "Rust" {
        fn dissect_file(path: &str) -> Result<FileInfo>;
    }
}

fn flatten(blocks: Vec<Block>, parent: i32, out: &mut Vec<ffi::FfiBlock>) {
    for block in blocks {
        let index = out.len() as i32;
        out.push(ffi::FfiBlock {
            parent,
            label: block.label,
            start: block.range.start,
            end: block.range.end,
            expandable: block.expandable,
        });
        flatten(block.children, index, out);
    }
}

fn dissect_file(path: &str) -> Result<ffi::FileInfo, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    let mut blocks = Vec::new();
    flatten(dissectors::dissect(&data), -1, &mut blocks);

    Ok(ffi::FileInfo {
        size: data.len() as u64,
        file_type: dissectors::identify(&data).to_string(),
        hex_dump: dissect::hex_dump(&data),
        blocks,
    })
}
