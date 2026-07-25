use crate::dissect;

#[cxx::bridge]
pub mod ffi {
    struct FileInfo {
        size: u64,
        hex_dump: String,
    }

    unsafe extern "C++" {
        include!("mainwindow.h");

        fn run_app() -> i32;
    }

    extern "Rust" {
        fn dissect_file(path: &str) -> Result<FileInfo>;
    }
}

fn dissect_file(path: &str) -> Result<ffi::FileInfo, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(ffi::FileInfo {
        size: data.len() as u64,
        hex_dump: dissect::hex_dump(&data),
    })
}
