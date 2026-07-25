mod bridge;
mod dissect;
mod dissectors;

fn main() {
    let code = bridge::ffi::run_app();
    std::process::exit(code);
}
