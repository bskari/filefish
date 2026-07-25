mod bridge;
mod dissect;

fn main() {
    let code = bridge::ffi::run_app();
    std::process::exit(code);
}
