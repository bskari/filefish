mod bridge;
mod dissect;
mod dissectors;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = bridge::ffi::run_app(args);
    std::process::exit(code);
}
