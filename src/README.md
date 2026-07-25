# src

Rust backend for filefish, a file-format viewer with a Qt (C++) GUI.

- `main.rs` — entry point; delegates to the C++ GUI via `bridge::ffi::run_app`.
- `bridge.rs` — the `cxx-qt` FFI boundary between Rust and C++. Defines the
  types (`FileInfo`, `FfiBlock`) and functions shared across the boundary,
  and exposes `dissect_file` (reads a file, runs it through `dissectors`,
  and flattens the resulting `Block` tree into a flat `Vec<FfiBlock>` for
  the C++ side).
- `dissect.rs` — small standalone helpers for the GUI, e.g. `hex_dump`.
- `dissectors/` — per-file-format parsers that turn raw bytes into a tree
  of structural `Block`s. See `dissectors/README.md`.

The C++/Qt side (window, widgets, `mainwindow.h`) lives outside `src/` and
is wired in via `build.rs` and `cxx-qt-build`.
