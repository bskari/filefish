# How to add a dissector

A new format needs one new Rust file and two lines in
`src/dissectors/mod.rs`. No changes are needed in `bridge.rs`, the C++/Qt
GUI, `build.rs` or `Cargo.toml`. The MP3 commit (cc4b399) is a reference: it
touched only `mp3.rs` and `mod.rs`.

A dissector turns a file's raw bytes into a tree of labeled `Block`s, each
covering a half-open `ByteRange`. `bridge.rs` calls `dissectors::identify`
and `dissectors::dissect`, flattens the tree, and hands it to the GUI, so any
format registered in `mod.rs` shows up automatically. See
`src/dissectors/README.md` for the `Dissector` trait and `Block` type.

## 1. Add the module

Create `src/dissectors/<format>.rs` with a unit struct that implements
`Dissector`:

```rust
use super::{Block, ByteRange, Dissector};

const MYFMT_MAGIC: &[u8] = b"MYFM";

pub struct MyFmtDissector;

impl Dissector for MyFmtDissector {
    fn name(&self) -> &'static str {
        "MyFmt"
    }

    fn matches(&self, data: &[u8]) -> bool {
        data.starts_with(MYFMT_MAGIC)
    }

    fn dissect(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        if data.len() < 16 {
            return blocks;
        }
        blocks.push(
            Block::node(
                "Header",
                ByteRange::new(0, 16),
                vec![
                    Block::leaf("Magic: MYFM", ByteRange::new(0, 4)),
                    // ...one leaf per field, with the decoded value in the label
                ],
            )
            .expanded(),
        );
        blocks
    }
}
```

| Method    | What it must do |
| --------- | --------------- |
| `name`    | Short display name, e.g. `"BMP"`. Shown as the file type in the GUI. |
| `matches` | Cheap check, usually a magic number. Must never panic and must reject short or empty input. |
| `dissect` | Return top-level `Block`s. Use `Block::leaf` for fields and `Block::node` for containers; `.expanded()` / `.expanded_if(cond)` open a node by default. |

Conventions the existing dissectors follow:

- Treat input as untrusted. Read with bounds-checked helpers like
  `read_u32(data, off) -> Option<u32>` built on `data.get(..)`, and clamp
  ranges to `data.len()`. A truncated file should yield fewer blocks, not a
  panic.
- Put decoded values in labels (`"Width: 4"`, `"Compression: BI_RGB"`) and
  map enum codes to names.
- Keep child ranges inside their parent's range; `end` is exclusive.
- Keep helpers private to the module; each file defines its own `read_*`
  functions.

## 2. Register it in mod.rs

1. Add `mod myfmt;` to the alphabetical module list at the top.
2. Add `Box::new(myfmt::MyFmtDissector),` to the `vec!` in `dissectors()`.

Order in `dissectors()` matters: the first dissector whose `matches` returns
true wins, and `GenericDissector` is the fallback.

- Strong magic at offset 0 (ELF, PNG, SQLite) can go near the top.
- Formats that share a container magic must check the sub-type in `matches`
  (WAV and WebP both start with `RIFF` and check bytes 8..12).
- Weak or heuristic signatures go near the end. MP3 sits just before gzip
  because it can match on frame sync bits alone.

If the new format could be mistaken for an existing one, or vice versa,
tighten `matches` rather than relying on order alone.

## 3. Add tests

Tests live in a `#[cfg(test)] mod tests` block at the bottom of the same
file. There are no binary fixtures; each test builds a minimal valid file in
code with a `build_<format>(...)` helper, and a `find_block(blocks, label)`
helper locates blocks by label. The tests in `bmp.rs` are a good template.
Cover at least:

- `matches` accepts a built file.
- `matches` rejects empty input, unrelated bytes and a truncated header.
- `dissect` on truncated input returns fewer blocks without panicking.
- `dissect` on a built file produces the expected labels and exact
  `ByteRange`s.
- `super::super::identify(&data)` returns the new name, which checks
  registration and match order.

Run `cargo test`, then open a real sample file with `cargo run` to check the
tree renders sensibly.

## Checklist

- [ ] `src/dissectors/<format>.rs` implementing `name`, `matches` and `dissect`
- [ ] `mod <format>;` added to `mod.rs`
- [ ] Instance added to `dissectors()` at the right position
- [ ] Unit tests, including an `identify` test
- [ ] `cargo test` passes and a real file renders in the GUI
