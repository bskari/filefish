# Dissectors

A dissector parses a file's raw bytes into a tree of labeled `Block`s that
describe its structure (e.g. headers, sections, fields), which the UI can
then render and let users expand/inspect.

## The `Dissector` trait

Each file format implements `Dissector` (see `mod.rs`):

- `fn name(&self) -> &'static str` — short, human-readable name for the
  format (e.g. `"ELF"`), used to report what was identified.
- `fn matches(&self, data: &[u8]) -> bool` — cheap check (usually a magic
  number/header check) that returns whether this dissector can handle the
  given data.
- `fn dissect(&self, data: &[u8]) -> Vec<Block>` — parses `data` and returns
  the top-level `Block`s describing its structure.

## Blocks

A `Block` is a labeled, byte-addressed span:

- `label` — display name (e.g. `"e_shoff"`).
- `range` — the `ByteRange` (`start..end`, half-open) it covers in the file.
- `expandable` / `children` — leaf blocks (`Block::leaf`) have no children;
  container blocks (`Block::node`) hold nested `Block`s covering sub-ranges.

## Adding a new dissector

1. Create a new module (e.g. `src/dissectors/myformat.rs`) implementing
   `Dissector`.
2. Add `mod myformat;` in `mod.rs`.
3. Register an instance in `dissectors()` in `mod.rs`.

Dissectors are tried in the order returned by `dissectors()`; the first
whose `matches` returns true is used. If none match, `GenericDissector`
(`generic.rs`) is used as a fallback, producing a single block spanning
the whole file.
