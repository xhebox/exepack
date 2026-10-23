# exepack

[![Test](https://github.com/xhebox/exepack/actions/workflows/test.yml/badge.svg)](https://github.com/xhebox/exepack/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/v/exepack.svg)](https://crates.io/crates/exepack)
[![docs.rs](https://img.shields.io/docsrs/exepack)](https://docs.rs/exepack)
[![License: MIT](https://img.shields.io/crates/l/exepack.svg)](https://github.com/xhebox/exepack/blob/main/LICENSE)

Embed items into a single executable, with optional compression.

ELF and Mach-O is highly inspired by [libsui](https://github.com/denoland/sui), PE based on [editpe](https://github.com/Systemcluster/editpe).

## Install

```
cargo binstall exepack
```

Prebuilt binaries come from the GitHub releases; `cargo install exepack` builds from source.

## Usage

```
exepack --main <executable> --output <image> [--compress none|lz4|gzip[:LEVEL]|brotli[:LEVEL]] --item NAME=PATH [--item NAME=PATH ...]
```

```console
$ exepack --main target/debug/myapp --output build/dist/myapp \
    --item test_item=build/test ...
$ build/dist/myapp
```

Repeat `--item` once per item; names must be unique.

Compression defaults to `lz4`; `--compress none` embeds the original bytes. `gzip` takes a level in 0-9 (default 6) and `brotli` one in 0-11 (default 11), as in `--compress brotli:5`.

The output copies the permissions of `--main`, setuid/setgid included. And also codesign/entitlements for Mach-O.

## Reading items back

```rust
let mut item = exepack::find_loaded("test_item")?;
let mut bytes = Vec::new();
item.read_to_end(&mut bytes)?;
```

`lz4`, `gzip` and `brotli` are Cargo features, all enabled by default, so a binary that only reads one format (or `none`) can disable the rest with `default-features = false`.

An item packed with `--compress none` is mapped as it is, and `Item::as_bytes` hands its bytes over without a copy.

A build that carries no such item, fails with `ErrorKind::NotFound`, so you can fallback:

```rust
let item: Box<dyn std::io::Read> = match exepack::find_loaded("test_item") {
    Ok(item) => Box::new(item),
    Err(error) if error.kind() == exepack::ErrorKind::NotFound => Box::new(std::fs::File::open("test_item")?),
    Err(error) => return Err(error.into()),
};
```

## Benchmarks

`task pack-time` and `task find-time` run the whole binary under
[hyperfine](https://github.com/sharkdp/hyperfine) —the first packs, the second starts a process that looks an item up,
packed and unpacked— and both report the memory it peaks at. The sizes each compression stores are pinned by a
snapshot test.
