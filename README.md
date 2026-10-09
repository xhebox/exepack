# exepack

Embed items into a single executable, with optional compression.

ELF and Mach-O inspired by [libsui](https://github.com/denoland/sui), PE based on [editpe](https://github.com/Systemcluster/editpe).

## Install

```
cargo binstall exepack
```

Prebuilt binaries come from the GitHub releases; `cargo install exepack` builds from source.

## Usage

```
exepack --main <executable> --output <image> [--compress none|zstd|gzip[:LEVEL]|brotli[:LEVEL]] --item NAME=PATH [--item NAME=PATH ...]
```

```console
$ exepack --main target/debug/myapp --output build/dist/myapp \
    --item test_item=build/test ...
$ build/dist/myapp
```

Repeat `--item` once per item; names must be unique.

Compression defaults to `gzip`; `--compress none` embeds the original bytes. `gzip` takes a level in 0-9 (default 6) and `brotli` one in 0-11 (default 11), as in `--compress brotli:5`.

The output copies the permissions of `--main`, setuid and setgid included.

## Reading items back

```rust
let mut kernel = exepack::find_loaded("test_item")?;
let mut bytes = Vec::new();
kernel.read_to_end(&mut bytes)?;
```

A build that carries no such item, such as an unpacked one, fails with `ErrorKind::NotFound`, so it can fall back:

```rust
match exepack::find_loaded("test_item") {
    Ok(item) => item,
    Err(error) if error.kind() == exepack::ErrorKind::NotFound => Box::new(std::fs::File::open("test_item")?),
    Err(error) => return Err(error.into()),
}
```

## License

MIT
