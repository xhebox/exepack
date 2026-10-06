# exepack

Embed items into a single executable with compression.

ELF and Mach-O inspired by [libsui](https://github.com/denoland/sui), PE based on [editpe](https://github.com/Systemcluster/editpe).

## Usage

```
exepack --main <executable> --output <image> [--compress gzip|none] --item NAME=PATH [--item NAME=PATH ...]
```

```console
$ exepack --main target/debug/myapp --output build/dist/myapp \
    --item test_item=build/test ...
$ build/dist/myapp
```

Repeat `--item` once per item; names must be unique.

Compression defaults to `gzip`; use `--compress none` to embed the original bytes.

The output copies the permissions of `--main`, setuid and setgid included.

## Reading items back

```rust
let mut kernel = exepack::format::find_loaded("test_item")?;
let mut bytes = Vec::new();
kernel.read_to_end(&mut bytes)?;
```

`format::find_loaded` returns `anyhow::Result`; a missing item is reported as an error naming the requested item.

## License

MIT
