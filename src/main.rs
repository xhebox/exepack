use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use exepack::{Compression, Container};

#[derive(Parser)]
#[command(version, about = "Embed items into a single executable")]
struct Cli {
	/// The executable the items are embedded in.
	#[arg(long)]
	main: PathBuf,
	/// The image to write: `main` carrying the items.
	#[arg(long)]
	output: PathBuf,
	/// Compression applied to each item: none, zstd, gzip[:0-9] (default 6) or brotli[:0-11] (default 11).
	#[arg(long, default_value = "gzip")]
	compress: Compression,
	/// An item to embed, as `NAME=PATH`; repeat once per item.
	#[arg(long = "item", value_name = "NAME=PATH", required = true)]
	items: Vec<String>,
}

fn main() -> Result<()> {
	let args = Cli::parse();

	// The names are settled before anything is read: a typo in the caller's list is worth saying before a few hundred megabytes are read.
	let mut named: Vec<(String, PathBuf)> = Vec::with_capacity(args.items.len());
	for spec in &args.items {
		let (name, path) = spec
			.split_once('=')
			.with_context(|| format!("--item {spec:?} is not NAME=PATH"))?;
		if name.is_empty() {
			bail!("item name cannot be empty");
		}
		if named.iter().any(|(seen, _)| seen.as_str() == name) {
			bail!("item name {name:?} is embedded twice");
		}
		named.push((name.to_owned(), PathBuf::from(path)));
	}

	let mut items = Vec::with_capacity(named.len());
	for (name, path) in &named {
		let file = std::fs::File::open(path)
			.with_context(|| format!("open item {name} from {}", path.display()))?;
		items.push((name.to_owned(), file));
	}

	let mut image = std::fs::File::open(&args.main)
		.with_context(|| format!("open the main executable {}", args.main.display()))?;
	// The output copy carries the permissions of the executable it was read from, setuid and setgid included.
	#[cfg(unix)]
	let mode = {
		use std::os::unix::fs::PermissionsExt;
		image
			.metadata()
			.with_context(|| format!("read the mode of {}", args.main.display()))?
			.permissions()
			.mode()
			& 0o7777
	};
	let mut bytes = Vec::new();
	image
		.read_to_end(&mut bytes)
		.context("read the main executable")?;
	let container = Container::detect(&bytes)?;

	let mut out = std::fs::File::create(&args.output)
		.with_context(|| format!("create {}", args.output.display()))?;
	container
		.append(&bytes, items, args.compress, &mut out)
		.with_context(|| format!("embed items in {}", args.main.display()))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&args.output, std::fs::Permissions::from_mode(mode))
			.with_context(|| format!("mark {} executable", args.output.display()))?;
	}
	Ok(())
}
