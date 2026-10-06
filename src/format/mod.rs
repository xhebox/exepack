use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};

use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use flate2::Compression as Level;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use strum::FromRepr;

#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "windows")]
mod pe;

#[derive(Clone, Copy, FromRepr, ValueEnum)]
#[repr(u8)]
pub enum Compression {
	None = 0,
	Gzip = 1,
}

impl Compression {
	/// Compress `input` onto the end of `out`, tag first. The caller clears `out` between items.
	fn encode(self, mut input: impl Read, out: &mut Vec<u8>) -> Result<()> {
		out.push(self as u8);
		match self {
			Self::Gzip => {
				let mut encoder = GzEncoder::new(&mut *out, Level::default());
				io::copy(&mut input, &mut encoder)?;
				encoder.finish()?;
			}
			Self::None => {
				input.read_to_end(out)?;
			}
		}
		Ok(())
	}

	fn decode<'a>(stored: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
		let (&tag, data) = stored
			.split_first()
			.ok_or_else(|| anyhow::anyhow!("the item carries no compression tag"))?;
		let reader = Cursor::new(data);
		match Self::from_repr(tag) {
			Some(Self::Gzip) => Ok(Box::new(GzDecoder::new(reader))),
			Some(Self::None) => Ok(Box::new(reader)),
			None => bail!("the item is compressed under tag {tag}, which this build does not know"),
		}
	}
}

pub enum Container {
	Elf,
	MachO,
	Pe,
}

impl Container {
	pub fn detect(image: &[u8]) -> Result<Self> {
		if image.starts_with(b"\xca\xfe\xba\xbe") || image.starts_with(b"\xbe\xba\xfe\xca") {
			bail!("a universal Mach-O image is not packed; thin it to one architecture first");
		}
		if image.starts_with(b"\x7fELF") {
			return Ok(Self::Elf);
		}
		if image.starts_with(b"\xcf\xfa\xed\xfe") {
			return Ok(Self::MachO);
		}
		if image.starts_with(b"MZ") {
			return Ok(Self::Pe);
		}
		bail!("the image is neither ELF, Mach-O, nor PE")
	}

	pub fn append<W: Write, R: Read>(
		&self,
		image: &[u8],
		items: impl IntoIterator<Item = (String, R)>,
		compression: Compression,
		output: &mut W,
	) -> Result<()> {
		let mut items = items.into_iter();
		let mut names = HashSet::new();
		// The compressed bytes land in the caller's reusable buffer; an empty returned name signals the end of the items.
		let store = |out: &mut Vec<u8>| -> Result<String> {
			let Some((name, input)) = items.next() else {
				return Ok(String::new());
			};
			ensure!(!name.is_empty(), "item name cannot be empty");
			if !names.insert(name.clone()) {
				bail!("item name {name:?} is embedded twice");
			}
			compression.encode(input, out)?;
			Ok(name)
		};

		match self {
			#[cfg(target_os = "linux")]
			Self::Elf => elf::append(image, store, output),
			#[cfg(target_os = "macos")]
			Self::MachO => macho::append(image, store, output),
			#[cfg(target_os = "windows")]
			Self::Pe => pe::append(image, store, output),
			_ => bail!("embedding items in this image requires the platform it targets"),
		}
	}
}

/// The bytes embedded under `name`, decompressed as they are read.
pub fn find_loaded(name: &str) -> Result<Box<dyn Read + '_>> {
	let stored = cfg_select! {
		target_os = "linux" => { elf::find(name)? }
		target_os = "macos" => { macho::find(name)? }
		target_os = "windows" => { pe::find(name)? }
		_ => { bail!("reading embedded items is unsupported on this platform") }
	};
	Compression::decode(stored)
}
