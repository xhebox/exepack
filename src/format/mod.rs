use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};

use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use flate2::Compression as Level;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "macos")]
mod macho;
#[cfg(target_os = "windows")]
mod pe;

/// How each item is compressed, with the level for those that take one.
#[derive(Clone, Copy)]
pub enum Compression {
	None,
	/// Levels 0-9.
	Gzip(u32),
	/// Levels 0-11.
	Brotli(u32),
	/// ruzstd implements only its fastest level, zstd's 1.
	Zstd,
}

impl Compression {
	/// The tag stored ahead of each item, which reading it back dispatches on.
	fn tag(self) -> u8 {
		match self {
			Self::None => 0,
			Self::Gzip(_) => 1,
			Self::Brotli(_) => 2,
			Self::Zstd => 3,
		}
	}

	/// `self`, if its level is one the compression has.
	fn checked(self) -> Result<Self> {
		match self {
			Self::Gzip(level) => ensure!(level <= 9, "gzip takes a level in 0-9, not {level}"),
			Self::Brotli(level) => {
				ensure!(level <= 11, "brotli takes a level in 0-11, not {level}")
			}
			Self::None | Self::Zstd => {}
		}
		Ok(self)
	}

	/// Compress `input` onto the end of `out`, tag first. The caller clears `out` between items.
	fn encode(self, mut input: impl Read, out: &mut Vec<u8>) -> Result<()> {
		out.push(self.tag());
		match self {
			Self::Gzip(level) => {
				let mut encoder = GzEncoder::new(&mut *out, Level::new(level));
				io::copy(&mut input, &mut encoder)?;
				encoder.finish()?;
			}
			Self::Brotli(level) => {
				// The largest window brotli allows.
				let mut encoder = brotli::CompressorWriter::new(&mut *out, 4096, level, 24);
				io::copy(&mut input, &mut encoder)?;
				// Ends the stream; writing into a Vec cannot fail.
				encoder.into_inner();
			}
			Self::Zstd => {
				ruzstd::encoding::compress(
					input,
					&mut *out,
					ruzstd::encoding::CompressionLevel::Fastest,
				);
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
		match tag {
			0 => Ok(Box::new(reader)),
			1 => Ok(Box::new(GzDecoder::new(reader))),
			2 => Ok(Box::new(brotli::Decompressor::new(reader, 4096))),
			3 => Ok(Box::new(ruzstd::decoding::StreamingDecoder::new(reader)?)),
			_ => bail!("the item is compressed under tag {tag}, which this build does not know"),
		}
	}
}

/// `none`, `zstd`, or `gzip` and `brotli` with an optional `:LEVEL`, by default 6 and 11.
impl FromStr for Compression {
	type Err = anyhow::Error;

	fn from_str(spec: &str) -> Result<Self> {
		let (name, level) = match spec.split_once(':') {
			Some((name, level)) => (
				name,
				Some(
					level
						.parse()
						.with_context(|| format!("{level:?} is not a level"))?,
				),
			),
			None => (spec, None),
		};
		let compression = match (name, level) {
			("none", None) => Self::None,
			("gzip", level) => Self::Gzip(level.unwrap_or(6)),
			("brotli", level) => Self::Brotli(level.unwrap_or(11)),
			("zstd", None) => Self::Zstd,
			("none" | "zstd", Some(_)) => bail!("{name} takes no level"),
			_ => bail!("{name:?} is none of none, gzip, brotli and zstd"),
		};
		compression.checked()
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
		target_os = "linux" => elf::find(name)?,
		target_os = "macos" => macho::find(name)?,
		target_os = "windows" => pe::find(name)?,
		_ => {
			bail!("reading embedded items is unsupported on this platform")
		}
	};
	Compression::decode(stored)
}
