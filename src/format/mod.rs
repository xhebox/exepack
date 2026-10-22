use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use flate2::Compression as Level;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;

mod error;

use error::OrInvalid;
pub use error::{Error, ErrorKind};

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
	/// The tag stored ahead of each item; `decode` matches on the same values.
	fn tag(self) -> u8 {
		match self {
			Self::None => 0,
			Self::Gzip(_) => 1,
			Self::Brotli(_) => 2,
			Self::Zstd => 3,
		}
	}

	/// Reject a level outside the compression's range.
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

	/// Compress `input` onto the end of `out`, tag first.
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
}

/// An embedded item, decompressed as it is read.
pub struct Item(Decoder);

enum Decoder {
	None(&'static [u8]),
	// The slice is its own buffer, so gzip reads it in place.
	Gzip(GzDecoder<&'static [u8]>),
	Brotli(Box<brotli::Decompressor<&'static [u8]>>),
	Zstd(Box<ruzstd::decoding::StreamingDecoder<&'static [u8], ruzstd::decoding::FrameDecoder>>),
}

impl Item {
	fn decode(stored: &'static [u8]) -> Result<Self, Error> {
		let (&tag, data) = stored
			.split_first()
			.or_invalid("the item carries no compression tag")?;
		Ok(Self(match tag {
			0 => Decoder::None(data),
			1 => Decoder::Gzip(GzDecoder::new(data)),
			2 => Decoder::Brotli(Box::new(brotli::Decompressor::new(data, 4096))),
			3 => Decoder::Zstd(Box::new(
				ruzstd::decoding::StreamingDecoder::new(data)
					.or_invalid("the zstd frame header is malformed")?,
			)),
			_ => {
				return Err(Error::invalid(format!(
					"the item is compressed under tag {tag}, which this build does not know; a newer exepack stored it"
				)));
			}
		}))
	}

	/// The bytes of an item stored uncompressed, which the running image maps, or `None` if it was compressed.
	///
	/// Only the bytes not yet read are returned.
	pub fn as_bytes(&self) -> Option<&'static [u8]> {
		match self.0 {
			Decoder::None(data) => Some(data),
			_ => None,
		}
	}
}

impl Read for Item {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match &mut self.0 {
			Decoder::None(data) => data.read(buf),
			Decoder::Gzip(decoder) => decoder.read(buf),
			Decoder::Brotli(decoder) => decoder.read(buf),
			Decoder::Zstd(decoder) => decoder.read(buf),
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

/// The executable format of an image, which decides where its items are embedded.
pub enum Container {
	/// A new note segment maps the items into the process.
	Elf,
	/// The items are appended past the end of the image.
	MachO,
	/// One RCDATA resource per item.
	Pe,
}

impl Container {
	/// Identify the format of `image` from its magic bytes.
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

	/// Write `image` to `output` with `items` embedded in it, each compressed with `compression`.
	pub fn append<N: AsRef<str>, R: Read>(
		&self,
		image: &[u8],
		items: impl IntoIterator<Item = (N, R)>,
		compression: Compression,
		output: &mut impl Write,
	) -> Result<()> {
		let items = Items {
			items: items.into_iter(),
			names: HashSet::new(),
			compression,
		};
		match self {
			#[cfg(target_os = "linux")]
			Self::Elf => elf::append(image, items, output),
			#[cfg(target_os = "macos")]
			Self::MachO => macho::append(image, items, output),
			#[cfg(target_os = "windows")]
			Self::Pe => pe::append(image, items, output),
			_ => bail!("embedding items in this image requires the platform it targets"),
		}
	}
}

/// The items left to embed. Each container writes an item's header before its bytes, so the name comes first and the
/// bytes are compressed straight into the container after it.
struct Items<I> {
	items: I,
	names: HashSet<String>,
	compression: Compression,
}

impl<N: AsRef<str>, R: Read, I: Iterator<Item = (N, R)>> Items<I> {
	/// The next item, its name checked, or `None` once none are left.
	fn next(&mut self) -> Result<Option<(N, R)>> {
		let Some((name, input)) = self.items.next() else {
			return Ok(None);
		};
		let text = name.as_ref();
		ensure!(!text.is_empty(), "item name cannot be empty");
		if !self.names.insert(text.to_owned()) {
			bail!("item name {text:?} is embedded twice");
		}
		Ok(Some((name, input)))
	}

	/// Compress `input` onto the end of `out`.
	fn encode(&self, input: R, out: &mut Vec<u8>) -> Result<()> {
		self.compression.encode(input, out)
	}
}

/// The bytes embedded under `name`, decompressed as they are read.
///
/// Fails with [`ErrorKind::NotFound`] if the running image carries no such item, and with [`ErrorKind::Invalid`] if it
/// cannot be read back.
pub fn find_loaded(name: &str) -> Result<Item, Error> {
	let found = cfg_select! {
		target_os = "linux" => elf::find(name),
		target_os = "macos" => macho::find(name),
		target_os = "windows" => pe::find(name),
		_ => Err(Error::invalid(
			"reading embedded items is unsupported on this platform",
		)),
	};
	found
		.and_then(Item::decode)
		.map_err(|error| error.named(name))
}
