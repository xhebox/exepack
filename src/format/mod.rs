use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
#[cfg(feature = "gzip")]
use flate2::{Compression as Level, bufread::GzDecoder, write::GzEncoder};

use crate::error::{Error, OrInvalid};

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
	#[cfg(feature = "gzip")]
	Gzip(u32),
	/// Levels 0-11.
	#[cfg(feature = "brotli")]
	Brotli(u32),
	#[cfg(feature = "lz4")]
	Lz4,
}

impl Compression {
	/// The tag stored ahead of each item; `decode` matches on the same values.
	fn tag(self) -> u8 {
		match self {
			Self::None => 0,
			#[cfg(feature = "gzip")]
			Self::Gzip(_) => 1,
			#[cfg(feature = "brotli")]
			Self::Brotli(_) => 2,
			#[cfg(feature = "lz4")]
			Self::Lz4 => 3,
		}
	}

	/// Reject a level outside the compression's range.
	fn checked(self) -> Result<Self> {
		match self {
			#[cfg(feature = "gzip")]
			Self::Gzip(level) => ensure!(level <= 9, "gzip takes a level in 0-9, not {level}"),
			#[cfg(feature = "brotli")]
			Self::Brotli(level) => {
				ensure!(level <= 11, "brotli takes a level in 0-11, not {level}")
			}
			_ => {}
		}
		Ok(self)
	}

	/// Compress `input` onto the end of `out`, tag first.
	fn encode(self, mut input: impl Read, out: &mut Vec<u8>) -> Result<()> {
		out.push(self.tag());
		match self {
			#[cfg(feature = "gzip")]
			Self::Gzip(level) => {
				let mut encoder = GzEncoder::new(&mut *out, Level::new(level));
				io::copy(&mut input, &mut encoder)?;
				encoder.finish()?;
			}
			#[cfg(feature = "brotli")]
			Self::Brotli(level) => {
				// The largest window brotli allows.
				let mut encoder = brotli::CompressorWriter::new(&mut *out, 4096, level, 24);
				io::copy(&mut input, &mut encoder)?;
				// Ends the stream; writing into a Vec cannot fail.
				encoder.into_inner();
			}
			#[cfg(feature = "lz4")]
			Self::Lz4 => {
				let mut encoder = lz4_flex::frame::FrameEncoder::new(&mut *out);
				io::copy(&mut input, &mut encoder)?;
				encoder.finish()?;
			}
			Self::None => {
				input.read_to_end(out)?;
			}
		}
		Ok(())
	}

	fn decode(stored: &'static [u8]) -> Result<Item, Error> {
		let (&tag, data) = stored
			.split_first()
			.or_invalid("the item carries no compression tag")?;
		Ok(Item {
			name: None,
			decoder: match tag {
				0 => Decoder::None(data),
				#[cfg(feature = "gzip")]
				1 => Decoder::Stored { tag, data },
				#[cfg(feature = "brotli")]
				2 => Decoder::Stored { tag, data },
				#[cfg(feature = "lz4")]
				3 => Decoder::Stored { tag, data },
				_ => {
					return Err(Error::invalid(format!(
						"the item is compressed under tag {tag}, which this build does not know; a newer exepack stored it"
					)));
				}
			},
		})
	}
}

/// `none`, `lz4`, or `gzip` and `brotli` with an optional `:LEVEL`, by default 6 and 11.
impl FromStr for Compression {
	type Err = anyhow::Error;

	fn from_str(spec: &str) -> Result<Self> {
		let (name, level) = match spec.split_once(':') {
			Some((name, level)) => (
				name,
				Some(
					level
						.parse::<u32>()
						.with_context(|| format!("{level:?} is not a level"))?,
				),
			),
			None => (spec, None),
		};
		let compression = match (name, level) {
			("none", None) => Self::None,
			#[cfg(feature = "gzip")]
			("gzip", level) => Self::Gzip(level.unwrap_or(6)),
			#[cfg(feature = "brotli")]
			("brotli", level) => Self::Brotli(level.unwrap_or(11)),
			#[cfg(feature = "lz4")]
			("lz4", None) => Self::Lz4,
			("none" | "lz4", Some(_)) => bail!("{name} takes no level"),
			_ => bail!("{name:?} is none of none, gzip, brotli and lz4"),
		};
		compression.checked()
	}
}

/// An embedded item, decompressed as it is read.
pub struct Item {
	name: Option<Cow<'static, str>>,
	decoder: Decoder,
}

enum Decoder {
	None(&'static [u8]),
	#[cfg(any(feature = "gzip", feature = "brotli", feature = "lz4"))]
	Stored {
		tag: u8,
		data: &'static [u8],
	},
	// The slice is its own buffer, so gzip reads it in place.
	#[cfg(feature = "gzip")]
	Gzip(Box<GzDecoder<&'static [u8]>>),
	#[cfg(feature = "brotli")]
	Brotli(Box<brotli::Decompressor<&'static [u8]>>),
	#[cfg(feature = "lz4")]
	Lz4(lz4_flex::frame::FrameDecoder<&'static [u8]>),
}

impl Decoder {
	#[cfg(any(feature = "gzip", feature = "brotli", feature = "lz4"))]
	fn open(tag: u8, data: &'static [u8]) -> Self {
		match tag {
			#[cfg(feature = "gzip")]
			1 => Self::Gzip(Box::new(GzDecoder::new(data))),
			#[cfg(feature = "brotli")]
			2 => Self::Brotli(Box::new(brotli::Decompressor::new(data, 4096))),
			#[cfg(feature = "lz4")]
			3 => Self::Lz4(lz4_flex::frame::FrameDecoder::new(data)),
			_ => unreachable!("tag {tag} is refused when the item is opened"),
		}
	}
}

impl Item {
	/// The bytes of an item stored uncompressed, which the running image maps, or `None` if it was compressed.
	///
	/// Only the bytes not yet read are returned.
	pub fn as_bytes(&self) -> Option<&'static [u8]> {
		match self.decoder {
			Decoder::None(data) => Some(data),
			#[cfg(any(feature = "gzip", feature = "brotli", feature = "lz4"))]
			_ => None,
		}
	}

	fn named(mut self, name: Option<Cow<'static, str>>) -> Self {
		self.name = name;
		self
	}

	fn failed(&self, error: io::Error) -> io::Error {
		match &self.name {
			Some(name) => io::Error::new(error.kind(), Error::read_failed(name, error)),
			None => error,
		}
	}
}

impl Read for Item {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		#[cfg(any(feature = "gzip", feature = "brotli", feature = "lz4"))]
		if let Decoder::Stored { tag, data } = self.decoder {
			self.decoder = Decoder::open(tag, data);
		}
		let read = match &mut self.decoder {
			Decoder::None(data) => data.read(buf),
			#[cfg(feature = "gzip")]
			Decoder::Gzip(decoder) => decoder.read(buf),
			#[cfg(feature = "brotli")]
			Decoder::Brotli(decoder) => decoder.read(buf),
			#[cfg(feature = "lz4")]
			Decoder::Lz4(decoder) => decoder.read(buf),
			#[cfg(any(feature = "gzip", feature = "brotli", feature = "lz4"))]
			Decoder::Stored { .. } => unreachable!("the stored bytes were opened just above"),
		};
		read.map_err(|error| self.failed(error))
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
		let mut names = HashSet::new();
		let mut checked = Vec::new();
		for (name, input) in items {
			let text = name.as_ref();
			ensure!(!text.is_empty(), "item name cannot be empty");
			ensure!(
				names.insert(text.to_owned()),
				"item name {text:?} is embedded twice"
			);
			checked.push((name, input));
		}
		let items = checked.into_iter();
		match self {
			#[cfg(target_os = "linux")]
			Self::Elf => elf::append(image, items, compression, output),
			#[cfg(target_os = "macos")]
			Self::MachO => macho::append(image, items, compression, output),
			#[cfg(target_os = "windows")]
			Self::Pe => pe::append(image, items, compression, output),
			_ => bail!("embedding items in this image requires the platform it targets"),
		}
	}
}

/// The bytes embedded under `name`, decompressed as they are read.
///
/// Fails with [`ErrorKind::NotFound`](crate::ErrorKind::NotFound) if the running image carries no such item, and with
/// [`ErrorKind::Invalid`](crate::ErrorKind::Invalid) if the item was stored by a newer exepack. Bytes that do not
/// decompress fail the first [`read`](Read::read), not this call.
pub fn find_loaded(name: &str) -> Result<Item, Error> {
	let found = cfg_select! {
		target_os = "linux" => elf::find(name),
		target_os = "macos" => macho::find(name),
		target_os = "windows" => pe::find(name),
		_ => Err(Error::invalid(
			"reading embedded items is unsupported on this platform",
		)),
	};
	let (stored_name, stored) = found.map_err(|error| error.named(name))?;
	Compression::decode(stored)
		.map(|item| item.named(stored_name))
		.map_err(|error| error.named(name))
}

#[cfg(test)]
mod tests {
	use super::*;
	use assert2::{assert, check};
	use insta::assert_snapshot;
	use rstest::rstest;

	#[test]
	fn a_level_the_compression_lacks_is_refused() {
		assert!(let Err(gzip) = "gzip:10".parse::<Compression>());
		assert_snapshot!(gzip, @"gzip takes a level in 0-9, not 10");
		assert!(let Err(brotli) = "brotli:12".parse::<Compression>());
		assert_snapshot!(brotli, @"brotli takes a level in 0-11, not 12");
		assert!(let Err(none) = "none:1".parse::<Compression>());
		assert_snapshot!(none, @"none takes no level");
	}

	#[test]
	fn an_image_of_no_known_container_is_refused() {
		assert!(let Err(unknown) = Container::detect(b"not an executable"));
		assert_snapshot!(unknown, @"the image is neither ELF, Mach-O, nor PE");
	}

	#[cfg(not(target_os = "macos"))]
	#[test]
	fn a_macho_is_refused_away_from_macos() {
		let mut out = Vec::new();
		assert!(
			let Err(refused) = Container::MachO.append(
				b"\xcf\xfa\xed\xfe",
				[("kernel", &b"item"[..])],
				Compression::None,
				&mut out,
			)
		);
		assert_snapshot!(
			refused,
			@"embedding items in this image requires the platform it targets"
		);
	}

	#[test]
	fn an_empty_item_name_is_refused() {
		let mut out = Vec::new();
		assert!(
			let Err(empty) = Container::Elf.append(
				b"\x7fELF",
				[("", &b"item"[..])],
				Compression::None,
				&mut out,
			)
		);
		assert_snapshot!(empty, @"item name cannot be empty");
		check!(out.is_empty());
	}

	#[test]
	fn a_name_embedded_twice_is_refused() {
		let mut out = Vec::new();
		assert!(
			let Err(twice) = Container::Elf.append(
				b"\x7fELF",
				[("kernel", &b"item"[..]), ("kernel", &b"item"[..])],
				Compression::None,
				&mut out,
			)
		);
		assert_snapshot!(twice, @r#"item name "kernel" is embedded twice"#);
		check!(out.is_empty());
	}

	#[rstest]
	#[case("gzip")]
	#[case("gzip:1")]
	#[case("brotli")]
	#[case("brotli:5")]
	#[case("lz4")]
	#[case("none")]
	fn each_compression_roundtrips_its_bytes(#[case] spec: &str) -> Result<()> {
		let payload = b"the item, as it was written".repeat(16);
		let compression: Compression = spec.parse()?;
		let mut stored = Vec::new();
		compression.encode(&payload[..], &mut stored)?;
		let mut item = Compression::decode(stored.leak())?;
		if spec == "none" {
			check!(item.as_bytes() == Some(&payload[..]));
		} else {
			check!(item.as_bytes().is_none());
		}
		let mut bytes = Vec::new();
		item.read_to_end(&mut bytes)?;
		check!(bytes == payload);
		Ok(())
	}

	fn stored_size(spec: &str, payload: &[u8]) -> Result<usize> {
		let mut stored = Vec::new();
		spec.parse::<Compression>()?.encode(payload, &mut stored)?;
		Ok(stored.len())
	}

	#[test]
	fn an_item_is_opened_when_it_is_first_read() -> Result<()> {
		let mut item = Compression::decode(vec![3, 0, 0, 0].leak())?;
		check!(item.as_bytes().is_none());
		let error = item
			.read_to_end(&mut Vec::new())
			.expect_err("the frame header is no lz4");
		check!(error.to_string() == "failed to fill whole buffer");
		Ok(())
	}

	#[test]
	fn a_failed_read_names_the_item() -> Result<()> {
		let mut item = Compression::decode(vec![3, 0, 0, 0].leak())?.named(Some("kernel".into()));
		let error = item
			.read_to_end(&mut Vec::new())
			.expect_err("the frame header is no lz4");
		check!(error.to_string() == "item \"kernel\": failed to fill whole buffer");
		check!(error.kind() == io::ErrorKind::UnexpectedEof);
		Ok(())
	}

	#[test]
	fn a_decoder_that_fails_mid_stream_still_names_the_item() -> Result<()> {
		let payload = b"the item, as it was written".repeat(16);
		let mut stored = Vec::new();
		"gzip"
			.parse::<Compression>()?
			.encode(&payload[..], &mut stored)?;
		let truncated = stored[..stored.len() - 4].to_vec();
		let mut item = Compression::decode(truncated.leak())?.named(Some("kernel".into()));
		let error = item
			.read_to_end(&mut Vec::new())
			.expect_err("the stream was cut short");
		check!(error.to_string().starts_with("item \"kernel\": "));
		Ok(())
	}

	#[test]
	fn a_fixed_payload_stores_the_same_bytes() -> Result<()> {
		let mut text = String::new();
		let mut state: u64 = 0x2545_f491_4f6c_dd1d;
		for line in 0..4096 {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			text += &format!(
				"{{\"id\":{line},\"hash\":\"{state:016x}\",\"name\":\"asset-{line}\",\"kind\":\"script\"}}\n"
			);
		}
		let mut noise = vec![0; 64 * 1024];
		let mut state: u64 = 0x2545_f491_4f6c_dd1d;
		for byte in &mut noise {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			*byte = state as u8;
		}
		let mut table = String::new();
		for spec in [
			"none",
			"lz4",
			"gzip:1",
			"gzip:6",
			"gzip:9",
			"brotli:5",
			"brotli:11",
		] {
			table += &format!(
				"{spec:9} text {:>7}  noise {:>6}\n",
				stored_size(spec, text.as_bytes())?,
				stored_size(spec, &noise)?,
			);
		}
		assert_snapshot!(table, @r"
none      text  300885  noise  65537
lz4       text  115065  noise  65552
gzip:1    text  102289  noise  69122
gzip:6    text   67344  noise  65575
gzip:9    text   71804  noise  65575
brotli:5  text   55265  noise  65541
brotli:11 text   45111  noise  65541
");
		Ok(())
	}
}
