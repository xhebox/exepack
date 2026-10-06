use std::collections::HashSet;
use std::io::{self, Cursor, Read};

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use flate2::Compression as Level;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use strum::FromRepr;

#[cfg(target_os = "macos")]
const SECTION: &str = "__EXEPACK";

// RT_RCDATA, the resource type PE items are stored under.
#[cfg(target_os = "windows")]
const RT_RCDATA: u32 = 10;

#[derive(Clone, Copy, FromRepr, ValueEnum)]
#[repr(u8)]
pub enum Compression {
	None = 0,
	Gzip = 1,
}

impl Compression {
	fn encode(self, mut input: impl Read) -> Result<Vec<u8>> {
		let mut data = vec![self as u8];
		match self {
			Self::Gzip => {
				let mut encoder = GzEncoder::new(&mut data, Level::default());
				io::copy(&mut input, &mut encoder)?;
				encoder.finish()?;
			}
			Self::None => {
				input.read_to_end(&mut data)?;
			}
		}
		Ok(data)
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

pub struct Container;

impl Container {
	pub fn detect(image: &[u8]) -> Result<Self> {
		if libsui::utils::is_pe(image) {
			#[cfg(target_os = "windows")]
			return Ok(Self);
			#[cfg(not(target_os = "windows"))]
			bail!("embedding items in PE requires Windows");
		}
		if libsui::utils::is_macho(image) {
			#[cfg(target_os = "macos")]
			return Ok(Self);
			#[cfg(not(target_os = "macos"))]
			bail!("embedding items in Mach-O requires macOS for code signing");
		}
		if image.starts_with(b"\xca\xfe\xba\xbe") || image.starts_with(b"\xbe\xba\xfe\xca") {
			bail!("a universal Mach-O image is not packed; thin it to one architecture first");
		}
		if libsui::utils::is_elf(image) {
			#[cfg(target_os = "linux")]
			return Ok(Self);
			#[cfg(not(target_os = "linux"))]
			bail!("embedding items in ELF requires Linux");
		}
		bail!("the image is neither ELF, Mach-O, nor PE")
	}

	pub fn append<R: Read>(
		&self,
		image: &[u8],
		items: impl IntoIterator<Item = (String, R)>,
		compression: Compression,
	) -> Result<Vec<u8>> {
		let mut names = HashSet::new();
		let mut store = |name: String, input: R| -> Result<(String, Vec<u8>)> {
			ensure!(!name.is_empty(), "item name cannot be empty");
			if !names.insert(name.clone()) {
				bail!("item name {name:?} is embedded twice");
			}
			Ok((name, compression.encode(input)?))
		};

		#[cfg(target_os = "linux")]
		{
			let mut output = image.to_vec();
			for (name, input) in items {
				let (name, data) = store(name, input)?;
				let mut next = Vec::new();
				libsui::Elf::new(&output)
					.append(&name, &data, &mut next)
					.with_context(|| format!("embed ELF item {name:?}"))?;
				output = next;
			}
			Ok(output)
		}

		#[cfg(target_os = "macos")]
		{
			let stored = items
				.into_iter()
				.map(|(name, input)| store(name, input))
				.collect::<Result<Vec<_>>>()?;
			let packet = crate::packet::build(&stored)?;
			let mut contents = Vec::with_capacity(8 + packet.len());
			contents.extend_from_slice(&u64::try_from(packet.len())?.to_le_bytes());
			contents.extend_from_slice(&packet);
			let mut output = Vec::new();
			libsui::Macho::from(image.to_vec())
				.context("parse Mach-O")?
				.write_section(SECTION, contents)
				.context("add Mach-O section")?
				.build_and_sign(&mut output)
				.context("sign Mach-O")?;
			Ok(output)
		}

		#[cfg(target_os = "windows")]
		{
			let mut pe = editpe::Image::parse(image)?;
			let mut resources = pe.resource_directory().cloned().unwrap_or_default();
			let root = resources.root_mut();
			let resource_type = editpe::ResourceEntryName::ID(RT_RCDATA);
			if root.get(resource_type.clone()).is_none() {
				root.insert(
					resource_type.clone(),
					editpe::ResourceEntry::Table(editpe::ResourceTable::default()),
				);
			}
			let Some(editpe::ResourceEntry::Table(table)) = root.get_mut(resource_type) else {
				bail!("the PE RCDATA resource is not a table");
			};
			for (name, input) in items {
				let (name, data) = store(name, input)?;
				ensure!(!name.contains('\0'), "PE item name {name:?} has a NUL");
				let key = editpe::ResourceEntryName::try_from_string(name.to_uppercase())?;
				if table.get(&key).is_some() {
					bail!("PE resource name {name:?} is embedded twice");
				}
				let mut language = editpe::ResourceTable::default();
				let mut resource = editpe::ResourceData::default();
				resource.set_data(data);
				language.insert(
					editpe::ResourceEntryName::ID(0),
					editpe::ResourceEntry::Data(resource),
				);
				table.insert(key, editpe::ResourceEntry::Table(language));
			}
			pe.set_resource_directory(resources)?;
			let mut output = Vec::new();
			pe.write_writer(&mut output)?;
			Ok(output)
		}

		#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
		{
			let _ = (image, items, &mut store);
			bail!("embedding items is unsupported on this platform")
		}
	}
}

pub(crate) fn find_loaded(name: &str) -> Result<Box<dyn Read + '_>> {
	#[cfg(target_os = "macos")]
	let stored = {
		let contents =
			libsui::find_section(SECTION)?.context("no items are embedded in the Mach-O")?;
		let length = usize::try_from(u64::from_le_bytes(
			contents
				.get(..8)
				.context("the Mach-O carries a truncated exepack payload")?
				.try_into()?,
		))?;
		let end = 8usize
			.checked_add(length)
			.context("the Mach-O exepack payload overflows")?;
		let packet = contents
			.get(8..end)
			.context("the Mach-O carries a truncated exepack payload")?;
		crate::packet::find(packet, name)?
	};
	#[cfg(target_os = "linux")]
	let stored =
		libsui::find_section(name)?.with_context(|| format!("no item is embedded as {name:?}"))?;
	#[cfg(target_os = "windows")]
	let stored = pe_loaded(name)?;
	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	let stored: &[u8] = { bail!("reading embedded items is unsupported on this platform") };
	Compression::decode(stored)
}

#[cfg(target_os = "windows")]
fn pe_loaded(name: &str) -> Result<&'static [u8]> {
	use windows_sys::Win32::System::LibraryLoader::{
		FindResourceW, GetModuleHandleW, LoadResource, LockResource, SizeofResource,
	};
	let wide: Vec<u16> = name
		.to_uppercase()
		.encode_utf16()
		.chain(std::iter::once(0))
		.collect();
	// Windows owns the executable module and its mapped resources for the lifetime of the process.
	unsafe {
		let module = GetModuleHandleW(std::ptr::null());
		if module.is_null() {
			return Err(std::io::Error::last_os_error()).context("find the executable module");
		}
		let resource = FindResourceW(module, wide.as_ptr(), RT_RCDATA as usize as *const u16);
		if resource.is_null() {
			bail!("no item is embedded as {name:?}");
		}
		let size = SizeofResource(module, resource) as usize;
		let data = LoadResource(module, resource);
		if data.is_null() {
			return Err(std::io::Error::last_os_error()).context("load the item resource");
		}
		let ptr = LockResource(data);
		if ptr.is_null() {
			return Err(std::io::Error::last_os_error()).context("map the item resource");
		}
		Ok(std::slice::from_raw_parts(ptr.cast::<u8>(), size))
	}
}
