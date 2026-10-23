//! The PE container: one RCDATA resource per item.

use std::borrow::Cow;
use std::io::{Read, Write};

use anyhow::{Context, Result, bail, ensure};

use editpe::constants::RT_RCDATA;

use super::Compression;
use crate::error::{Error, OrInvalid};

/// Add each item to the image as a resource of its own.
///
/// The resources the image already carries are kept, so a manifest or version block survives.
///
/// Each item is compressed into a buffer of its own, which is moved into its resource.
pub(super) fn append(
	image: &[u8],
	items: impl Iterator<Item = (impl AsRef<str>, impl Read)>,
	compression: Compression,
	output: &mut impl Write,
) -> Result<()> {
	let mut pe = editpe::Image::parse(image).context("parse PE")?;
	let mut resources = pe.resource_directory().cloned().unwrap_or_default();
	let root = resources.root_mut();
	let resource_type = editpe::ResourceEntryName::ID(RT_RCDATA as u32);
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
		let name = name.as_ref();
		ensure!(!name.contains('\0'), "PE item name {name:?} has a NUL");
		// Windows matches resource names case-insensitively, so names differing only in case collide.
		let key = editpe::ResourceEntryName::try_from_string(name.to_uppercase())?;
		if table.get(&key).is_some() {
			bail!("PE resource name {name:?} is embedded twice");
		}
		let mut buffer = Vec::new();
		compression.encode(input, &mut buffer)?;
		let mut language = editpe::ResourceTable::default();
		let mut resource = editpe::ResourceData::default();
		resource.set_data(buffer);
		language.insert(
			editpe::ResourceEntryName::ID(0),
			editpe::ResourceEntry::Data(resource),
		);
		table.insert(key, editpe::ResourceEntry::Table(language));
	}
	pe.set_resource_directory(resources)
		.context("add the PE resources")?;
	pe.write_writer(output).context("write PE")
}

/// The bytes stored as the `name` resource of the running module.
pub(super) fn find(name: &str) -> Result<(Option<Cow<'static, str>>, &'static [u8]), Error> {
	use windows_sys::Win32::System::LibraryLoader::{
		FindResourceW, GetModuleHandleW, LoadResource, LockResource, SizeofResource,
	};
	let mut wide = Vec::with_capacity(name.len() + 1);
	let mut buf = [0; 2];
	for ch in name.chars().flat_map(char::to_uppercase) {
		wide.extend_from_slice(ch.encode_utf16(&mut buf));
	}
	wide.push(0);
	// SAFETY: Windows owns the executable module and its mapped resources for the lifetime of the process.
	unsafe {
		let module = GetModuleHandleW(std::ptr::null());
		if module.is_null() {
			return Err(std::io::Error::last_os_error())
				.or_invalid("the executable module cannot be found");
		}
		let resource = FindResourceW(module, wide.as_ptr(), RT_RCDATA as usize as *const u16);
		if resource.is_null() {
			return Err(Error::not_found("the running image carries no such item"));
		}
		let size = SizeofResource(module, resource) as usize;
		let data = LoadResource(module, resource);
		if data.is_null() {
			return Err(std::io::Error::last_os_error())
				.or_invalid("the item resource cannot be loaded");
		}
		let ptr = LockResource(data);
		if ptr.is_null() {
			return Err(std::io::Error::last_os_error())
				.or_invalid("the item resource cannot be mapped");
		}
		let data = std::slice::from_raw_parts(ptr.cast::<u8>(), size);
		Ok((Some(Cow::Owned(name.to_owned())), data))
	}
}
