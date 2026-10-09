//! The PE container: one RCDATA resource per item.

use std::io::Write;

use anyhow::{Context, Result, bail, ensure};

use editpe::constants::RT_RCDATA;

use super::OrInvalid;

/// Add each item to the image as a resource of its own.
///
/// The resources the image already carries are kept, so a manifest or version block survives.
///
/// Each item's buffer is moved into its resource.
pub(super) fn append(
	image: &[u8],
	mut items: impl FnMut(&mut Vec<u8>) -> Result<String>,
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
	let mut buffer = Vec::new();
	loop {
		buffer.clear();
		let name = items(&mut buffer)?;
		if name.is_empty() {
			break;
		}
		ensure!(!name.contains('\0'), "PE item name {name:?} has a NUL");
		// Windows matches resource names case-insensitively, so names differing only in case collide.
		let key = editpe::ResourceEntryName::try_from_string(name.to_uppercase())?;
		if table.get(&key).is_some() {
			bail!("PE resource name {name:?} is embedded twice");
		}
		let mut language = editpe::ResourceTable::default();
		let mut resource = editpe::ResourceData::default();
		resource.set_data(std::mem::take(&mut buffer));
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
pub(super) fn find(name: &str) -> Result<&'static [u8], super::Error> {
	use windows_sys::Win32::System::LibraryLoader::{
		FindResourceW, GetModuleHandleW, LoadResource, LockResource, SizeofResource,
	};
	let wide: Vec<u16> = name
		.to_uppercase()
		.encode_utf16()
		.chain(std::iter::once(0))
		.collect();
	// SAFETY: Windows owns the executable module and its mapped resources for the lifetime of the process.
	unsafe {
		let module = GetModuleHandleW(std::ptr::null());
		if module.is_null() {
			return Err(std::io::Error::last_os_error())
				.or_invalid("the executable module cannot be found");
		}
		let resource = FindResourceW(module, wide.as_ptr(), RT_RCDATA as usize as *const u16);
		if resource.is_null() {
			return Err(super::Error::not_found(
				"the running image carries no such item",
			));
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
		Ok(std::slice::from_raw_parts(ptr.cast::<u8>(), size))
	}
}
