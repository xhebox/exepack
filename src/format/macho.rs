//! The Mach-O container: the items are appended past the end of the image.
//!
//! No load command is added. The payload is appended, the code signature is moved behind it, and `__LINKEDIT` is grown to cover both, which maps the payload into the process at run time.
//!
//! Layout of the appended bytes:
//!
//! ```text
//! [original image][pad][MARKER][record ...][pad][signature]
//! record = name length | data length | name | data
//! ```
//!
//! Both lengths come before the name, so one record can be stepped over using its ten byte header.

use std::{io::Write, mem::size_of};

use super::OrInvalid;
use anyhow::{Context, Result, ensure};
use object::{
	endian::LittleEndian,
	macho::{self, LinkeditDataCommand, MachHeader64},
	read::macho::{LoadCommandVariant, MachHeader, Segment},
};

// The payload opens with this marker, so the reader can pick it out of the bytes `__LINKEDIT` maps.
const MARKER: &[u8; 8] = b"EXEPACK\x04";

// The identifier an ad-hoc signature carries. `arwen-codesign` cannot read the one the image was signed with, so it is fixed rather than preserved.
const IDENTIFIER: &str = "a.out";

// The payload and the signature behind it both start on this boundary.
const ALIGN: usize = 16;

// A record's header: a u16 name length and a u64 data length.
const RECORD_LEN: usize = 2 + 8;

/// Append the items to the image.
///
/// Each item is one record of its own, named in the record rather than by a load command, because a Mach-O section name is 16 bytes at most and every added load command would move the sections behind it.
pub(super) fn append(
	image: &[u8],
	items: impl FnMut(&mut Vec<u8>) -> Result<String>,
	output: &mut impl Write,
) -> Result<()> {
	let header = MachHeader64::<LittleEndian>::parse(image, 0)?;
	ensure!(
		header.is_little_endian(),
		"the image is not a 64-bit little-endian Mach-O"
	);
	let mut signature = None;
	for command in header.load_commands(LittleEndian, image, 0)? {
		let command = command?;
		if command.cmd() == macho::LC_CODE_SIGNATURE {
			command.data::<LinkeditDataCommand<LittleEndian>>()?;
			signature = Some(usize::try_from(command.offset())?);
			break;
		}
	}
	let signature = signature
		.context("the image carries no code signature to move behind the items; sign it first")?;
	// Read before `dataoff` moves off the original signature.
	let entitlements = arwen_codesign::extract_entitlements(image);

	let mut built = image.to_vec();
	built.resize(built.len().next_multiple_of(ALIGN), 0);
	built.extend_from_slice(MARKER);
	write_records(&mut built, items)?;
	built.resize(built.len().next_multiple_of(ALIGN), 0);
	// Point the signature past the payload; signing grows `__LINKEDIT` up to it.
	let dataoff = u32::try_from(built.len())?;
	let (command, _) =
		object::pod::from_bytes_mut::<LinkeditDataCommand<LittleEndian>>(&mut built[signature..])
			.map_err(|_| anyhow::anyhow!("invalid Mach-O code signature command"))?;
	command.dataoff.set(LittleEndian, dataoff);

	// Sign with the entitlements the input image carried.
	let options = arwen_codesign::AdhocSignOptions::new(IDENTIFIER).with_entitlements(
		entitlements.as_deref().map_or(
			arwen_codesign::Entitlements::None,
			arwen_codesign::Entitlements::Custom,
		),
	);
	let signed = arwen_codesign::adhoc_sign(built, &options).context("sign Mach-O")?;
	output.write_all(&signed).context("write Mach-O")
}

/// Append each item as a record: name length, data length, name, data.
fn write_records(
	built: &mut Vec<u8>,
	mut items: impl FnMut(&mut Vec<u8>) -> Result<String>,
) -> Result<()> {
	let mut data = Vec::new();
	loop {
		data.clear();
		let name = items(&mut data)?;
		if name.is_empty() {
			return Ok(());
		}
		let name_len = u16::try_from(name.len()).context("an item name is too long")?;
		built.extend_from_slice(&name_len.to_le_bytes());
		built.extend_from_slice(&u64::try_from(data.len())?.to_le_bytes());
		built.extend_from_slice(name.as_bytes());
		built.extend_from_slice(&data);
	}
}

/// The bytes stored under `name` in the running image.
pub(super) fn find(name: &str) -> Result<&'static [u8], super::Error> {
	// SAFETY: image 0 is the running executable, whose headers stay mapped for the life of the process.
	let pointer = unsafe { _dyld_get_image_header(0) };
	if pointer.is_null() {
		return Err(super::Error::invalid(
			"the running process has no Mach-O image 0",
		));
	}
	// SAFETY: dyld image headers contain the magic identifying their header layout.
	let magic = unsafe { pointer.cast::<u32>().read() };
	if magic != macho::MH_MAGIC_64 {
		return Err(super::Error::invalid(
			"the running image is not a 64-bit little-endian Mach-O",
		));
	}
	// SAFETY: the checked magic identifies a mapped 64-bit Mach-O header, and dyld maps it page-aligned.
	let header = unsafe { &*pointer.cast::<MachHeader64<LittleEndian>>() };
	let sizeofcmds = header.sizeofcmds.get(LittleEndian) as usize;
	// SAFETY: the image maps its header and `sizeofcmds` bytes of load commands as one contiguous range.
	let bytes = unsafe {
		std::slice::from_raw_parts(
			pointer,
			size_of::<MachHeader64<LittleEndian>>() + sizeofcmds,
		)
	};
	let mut linkedit = None;
	let mut signature = None;
	let commands = header
		.load_commands(LittleEndian, bytes, 0)
		.or_invalid("the running image's load commands are malformed")?;
	for command in commands {
		let command = command.or_invalid("a load command of the running image is malformed")?;
		let variant = command
			.variant()
			.or_invalid("a load command of the running image is malformed")?;
		match variant {
			LoadCommandVariant::Segment64(segment, _) if segment.name() == b"__LINKEDIT" => {
				linkedit = Some(segment);
			}
			LoadCommandVariant::LinkeditData(data) if command.cmd() == macho::LC_CODE_SIGNATURE => {
				signature = Some(data.dataoff.get(LittleEndian));
			}
			_ => {}
		}
	}
	let linkedit = linkedit.or_invalid("the running image has no __LINKEDIT segment")?;
	// Packing always signs the image, so an unsigned one was never packed.
	let signature = signature.ok_or_else(|| {
		super::Error::not_found("the running image is not signed, so it carries no items")
	})? as usize;
	let end = signature
		.checked_sub(linkedit.fileoff.get(LittleEndian) as usize)
		.filter(|&end| end as u64 <= linkedit.filesize.get(LittleEndian))
		.or_invalid("the code signature lies outside the __LINKEDIT segment")?;
	// SAFETY: image 0 is the same executable whose load commands were read above.
	let slide = unsafe { _dyld_get_image_vmaddr_slide(0) };
	let address = (linkedit.vmaddr.get(LittleEndian) as usize).wrapping_add_signed(slide);
	// SAFETY: dyld maps this segment at `vmaddr + slide`, and `end` was checked against its file-backed size.
	let payload = unsafe { std::slice::from_raw_parts(address as *const u8, end) };

	let start = payload
		.windows(MARKER.len())
		.position(|bytes| bytes == MARKER)
		.ok_or_else(|| super::Error::not_found("the running image carries no items"))?;
	let mut records = &payload[start + MARKER.len()..];
	while let Some((header, body)) = records.split_first_chunk::<RECORD_LEN>() {
		let [name_0, name_1, data_len @ ..] = *header;
		let name_len = usize::from(u16::from_le_bytes([name_0, name_1]));
		// The record lies in the mapped segment, so its length fits in a usize.
		let data_len = u64::from_le_bytes(data_len) as usize;
		// An item name is never empty, so a zero length marks the alignment padding after the last record.
		if name_len == 0 {
			break;
		}
		let Some((stored_name, body)) = body.split_at_checked(name_len) else {
			break;
		};
		let Some((data, rest)) = body.split_at_checked(data_len) else {
			break;
		};
		if stored_name == name.as_bytes() {
			return Ok(data);
		}
		records = rest;
	}
	Err(super::Error::not_found(
		"the running image carries no such item",
	))
}

unsafe extern "C" {
	fn _dyld_get_image_header(image_index: u32) -> *const u8;
	fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
}
