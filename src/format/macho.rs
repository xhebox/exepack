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

use anyhow::{Context, Result, bail, ensure};
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

// A record is a name length, a data length and then the two of them.
const RECORD_LEN: usize = 2 + 8;

/// Append the items to the image.
///
/// Each item is one record of its own, named in the record rather than by a load command, because a Mach-O section name is 16 bytes at most and every added load command would move the sections behind it.
///
/// `items` is called once per item with the buffer to write into, which is cleared before each call and reused, so only one item's bytes are held beyond the data already laid out.
pub(super) fn append(
	image: &[u8],
	mut items: impl FnMut(&mut Vec<u8>) -> Result<String>,
	output: &mut impl Write,
) -> Result<()> {
	let header = header(image)?;
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
	// Read before the signature is moved: once `dataoff` points past the items, the blob the image arrived with is no longer where a signer would look for it.
	let entitlements = arwen_codesign::extract_entitlements(image);

	let mut built = image.to_vec();
	built.resize(built.len().next_multiple_of(ALIGN), 0);
	built.extend_from_slice(MARKER);
	let mut buffer = Vec::new();
	loop {
		buffer.clear();
		let name = items(&mut buffer)?;
		if name.is_empty() {
			break;
		}
		let name_len = u16::try_from(name.len()).context("an item name is too long")?;
		built.extend_from_slice(&name_len.to_le_bytes());
		built.extend_from_slice(&u64::try_from(buffer.len())?.to_le_bytes());
		built.extend_from_slice(name.as_bytes());
		built.extend_from_slice(&buffer);
	}
	drop(buffer);
	built.resize(built.len().next_multiple_of(ALIGN), 0);
	// The signature goes where `__LINKEDIT` can grow to reach it, so the payload ends up covered by the segment.
	let dataoff = u32::try_from(built.len())?;
	let (command, _) =
		object::pod::from_bytes_mut::<LinkeditDataCommand<LittleEndian>>(&mut built[signature..])
			.map_err(|_| anyhow::anyhow!("invalid Mach-O code signature command"))?;
	command.dataoff.set(LittleEndian, dataoff);

	// Signing uses the entitlements read from the image the caller supplied, and grows `__LINKEDIT` over the payload.
	let options = arwen_codesign::AdhocSignOptions::new(IDENTIFIER).with_entitlements(
		match entitlements.as_deref() {
			Some(data) => arwen_codesign::Entitlements::Custom(data),
			None => arwen_codesign::Entitlements::None,
		},
	);
	let signed = arwen_codesign::adhoc_sign(built, &options).context("sign Mach-O")?;
	output.write_all(&signed).context("write Mach-O")
}

/// The bytes stored under `name` in the running image.
pub(super) fn find(name: &str) -> Result<&'static [u8]> {
	// SAFETY: image 0 is the running executable, whose headers stay mapped for the life of the process.
	let pointer = unsafe { _dyld_get_image_header(0) };
	if pointer.is_null() {
		bail!("the running process has no Mach-O image 0");
	}
	// SAFETY: dyld image headers contain the magic identifying their header layout.
	let magic = unsafe { pointer.cast::<u32>().read() };
	ensure!(
		magic == macho::MH_MAGIC_64,
		"the running image is not a 64-bit little-endian Mach-O"
	);
	// SAFETY: the checked magic identifies a mapped 64-bit Mach-O header.
	let bytes =
		unsafe { std::slice::from_raw_parts(pointer, size_of::<MachHeader64<LittleEndian>>()) };
	let header = header(bytes)?;
	let sizeofcmds = usize::try_from(header.sizeofcmds.get(LittleEndian))?;
	// SAFETY: the image maps its header and `sizeofcmds` bytes of load commands as one contiguous range.
	let bytes = unsafe {
		std::slice::from_raw_parts(
			pointer,
			size_of::<MachHeader64<LittleEndian>>() + sizeofcmds,
		)
	};
	let mut linkedit = None;
	let mut signature = None;
	for command in header.load_commands(LittleEndian, bytes, 0)? {
		let command = command?;
		match command.variant()? {
			LoadCommandVariant::Segment64(segment, _) if segment.name() == b"__LINKEDIT" => {
				linkedit = Some(segment);
			}
			LoadCommandVariant::LinkeditData(data) if command.cmd() == macho::LC_CODE_SIGNATURE => {
				signature = Some(data.dataoff.get(LittleEndian));
			}
			_ => {}
		}
	}
	let linkedit = linkedit.context("the running image has no __LINKEDIT segment")?;
	let signature = usize::try_from(signature.context("the running image is not signed")?)?;
	let end = signature
		.checked_sub(usize::try_from(linkedit.fileoff.get(LittleEndian))?)
		.filter(|&end| end as u64 <= linkedit.filesize.get(LittleEndian))
		.context("the code signature is outside the __LINKEDIT segment")?;
	// SAFETY: image 0 is the same executable whose load commands were read above.
	let slide = unsafe { _dyld_get_image_vmaddr_slide(0) };
	let address = usize::try_from(linkedit.vmaddr.get(LittleEndian))?.wrapping_add_signed(slide);
	// SAFETY: dyld maps this segment at `vmaddr + slide`, and `end` was checked against its file-backed size.
	let payload = unsafe { std::slice::from_raw_parts(address as *const u8, end) };

	let start = payload
		.windows(MARKER.len())
		.position(|bytes| bytes == MARKER)
		.context("no items are embedded in this Mach-O")?;
	let mut records = &payload[start + MARKER.len()..];
	while let Some((header, body)) = records.split_at_checked(RECORD_LEN) {
		let name_len = usize::from(u16::from_le_bytes(header[..2].try_into()?));
		let data_len = usize::try_from(u64::from_le_bytes(header[2..].try_into()?))?;
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
	bail!("no item is embedded as {name:?}")
}

unsafe extern "C" {
	fn _dyld_get_image_header(image_index: u32) -> *const u8;
	fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
}

fn header(data: &[u8]) -> Result<&MachHeader64<LittleEndian>> {
	let header = MachHeader64::<LittleEndian>::parse(data, 0)?;
	ensure!(
		header.is_little_endian(),
		"the image is not a 64-bit little-endian Mach-O"
	);
	Ok(header)
}
