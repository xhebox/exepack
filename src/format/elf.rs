//! Append a mapped ELF note segment without rebuilding the original image.
//!
//! The program header table cannot grow in place, so a copy of it, two entries longer, opens the new segment:
//!
//! ```text
//! file    original image | pad to a page | header table | notes | section names | section headers
//!                                        '---- new PT_LOAD -----'   (only if the image has sections)
//!                                                       '-PT_NOTE'
//! memory  last PT_LOAD and its .bss | a page | new PT_LOAD
//! ```
//!
//! Each item is one note of type `NOTE_TYPE`, named after the item, whose desc is the packed item alone.

use std::{io::Write, mem::size_of};

use super::OrInvalid;
use anyhow::{Context, Result, ensure};
use object::{
	elf::{self, FileHeader64, NoteHeader64, ProgramHeader64, SectionHeader64},
	endian::{Endianness, NativeEndian, U32, U64},
	pod,
	read::elf::{FileHeader, NoteIterator, SectionHeader},
};

// The one mark of our own notes: the image carries notes by others too, and each of ours is named after the item it packs.
const NOTE_TYPE: elf::NoteType = elf::NoteType(0x67B8_1572);
type Header = FileHeader64<Endianness>;
type Program = ProgramHeader64<Endianness>;
type Section = SectionHeader64<Endianness>;

/// Bytes that sit at `offset` in the file and at `address` in memory.
#[derive(Clone, Copy)]
struct Span {
	offset: u64,
	address: u64,
	size: u64,
	align: u64,
}

pub(super) fn append(
	image: &[u8],
	items: impl FnMut(&mut Vec<u8>) -> Result<String>,
	output: &mut impl Write,
) -> Result<()> {
	let mut header = *Header::parse(image)?;
	let endian = header.endian()?;
	let mut programs = header.program_headers(endian, image)?.to_vec();

	// The largest alignment and the first address past every PT_LOAD.
	let mut page = 4096;
	let mut end = None;
	for program in programs
		.iter()
		.filter(|program| program.p_type.get(endian) == elf::PT_LOAD)
	{
		page = page.max(program.p_align.get(endian));
		let last = (program.p_vaddr.get(endian))
			.checked_add(program.p_memsz.get(endian))
			.context("ELF load address overflow")?;
		end = end.max(Some(last));
	}
	let end = end.context("the ELF has no PT_LOAD segment")?;
	ensure!(page.is_power_of_two(), "invalid ELF load alignment");

	let count = u16::try_from(programs.len() + 2)?;
	ensure!(count < elf::PN_XNUM, "too many ELF program headers");
	// The file offset follows the image, but the address skips its .bss, so the file does not grow by the size of .bss.
	// The extra page keeps the segment clear of the last one's tail: GNU strip pulls a segment's address down by less than a page to keep it congruent with its file offset.
	let table = Span {
		offset: (image.len() as u64).next_multiple_of(page),
		address: end
			.checked_next_multiple_of(page)
			.and_then(|address| address.checked_add(page))
			.context("ELF load address overflow")?,
		size: u64::from(count) * size_of::<Program>() as u64,
		align: page,
	};

	let mut built = image.to_vec();
	built.resize(usize::try_from(table.offset + table.size)?, 0);
	write_notes(endian, &mut built, items)?;
	let size = built.len() as u64 - table.offset - table.size;
	// The segment's end is the last address left to check, and bounds every address before it.
	ensure!(
		table.address.checked_add(table.size + size).is_some(),
		"ELF load address overflow"
	);
	let notes = Span {
		offset: table.offset + table.size,
		address: table.address + table.size,
		size,
		align: 4,
	};

	for program in &mut programs {
		if program.p_type.get(endian) == elf::PT_PHDR {
			*program = Program {
				p_flags: program.p_flags,
				p_align: program.p_align,
				..new_program(endian, elf::PT_PHDR, table)
			};
		}
	}
	let load = Span {
		size: table.size + notes.size,
		..table
	};
	programs.push(new_program(endian, elf::PT_LOAD, load));
	programs.push(new_program(endian, elf::PT_NOTE, notes));
	built[table.offset as usize..notes.offset as usize]
		.copy_from_slice(pod::bytes_of_slice(&programs));
	header.e_phoff.set(endian, table.offset);
	header.e_phnum.set(endian, count);

	add_sections(endian, &mut header, image, &mut built, table, notes)?;
	built[..size_of::<Header>()].copy_from_slice(pod::bytes_of(&header));
	output.write_all(&built).context("write ELF")
}

/// Append each item as a note: header, NUL-terminated name, desc, each of the last two padded to 4 bytes.
fn write_notes(
	endian: Endianness,
	built: &mut Vec<u8>,
	mut items: impl FnMut(&mut Vec<u8>) -> Result<String>,
) -> Result<()> {
	let mut desc = Vec::new();
	loop {
		desc.clear();
		let name = items(&mut desc)?;
		if name.is_empty() {
			return Ok(());
		}
		let note = NoteHeader64 {
			n_namesz: U32::new(
				endian,
				u32::try_from(name.len() + 1).context("an item name is too long")?,
			),
			n_descsz: U32::new(endian, u32::try_from(desc.len())?),
			n_type: U32::new(endian, NOTE_TYPE),
		};
		built.extend_from_slice(pod::bytes_of(&note));
		built.extend_from_slice(name.as_bytes());
		built.push(0);
		built.resize(built.len().next_multiple_of(4), 0);
		built.extend_from_slice(&desc);
		built.resize(built.len().next_multiple_of(4), 0);
	}
}

/// Cover the table and the notes with allocated sections, if the image has a section table at all: section-based
/// strip tools otherwise discard or zero the bytes. The names go into a copy of the section name table, and the
/// section table moves behind it.
fn add_sections(
	endian: Endianness,
	header: &mut Header,
	image: &[u8],
	built: &mut Vec<u8>,
	table: Span,
	notes: Span,
) -> Result<()> {
	let mut sections = header.section_headers(endian, image)?.to_vec();
	if sections.is_empty() {
		return Ok(());
	}
	let index = header.section_strings_index(endian, image)?.0;
	let strings = sections
		.get_mut(index)
		.context("invalid ELF section string table index")?;
	let mut names = strings.data(endian, image)?.to_vec();
	let table_name = u32::try_from(names.len())?;
	names.extend_from_slice(b".exepack.phdrs\0");
	let notes_name = u32::try_from(names.len())?;
	names.extend_from_slice(b".note.exepack\0");
	strings.sh_offset.set(endian, built.len() as u64);
	strings.sh_size.set(endian, names.len() as u64);
	built.extend_from_slice(&names);
	built.resize(built.len().next_multiple_of(8), 0);

	sections.push(new_section(endian, table_name, elf::SHT_PROGBITS, table));
	sections.push(new_section(endian, notes_name, elf::SHT_NOTE, notes));
	let count = u16::try_from(sections.len())?;
	ensure!(count < elf::SHN_LORESERVE, "too many ELF sections");
	header.e_shoff.set(endian, built.len() as u64);
	header.e_shnum.set(endian, count);
	built.extend_from_slice(pod::bytes_of_slice(&sections));
	Ok(())
}

/// A read-only segment holding `span`.
fn new_program(endian: Endianness, kind: elf::ProgramType, span: Span) -> Program {
	Program {
		p_type: U32::new(endian, kind),
		p_flags: U32::new(endian, elf::PF_R),
		p_offset: U64::new(endian, span.offset),
		p_vaddr: U64::new(endian, span.address),
		p_paddr: U64::new(endian, span.address),
		p_filesz: U64::new(endian, span.size),
		p_memsz: U64::new(endian, span.size),
		p_align: U64::new(endian, span.align),
	}
}

/// An allocated section holding `span`, named by the offset `name` into the section name table.
fn new_section(endian: Endianness, name: u32, kind: elf::SectionType, span: Span) -> Section {
	Section {
		sh_name: U32::new(endian, name),
		sh_type: U32::new(endian, kind),
		sh_flags: U64::new(endian, elf::SHF_ALLOC),
		sh_addr: U64::new(endian, span.address),
		sh_offset: U64::new(endian, span.offset),
		sh_size: U64::new(endian, span.size),
		sh_link: U32::new(endian, 0),
		sh_info: U32::new(endian, 0),
		sh_addralign: U64::new(endian, span.align),
		sh_entsize: U64::new(endian, 0),
	}
}

pub(super) fn find(name: &str) -> Result<&'static [u8], super::Error> {
	let mut image: Option<libc::dl_phdr_info> = None;
	// The callback stops the walk with 1, so the return value is 1 exactly when libc reached it.
	let walked = unsafe {
		// The info of the main executable, taken by value: libc keeps it only for the call.
		unsafe extern "C" fn first_image(
			info: *mut libc::dl_phdr_info,
			_size: usize,
			data: *mut libc::c_void,
		) -> libc::c_int {
			// SAFETY: libc supplies a valid info for the duration of the call, and data points to the Option the caller owns.
			unsafe { *data.cast::<Option<libc::dl_phdr_info>>() = Some(*info) };
			1
		}
		// SAFETY: the callback receives a pointer to image for the duration of this synchronous call and stops at the main executable.
		libc::dl_iterate_phdr(
			Some(first_image),
			(&mut image as *mut Option<libc::dl_phdr_info>).cast(),
		)
	};
	let Some(image) = image else {
		// A zero means the callback never ran: libc walked no image at all.
		return Err(super::Error::not_found(format!(
			"the running image carries no such item, and libc described no image: dl_iterate_phdr returned {walked}"
		)));
	};

	// SAFETY: the loader keeps them mapped for the process lifetime.
	let programs =
		unsafe { std::slice::from_raw_parts(image.dlpi_phdr, usize::from(image.dlpi_phnum)) };
	let base = image.dlpi_addr as usize;
	let not_found = || super::Error::not_found("the running image carries no such item");
	// `append` pushes its PT_LOAD and PT_NOTE after the existing ones, so ours are the last of each.
	let (Some(load), Some(program)) = (
		programs.iter().rfind(|p| p.p_type == libc::PT_LOAD),
		programs.iter().rfind(|p| p.p_type == libc::PT_NOTE),
	) else {
		return Err(not_found());
	};

	// PT_NOTE creates no mapping, and GNU strip moves the note and its PT_LOAD without updating the PT_NOTE's p_vaddr. Resolve its file range through the PT_LOAD instead.
	let size = program.p_filesz;
	let Some(start) = program.p_offset.checked_sub(load.p_offset).filter(|start| {
		size != 0
			&& start
				.checked_add(size)
				.is_some_and(|end| end <= load.p_filesz)
	}) else {
		return Err(not_found());
	};
	// The segment is mapped, so its address and size fit in a usize.
	let address = (load.p_vaddr as usize)
		.wrapping_add(start as usize)
		.wrapping_add(base);
	// SAFETY: the note range was checked against the executable's file-backed load segments.
	let bytes = unsafe { std::slice::from_raw_parts(address as *const u8, size as usize) };

	#[cfg(target_pointer_width = "64")]
	type NativeHeader = FileHeader64<NativeEndian>;
	#[cfg(target_pointer_width = "32")]
	type NativeHeader = elf::FileHeader32<NativeEndian>;
	let notes = NoteIterator::<NativeHeader>::new(NativeEndian, program.p_align, bytes)
		.or_invalid("a PT_NOTE segment of the running image is malformed")?;
	for note in notes {
		let note = note.or_invalid("a note of the running image is malformed")?;
		// The type comes first: the notes of the running image are not all ours, and a note by another tool could bear the name we are after.
		if note.n_type(NativeEndian) == NOTE_TYPE && note.name() == name.as_bytes() {
			return Ok(note.desc());
		}
	}

	Err(not_found())
}
