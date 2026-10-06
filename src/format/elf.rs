//! Append a mapped ELF note segment without rebuilding the original image.

use std::{io::Write, mem::size_of};

use anyhow::{Context, Result, bail, ensure};
use object::{
	elf::{self, FileHeader64, NoteHeader64, ProgramHeader64, SectionHeader64},
	endian::{Endianness, NativeEndian},
	pod,
	read::elf::{FileHeader, NoteIterator, SectionHeader},
};

const NOTE_NAME: &[u8] = b"SUI\0";
const NOTE_TYPE: elf::NoteType = elf::NoteType(0x5355_4901);
type Header = FileHeader64<Endianness>;
type Program = ProgramHeader64<Endianness>;
type Section = SectionHeader64<Endianness>;

pub(super) fn append(
	image: &[u8],
	mut items: impl FnMut(&mut Vec<u8>) -> Result<String>,
	output: &mut impl Write,
) -> Result<()> {
	let mut header = *Header::parse(image)?;
	let endian = header.endian()?;
	let mut programs = header.program_headers(endian, image)?.to_vec();
	let mut bias = None;
	let mut page = 4096;
	let mut end = 0;
	for program in &programs {
		if program.p_type.get(endian) != elf::PT_LOAD {
			continue;
		}
		// Preserve the first load's file-to-address bias so loaders deriving AT_PHDR from e_phoff still find the relocated table.
		bias.get_or_insert(
			i128::from(program.p_vaddr.get(endian)) - i128::from(program.p_offset.get(endian)),
		);
		page = page.max(program.p_align.get(endian));
		end = end.max(
			program
				.p_vaddr
				.get(endian)
				.checked_add(program.p_memsz.get(endian))
				.context("ELF load address overflow")?,
		);
	}
	let bias = bias.context("the ELF has no PT_LOAD segment")?;
	ensure!(
		page.is_power_of_two() && bias.rem_euclid(i128::from(page)) == 0,
		"invalid ELF load alignment"
	);
	let phoff = u64::try_from(i128::from(image.len() as u64).max(i128::from(end) - bias))?
		.checked_next_multiple_of(page)
		.context("ELF file offset overflow")?;
	let address = u64::try_from(i128::from(phoff) + bias)?;
	let phnum = u16::try_from(programs.len() + 2)?;
	ensure!(phnum < elf::PN_XNUM, "too many ELF program headers");
	let table_size = u64::from(phnum) * size_of::<Program>() as u64;
	let note_offset = phoff
		.checked_add(table_size)
		.context("ELF file offset overflow")?;
	let note_address = address
		.checked_add(table_size)
		.context("ELF load address overflow")?;

	let mut built = image.to_vec();
	built.resize(usize::try_from(note_offset)?, 0);
	let mut buffer = Vec::new();
	loop {
		buffer.clear();
		let name = items(&mut buffer)?;
		if name.is_empty() {
			break;
		}
		let name_len = u16::try_from(name.len()).context("an item name is too long")?;
		let desc_len = u32::try_from(2 + name.len() + buffer.len())?;
		let note = NoteHeader64 {
			n_namesz: object::endian::U32::new(endian, NOTE_NAME.len() as u32),
			n_descsz: object::endian::U32::new(endian, desc_len),
			n_type: object::endian::U32::new(endian, NOTE_TYPE),
		};
		built.extend_from_slice(pod::bytes_of(&note));
		built.extend_from_slice(NOTE_NAME);
		built.extend_from_slice(&name_len.to_le_bytes());
		built.extend_from_slice(name.as_bytes());
		built.extend_from_slice(&buffer);
		built.resize(built.len().next_multiple_of(4), 0);
	}
	drop(buffer);
	let note_size = built.len() as u64 - note_offset;
	for program in &mut programs {
		if program.p_type.get(endian) == elf::PT_PHDR {
			program.p_offset.set(endian, phoff);
			program.p_vaddr.set(endian, address);
			program.p_paddr.set(endian, address);
			program.p_filesz.set(endian, table_size);
			program.p_memsz.set(endian, table_size);
		}
	}
	for (kind, offset, vaddr, size, align) in [
		(elf::PT_LOAD, phoff, address, table_size + note_size, page),
		(elf::PT_NOTE, note_offset, note_address, note_size, 4),
	] {
		let mut program = *pod::from_bytes::<Program>(&[0; size_of::<Program>()])
			.unwrap()
			.0;
		program.p_type.set(endian, kind);
		program.p_flags.set(endian, elf::PF_R);
		program.p_offset.set(endian, offset);
		program.p_vaddr.set(endian, vaddr);
		program.p_paddr.set(endian, vaddr);
		program.p_filesz.set(endian, size);
		program.p_memsz.set(endian, size);
		program.p_align.set(endian, align);
		programs.push(program);
	}
	built[usize::try_from(phoff)?..usize::try_from(note_offset)?]
		.copy_from_slice(pod::bytes_of_slice(&programs));
	header.e_phoff.set(endian, phoff);
	header.e_phnum.set(endian, phnum);

	// Allocated sections make both the relocated table and notes visible to section-based strip tools, which otherwise discard or zero these bytes.
	let mut sections = header.section_headers(endian, image)?.to_vec();
	if !sections.is_empty() {
		let strings_index = header.section_strings_index(endian, image)?.0;
		let strings = sections
			.get(strings_index)
			.context("invalid ELF section string table index")?;
		let mut names = strings.data(endian, image)?.to_vec();
		let phdr_name = u32::try_from(names.len())?;
		names.extend_from_slice(b".sui.phdrs\0");
		let note_name = u32::try_from(names.len())?;
		names.extend_from_slice(b".note.sui\0");
		sections[strings_index]
			.sh_offset
			.set(endian, built.len() as u64);
		sections[strings_index]
			.sh_size
			.set(endian, names.len() as u64);
		built.extend_from_slice(&names);
		built.resize(built.len().next_multiple_of(8), 0);
		header.e_shoff.set(endian, built.len() as u64);
		for (name, kind, offset, vaddr, size, align) in [
			(
				phdr_name,
				elf::SHT_PROGBITS,
				phoff,
				address,
				table_size,
				page,
			),
			(
				note_name,
				elf::SHT_NOTE,
				note_offset,
				note_address,
				note_size,
				4,
			),
		] {
			let mut section = *pod::from_bytes::<Section>(&[0; size_of::<Section>()])
				.unwrap()
				.0;
			section.sh_name.set(endian, name);
			section.sh_type.set(endian, kind);
			section.sh_flags.set(endian, elf::SHF_ALLOC.into());
			section.sh_offset.set(endian, offset);
			section.sh_addr.set(endian, vaddr);
			section.sh_size.set(endian, size);
			section.sh_addralign.set(endian, align);
			sections.push(section);
		}
		let count = u16::try_from(sections.len())?;
		ensure!(count < elf::SHN_LORESERVE, "too many ELF sections");
		header.e_shnum.set(endian, count);
		built.extend_from_slice(pod::bytes_of_slice(&sections));
	}
	built[..size_of::<Header>()].copy_from_slice(pod::bytes_of(&header));
	output.write_all(&built).context("write ELF")
}

pub(super) fn find(name: &str) -> Result<&'static [u8]> {
	#[cfg(target_pointer_width = "64")]
	type NativeHeader = FileHeader64<NativeEndian>;
	#[cfg(target_pointer_width = "32")]
	type NativeHeader = elf::FileHeader32<NativeEndian>;
	type NativeProgram = <NativeHeader as FileHeader>::ProgramHeader;

	struct Image {
		base: usize,
		programs: &'static [NativeProgram],
	}
	unsafe extern "C" fn first_image(
		info: *mut libc::dl_phdr_info,
		_size: usize,
		data: *mut libc::c_void,
	) -> libc::c_int {
		// SAFETY: libc supplies a valid info during this callback; data points to our Image, and the executable's program headers remain mapped for the process lifetime.
		unsafe {
			let info = &*info;
			let image = &mut *data.cast::<Image>();
			image.base = info.dlpi_addr as usize;
			image.programs =
				std::slice::from_raw_parts(info.dlpi_phdr.cast(), usize::from(info.dlpi_phnum));
		}
		1
	}
	let mut image = Image {
		base: 0,
		programs: &[],
	};
	// SAFETY: the callback receives a pointer to image for the duration of this synchronous call and stops at the main executable.
	unsafe {
		libc::dl_iterate_phdr(Some(first_image), (&mut image as *mut Image).cast());
	}
	for program in image.programs {
		if program.p_type.get(NativeEndian) != elf::PT_NOTE {
			continue;
		}
		let offset = program.p_offset.get(NativeEndian);
		let size = program.p_filesz.get(NativeEndian);
		// PT_NOTE creates no mapping. Resolve its file range through PT_LOAD, including after strip tools have rearranged the file.
		let load = image.programs.iter().find(|load| {
			load.p_type.get(NativeEndian) == elf::PT_LOAD
				&& offset
					.checked_sub(load.p_offset.get(NativeEndian))
					.and_then(|offset| offset.checked_add(size))
					.is_some_and(|end| end <= load.p_filesz.get(NativeEndian))
		});
		let Some(load) = load.filter(|_| size != 0) else {
			continue;
		};
		let address = usize::try_from(load.p_vaddr.get(NativeEndian))?
			.wrapping_add(usize::try_from(offset - load.p_offset.get(NativeEndian))?)
			.wrapping_add(image.base);
		// SAFETY: the note range was checked against the executable's file-backed load segments.
		let bytes =
			unsafe { std::slice::from_raw_parts(address as *const u8, usize::try_from(size)?) };
		for note in NoteIterator::<NativeHeader>::new(
			NativeEndian,
			program.p_align.get(NativeEndian),
			bytes,
		)? {
			let note = note?;
			if note.name() != b"SUI" || note.n_type(NativeEndian) != NOTE_TYPE {
				continue;
			}
			let Some((length, body)) = note.desc().split_at_checked(2) else {
				continue;
			};
			let length = usize::from(u16::from_le_bytes(length.try_into()?));
			let Some((stored_name, data)) = body.split_at_checked(length) else {
				continue;
			};
			if stored_name == name.as_bytes() {
				return Ok(data);
			}
		}
	}
	bail!("no item is embedded as {name:?}")
}
