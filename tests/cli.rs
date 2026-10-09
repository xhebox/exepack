//! What the command line takes, what a failed run leaves behind, and what a packed copy reads back.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
#[cfg(target_os = "linux")]
use object::{elf::FileHeader64, endian::Endianness, pod, read::elf::FileHeader};

/// The `exepack` cargo built for this run.
fn exepack() -> &'static str {
	env!("CARGO_BIN_EXE_exepack")
}

/// The image to embed into: this test binary.
fn carrier() -> PathBuf {
	std::env::current_exe().expect("the test binary has a path")
}

/// Run the tool with `args` and return what it wrote to stderr, asserting that it failed.
fn failure(args: &[&str]) -> String {
	let output = Command::new(exepack())
		.args(args)
		.output()
		.expect("the tool runs");
	assert!(
		!output.status.success(),
		"the run was expected to fail: {}",
		String::from_utf8_lossy(&output.stdout)
	);
	String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_missing_item_names_it_and_writes_nothing() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let out = scratch.path().join("packed");
	let missing = scratch.path().join("kernel");
	let stderr = failure(&[
		"--main",
		&carrier().display().to_string(),
		"--output",
		&out.display().to_string(),
		"--item",
		&format!("kernel={}", missing.display()),
	]);
	assert!(stderr.contains("kernel"), "{stderr}");
	assert!(stderr.contains(&missing.display().to_string()), "{stderr}");
	assert!(
		!out.exists(),
		"a run that failed left {} behind",
		out.display()
	);
	Ok(())
}

#[test]
fn an_empty_item_name_is_refused() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let out = scratch.path().join("packed");
	let item = format!("={}", carrier().display());
	let stderr = failure(&[
		"--main",
		&carrier().display().to_string(),
		"--output",
		&out.display().to_string(),
		"--item",
		&item,
	]);
	assert!(stderr.contains("item name cannot be empty"), "{stderr}");
	assert!(!out.exists(), "a rejected empty name left an output image");
	Ok(())
}

#[test]
fn an_image_of_no_known_container_is_refused() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let main = scratch.path().join("main");
	std::fs::write(&main, b"not an executable")?;
	let stderr = failure(&[
		"--main",
		&main.display().to_string(),
		"--output",
		&scratch.path().join("packed").display().to_string(),
		"--item",
		&format!("kernel={}", carrier().display()),
	]);
	assert!(stderr.contains("neither ELF"), "{stderr}");
	Ok(())
}

#[test]
fn a_level_the_compression_lacks_is_refused() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let out = scratch.path().join("packed");
	let stderr = failure(&[
		"--main",
		&carrier().display().to_string(),
		"--output",
		&out.display().to_string(),
		"--compress",
		"gzip:10",
		"--item",
		&format!("kernel={}", carrier().display()),
	]);
	assert!(stderr.contains("0-9"), "{stderr}");
	assert!(!out.exists(), "a rejected level left an output image");
	Ok(())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn a_macho_is_refused_away_from_macos() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let main = scratch.path().join("main");
	let out = scratch.path().join("packed");
	std::fs::write(&main, b"\xcf\xfa\xed\xfe")?;
	let stderr = failure(&[
		"--main",
		&main.display().to_string(),
		"--output",
		&out.display().to_string(),
		"--item",
		&format!("kernel={}", carrier().display()),
	]);
	assert!(
		stderr.contains("requires the platform it targets"),
		"{stderr}"
	);
	Ok(())
}

#[test]
fn an_item_name_may_match_a_native_section() -> Result<()> {
	let main = carrier();
	let image = std::fs::read(&main)?;
	if !image.starts_with(b"\x7fELF") {
		return Ok(());
	}
	let scratch = tempfile::tempdir()?;
	let out = scratch.path().join("packed");
	let status = Command::new(exepack())
		.args([
			"--main",
			&main.display().to_string(),
			"--output",
			&out.display().to_string(),
			"--item",
			&format!(".text={}", main.display()),
		])
		.status()?;
	assert!(
		status.success(),
		"a native section name was rejected: {status}"
	);
	Ok(())
}

#[test]
fn a_name_embedded_twice_is_refused() {
	let carrier = carrier();
	let item = format!("kernel={}", carrier.display());
	let stderr = failure(&[
		"--main",
		&carrier.display().to_string(),
		"--output",
		&carrier.display().to_string(),
		"--item",
		&item,
		"--item",
		&item,
	]);
	assert!(stderr.contains("embedded twice"), "{stderr}");
}

#[test]
fn every_item_is_written_into_the_image() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let out = scratch.path().join("packed");
	let kernel = scratch.path().join("kernel");
	std::fs::write(&kernel, b"the first item")?;
	let mkfs = scratch.path().join("mkfs.ext4");
	std::fs::write(&mkfs, b"the second item")?;
	let main = carrier();
	let status = Command::new(exepack())
		.args([
			"--main",
			&main.display().to_string(),
			"--output",
			&out.display().to_string(),
			"--compress",
			"none",
			"--item",
			&format!("kernel={}", kernel.display()),
			"--item",
			&format!("mkfs.ext4={}", mkfs.display()),
		])
		.status()?;
	assert!(status.success(), "the run failed: {status}");
	let main = std::fs::read(main)?;
	let image = std::fs::read(&out)?;
	assert!(
		image.len() > main.len(),
		"the image did not grow: {} bytes in, {} out",
		main.len(),
		image.len()
	);
	assert_eq!(
		&image[..4],
		&main[..4],
		"the image's own header was rewritten"
	);
	Ok(())
}

#[test]
fn an_unpacked_build_reports_not_found() {
	let missing = exepack::find_loaded("kernel")
		.err()
		.expect("an unpacked build read an item back");
	assert_eq!(missing.kind(), exepack::ErrorKind::NotFound, "{missing}");
}

/// A copy of the carrier under `dir` whose header points at no section table, as a stripped image's may.
#[cfg(target_os = "linux")]
fn sectionless(dir: &std::path::Path) -> Result<PathBuf> {
	let mut bytes = std::fs::read(carrier())?;
	let endian = FileHeader64::<Endianness>::parse(bytes.as_slice())?.endian()?;
	let (header, _) = pod::from_bytes_mut::<FileHeader64<Endianness>>(&mut bytes)
		.map_err(|_| anyhow::anyhow!("invalid carrier header"))?;
	header.e_shoff.set(endian, 0);
	header.e_shnum.set(endian, 0);
	header.e_shstrndx.set(endian, object::elf::SHN_UNDEF);
	let sectionless = dir.join("sectionless");
	std::fs::write(&sectionless, bytes)?;
	std::fs::set_permissions(&sectionless, std::fs::metadata(carrier())?.permissions())?;
	Ok(sectionless)
}

/// A copy of the carrier under `dir` whose last load segment claims `extra` more bytes of memory than the file holds, as a large `.bss` does.
#[cfg(target_os = "linux")]
fn with_bss(dir: &std::path::Path, extra: u64) -> Result<PathBuf> {
	let mut bytes = std::fs::read(carrier())?;
	let endian = FileHeader64::<Endianness>::parse(bytes.as_slice())?.endian()?;
	let (header, _) = pod::from_bytes::<FileHeader64<Endianness>>(&bytes)
		.map_err(|_| anyhow::anyhow!("invalid carrier header"))?;
	let (phoff, phnum) = (
		usize::try_from(header.e_phoff.get(endian))?,
		usize::from(header.e_phnum.get(endian)),
	);
	let (programs, _) = pod::slice_from_bytes_mut::<object::elf::ProgramHeader64<Endianness>>(
		&mut bytes[phoff..],
		phnum,
	)
	.map_err(|_| anyhow::anyhow!("invalid carrier program headers"))?;
	let last = programs
		.iter_mut()
		.filter(|program| program.p_type.get(endian) == object::elf::PT_LOAD)
		.max_by_key(|program| program.p_vaddr.get(endian))
		.ok_or_else(|| anyhow::anyhow!("the carrier has no load segment"))?;
	last.p_memsz.set(endian, last.p_memsz.get(endian) + extra);
	let bss = dir.join("bss");
	std::fs::write(&bss, bytes)?;
	std::fs::set_permissions(&bss, std::fs::metadata(carrier())?.permissions())?;
	Ok(bss)
}

#[cfg(target_os = "linux")]
#[test]
fn a_large_bss_does_not_grow_the_file() -> Result<()> {
	const BSS: u64 = 256 << 20;
	let scratch = tempfile::tempdir()?;
	let main = with_bss(scratch.path(), BSS)?;
	let item = scratch.path().join("kernel");
	std::fs::write(&item, b"the item")?;
	let out = scratch.path().join("packed");
	let status = Command::new(exepack())
		.args([
			"--main",
			&main.display().to_string(),
			"--output",
			&out.display().to_string(),
			"--compress",
			"none",
			"--item",
			&format!("kernel={}", item.display()),
		])
		.status()?;
	assert!(status.success(), "the run failed: {status}");
	let growth = std::fs::metadata(&out)?.len() - std::fs::metadata(&main)?.len();
	assert!(
		growth < BSS / 16,
		"packing grew the file by {growth} bytes for a {BSS}-byte .bss"
	);
	Ok(())
}

#[test]
fn a_packed_copy_reads_its_items_back() -> Result<()> {
	let items = [
		("kernel", "the item, as it was written"),
		("mkfs.ext4", "the second item"),
		("a-b", "first colliding section name"),
		("a.b", "second colliding section name"),
		(
			"this_item_name_exceeds_sixteen_bytes",
			"a long name survives the carrier",
		),
	];
	if std::env::var_os("EXEPACK_PROBE").is_some() {
		#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
		std::fs::remove_file(std::env::current_exe()?)?;
		for (name, expected) in items {
			let mut bytes = Vec::new();
			exepack::find_loaded(name)?.read_to_end(&mut bytes)?;
			assert_eq!(bytes, expected.as_bytes(), "{name:?} did not read back");
		}
		// A missing name must stop at the padding after the last record, not read past it.
		let missing = exepack::find_loaded("never_embedded")
			.err()
			.expect("a missing item was not reported");
		assert_eq!(missing.kind(), exepack::ErrorKind::NotFound, "{missing}");
		assert_eq!(missing.name(), "never_embedded");
		return Ok(());
	}

	let scratch = tempfile::tempdir()?;
	let specs: Vec<String> = items
		.iter()
		.map(|(name, bytes)| {
			let item = scratch.path().join(name);
			std::fs::write(&item, bytes)?;
			Ok(format!("{name}={}", item.display()))
		})
		.collect::<Result<_>>()?;
	let mains = cfg_select! {
		target_os = "linux" => [carrier(), sectionless(scratch.path())?],
		_ => [carrier()],
	};
	for (index, main) in mains.iter().enumerate() {
		for compress in [
			None,
			Some("gzip"),
			Some("gzip:1"),
			Some("brotli"),
			Some("brotli:5"),
			Some("zstd"),
			Some("none"),
		] {
			let out = scratch.path().join(format!(
				"{index}-{}",
				compress.unwrap_or("default").replace(':', "-")
			));
			let mut command = Command::new(exepack());
			command.args([
				"--main",
				&main.display().to_string(),
				"--output",
				&out.display().to_string(),
			]);
			if let Some(compress) = compress {
				command.args(["--compress", compress]);
			}
			let status = command
				.args(specs.iter().flat_map(|spec| ["--item", spec]))
				.status()?;
			assert!(status.success(), "the run failed: {status}");
			#[cfg(target_os = "macos")]
			{
				let verification = Command::new("codesign")
					.args(["--verify", "--strict"])
					.arg(&out)
					.output()?;
				assert!(
					verification.status.success(),
					"the packed copy has an invalid signature: {}",
					String::from_utf8_lossy(&verification.stderr)
				);
			}
			// GNU strip moves the notes and their load segment but leaves each PT_NOTE's p_vaddr behind. The probe deletes its image, so strip a copy first.
			#[cfg(target_os = "linux")]
			let stripped = if index == 0 && compress.is_none() {
				let stripped = scratch.path().join(format!("{index}-stripped"));
				std::fs::copy(&out, &stripped)?;
				let status = Command::new("strip").arg(&stripped).status()?;
				assert!(status.success(), "strip failed: {status}");
				Some(stripped)
			} else {
				None
			};
			reads_back(&out)?;
			#[cfg(target_os = "linux")]
			if let Some(stripped) = stripped {
				reads_back(&stripped)?;
			}
		}
	}
	Ok(())
}

/// Run `image` as a probe of `a_packed_copy_reads_its_items_back` and assert that it read every item back.
fn reads_back(image: &std::path::Path) -> Result<()> {
	let child = Command::new(image)
		.env("EXEPACK_PROBE", "1")
		.args(["--exact", "a_packed_copy_reads_its_items_back"])
		.output()?;
	assert!(
		child.status.success(),
		"{} does not read its items back: {}\nstdout: {}\nstderr: {}",
		image.display(),
		child.status,
		String::from_utf8_lossy(&child.stdout),
		String::from_utf8_lossy(&child.stderr)
	);
	Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn packing_keeps_entitlements_and_load_commands() -> Result<()> {
	let scratch = tempfile::tempdir()?;
	let main = scratch.path().join("signed");
	let entitlements = scratch.path().join("entitlements.plist");
	std::fs::write(
		&entitlements,
		br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>"#,
	)?;
	std::fs::copy(carrier(), &main)?;
	// The linker's ad-hoc signature has no entitlements; re-sign with some.
	let signing = Command::new("codesign")
		.args(["--force", "--sign", "-", "--entitlements"])
		.arg(&entitlements)
		.arg(&main)
		.output()?;
	assert!(
		signing.status.success(),
		"the carrier could not be signed: {}",
		String::from_utf8_lossy(&signing.stderr)
	);

	let out = scratch.path().join("packed");
	let item = scratch.path().join("kernel");
	std::fs::write(&item, b"the item, as it was written")?;
	let status = Command::new(exepack())
		.args([
			"--main",
			&main.display().to_string(),
			"--output",
			&out.display().to_string(),
			"--item",
			&format!("kernel={}", item.display()),
		])
		.status()?;
	assert!(status.success(), "the run failed: {status}");

	// The entitlements codesign prints to stdout, and the header's ncmds and sizeofcmds (offsets 16 and 20).
	let read = |path: &std::path::Path| -> Result<(String, u32, u32)> {
		let display = Command::new("codesign")
			.args(["--display", "--entitlements", "-"])
			.arg(path)
			.output()?;
		let bytes = std::fs::read(path)?;
		let count = u32::from_le_bytes(bytes[16..20].try_into()?);
		let size = u32::from_le_bytes(bytes[20..24].try_into()?);
		Ok((
			String::from_utf8_lossy(&display.stdout).into_owned(),
			count,
			size,
		))
	};
	let (input_entries, input_count, input_size) = read(&main)?;
	let (entries, count, size) = read(&out)?;
	assert!(
		input_entries.contains("com.apple.security.cs.allow-jit"),
		"the entitlements were never applied to the carrier: {input_entries}"
	);
	assert!(
		entries.contains("com.apple.security.cs.allow-jit"),
		"the packed copy lost its entitlements\n  input: {input_entries}\n  output: {entries}"
	);
	// Packing must not add or resize a load command.
	assert_eq!(
		(count, size),
		(input_count, input_size),
		"packing changed the load command table"
	);
	let verification = Command::new("codesign")
		.args(["--verify", "--strict"])
		.arg(&out)
		.output()?;
	assert!(
		verification.status.success(),
		"the packed copy has an invalid signature: {}",
		String::from_utf8_lossy(&verification.stderr)
	);
	Ok(())
}

#[cfg(unix)]
#[test]
fn the_output_carries_the_inputs_permissions() -> Result<()> {
	use std::os::unix::fs::PermissionsExt;

	let scratch = tempfile::tempdir()?;
	let main = scratch.path().join("main");
	std::fs::copy(carrier(), &main)?;
	// A mode no default would land on.
	std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o4751))?;
	let out = scratch.path().join("packed");
	let status = Command::new(exepack())
		.args([
			"--main",
			&main.display().to_string(),
			"--output",
			&out.display().to_string(),
			"--item",
			&format!("kernel={}", carrier().display()),
		])
		.status()?;
	assert!(status.success(), "the run failed: {status}");
	let mode = std::fs::metadata(&out)?.permissions().mode() & 0o7777;
	assert_eq!(mode, 0o4751, "{} does not carry it", out.display());
	Ok(())
}
