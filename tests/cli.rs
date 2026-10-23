//! What the command line takes, what a failed run leaves behind, and what a packed copy reads back.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use assert2::{assert, check};
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
	check!(stderr.contains("kernel"));
	check!(stderr.contains(&missing.display().to_string()));
	check!(!out.exists());
	Ok(())
}

#[test]
fn an_unpacked_build_reports_not_found() {
	assert!(let Err(missing) = exepack::find_loaded("kernel"));
	check!(missing.kind() == exepack::ErrorKind::NotFound);
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
			let mut item = exepack::find_loaded(name)?;
			// Only an item packed with `--compress none` lends its bytes.
			if let Some(stored) = item.as_bytes() {
				check!(stored == expected.as_bytes(), "{name:?} is stored wrong");
			}
			let mut bytes = Vec::new();
			item.read_to_end(&mut bytes)?;
			check!(bytes == expected.as_bytes(), "{name:?} did not read back");
		}
		// A missing name must stop at the padding after the last record, not read past it.
		assert!(let Err(missing) = exepack::find_loaded("never_embedded"));
		check!(missing.kind() == exepack::ErrorKind::NotFound);
		check!(missing.name() == "never_embedded");
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
		for compress in [None, Some("none")] {
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
	check!((count, size) == (input_count, input_size));
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
	check!(status.success());
	let mode = std::fs::metadata(&out)?.permissions().mode() & 0o7777;
	check!(mode == 0o4751);
	Ok(())
}
