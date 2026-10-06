//! What the command line takes, what a failed run leaves behind, and what a packed copy reads back.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;

/// The `exepack` cargo built for this run.
fn exepack() -> &'static str {
	env!("CARGO_BIN_EXE_exepack")
}

/// The image to embed into: this test binary, which is one of the containers the tool writes. Nothing has to be built for it.
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

#[cfg(not(target_os = "macos"))]
#[test]
fn macho_append_requires_macos() -> Result<()> {
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
		stderr.contains("requires macOS for code signing"),
		"{stderr}"
	);
	assert!(!out.exists(), "a rejected Mach-O left an output image");
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
			exepack::find_item(name)?.read_to_end(&mut bytes)?;
			assert_eq!(bytes, expected.as_bytes(), "{name:?} did not read back");
		}
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
	let main = carrier();
	for compress in [None, Some("gzip"), Some("none")] {
		let out = scratch.path().join(compress.unwrap_or("default"));
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
		let child = Command::new(&out)
			.env("EXEPACK_PROBE", "1")
			.args(["--exact", "a_packed_copy_reads_its_items_back"])
			.output()?;
		assert!(
			child.status.success(),
			"the packed copy does not read its items back: {}\nstdout: {}\nstderr: {}",
			child.status,
			String::from_utf8_lossy(&child.stdout),
			String::from_utf8_lossy(&child.stderr)
		);
	}
	Ok(())
}

#[cfg(unix)]
#[test]
fn the_output_carries_the_inputs_permissions() -> Result<()> {
	use std::os::unix::fs::PermissionsExt;

	let scratch = tempfile::tempdir()?;
	let main = scratch.path().join("main");
	std::fs::copy(carrier(), &main)?;
	// A mode no default would land on, and one that no `0o755` could be mistaken for.
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
