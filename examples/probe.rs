//! A stand-in for a program that embeds items: look one up by name, read it to the end, exit.

use std::io;
use std::process::ExitCode;

#[allow(clippy::print_stderr)]
fn main() -> ExitCode {
	let name = std::env::args()
		.nth(1)
		.unwrap_or_else(|| "text".to_string());

	match exepack::find_loaded(&name) {
		Ok(mut item) => {
			if let Err(error) = io::copy(&mut item, &mut io::sink()) {
				eprintln!("read {name}: {error}");
				return ExitCode::FAILURE;
			}
		}
		Err(error) if error.kind() == exepack::ErrorKind::NotFound => {}
		Err(error) => {
			eprintln!("find {name}: {error}");
			return ExitCode::FAILURE;
		}
	}

	ExitCode::SUCCESS
}
