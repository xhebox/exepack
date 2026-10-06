//! Read back what `exepack` embedded.

mod format;
#[cfg(target_os = "macos")]
mod packet;

pub use format::{Compression, Container};

use std::io::Read;

use anyhow::Result;

/// The bytes embedded under `name`, decompressed as they are read.
pub fn find_item(name: &str) -> Result<impl Read> {
	format::find_loaded(name)
}
