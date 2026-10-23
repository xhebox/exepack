//! Read back what `exepack` embedded.

mod error;
mod format;

pub use error::{Error, ErrorKind};
pub use format::{Compression, Container, Item, find_loaded};
