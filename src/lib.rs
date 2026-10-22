//! Read back what `exepack` embedded.

mod format;

pub use format::{Compression, Container, Error, ErrorKind, Item, find_loaded};
