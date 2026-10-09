use std::fmt;

/// Why [`find_loaded`](crate::find_loaded) could not hand an item back.
#[derive(Debug)]
pub struct Error {
	kind: ErrorKind,
	/// The item asked for.
	name: String,
	/// What went wrong, worded for whoever reads the log.
	message: String,
	source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// What the caller can do about an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
	/// The running image carries no item under the name, as an unpacked build does; the caller may fall back.
	NotFound,
	/// The item cannot be read back: the image is malformed, the item was stored by a newer exepack, or the platform
	/// reads no items.
	Invalid,
}

impl Error {
	pub fn kind(&self) -> ErrorKind {
		self.kind
	}

	/// The item asked for.
	pub fn name(&self) -> &str {
		&self.name
	}

	pub(super) fn not_found(message: impl Into<String>) -> Self {
		Self {
			kind: ErrorKind::NotFound,
			name: String::new(),
			message: message.into(),
			source: None,
		}
	}

	pub(super) fn invalid(message: impl Into<String>) -> Self {
		Self {
			kind: ErrorKind::Invalid,
			..Self::not_found(message)
		}
	}

	/// `self`, about the item asked for as `name`.
	pub(super) fn named(self, name: &str) -> Self {
		Self {
			name: name.to_owned(),
			..self
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "item {:?}: {}", self.name, self.message)
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		self.source.as_deref().map(|source| source as _)
	}
}

/// Turn a failed step of reading the running image into an [`ErrorKind::Invalid`] that says which step it was.
pub(super) trait OrInvalid<T> {
	fn or_invalid(self, message: &str) -> Result<T, Error>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> OrInvalid<T> for Result<T, E> {
	fn or_invalid(self, message: &str) -> Result<T, Error> {
		self.map_err(|source| Error {
			source: Some(Box::new(source)),
			..Error::invalid(message)
		})
	}
}

impl<T> OrInvalid<T> for Option<T> {
	fn or_invalid(self, message: &str) -> Result<T, Error> {
		self.ok_or_else(|| Error::invalid(message))
	}
}
