use core::fmt::{self, Debug, Display};

#[cfg(feature = "std")]
use std::boxed::Box;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Default)]
pub struct Error {
    _private: (),

    #[cfg(feature = "std")]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_source(
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            _private: (),
            source: Some(source.into()),
        }
    }
}

impl Debug for Error {
    #[cfg(not(feature = "std"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature::Error {}")
    }

    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature::Error { source: ")?;

        if let Some(source) = &self.source {
            write!(f, "Some({})", source)?;
        } else {
            f.write_str("None")?;
        }

        f.write_str(" }")
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature error")?;

        #[cfg(feature = "std")]
        {
            if let Some(source) = &self.source {
                write!(f, ": {}", source)?;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for Error {
    fn from(source: Box<dyn std::error::Error + Send + Sync + 'static>) -> Error {
        Self::from_source(source)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}
