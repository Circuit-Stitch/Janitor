//! The secret-shape model: how a Secret Set's stored value is parsed into
//! comparable Entries, and the zeroizing types that hold secret material.

mod flatten;
mod name;
mod plaintext;
mod shape;
mod value;

pub use flatten::{flatten, unflatten, ShapeError};
pub use name::EntryName;
pub use plaintext::Plaintext;
pub use shape::{SecretBytes, SecretShape};
pub use value::{LeafKind, Value};
