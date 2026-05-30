//! The secret-shape model: how a Secret Set's stored value is parsed into
//! comparable Entries, and the zeroizing types that hold secret material.

mod name;
mod value;

pub use name::EntryName;
pub use value::{LeafKind, Value};
