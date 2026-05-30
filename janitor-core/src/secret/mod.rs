//! The secret-shape model: how a Secret Set's stored value is parsed into
//! comparable Entries, and the zeroizing types that hold secret material.

mod value;

pub use value::{LeafKind, Value};
