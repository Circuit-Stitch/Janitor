//! Flatten a parsed JSON object into dotted-path Entries (and, with Task 6,
//! back again). Only JSON *objects* are descended into; every other value
//! (string, number, bool, null, array, empty object) is a leaf → one Entry,
//! with its [`LeafKind`] preserved. See ADR 0008.

use std::collections::BTreeMap;

use serde_json::{Map, Value as Json};

use super::name::EntryName;
use super::value::{LeafKind, Value};

/// Flatten a JSON object into Entries keyed by dotted-path [`EntryName`].
pub fn flatten(object: &Map<String, Json>) -> BTreeMap<EntryName, Value> {
    let mut out = BTreeMap::new();
    let mut path: Vec<String> = Vec::new();
    flatten_object(object, &mut path, &mut out);
    out
}

fn flatten_object(
    object: &Map<String, Json>,
    path: &mut Vec<String>,
    out: &mut BTreeMap<EntryName, Value>,
) {
    for (key, child) in object {
        path.push(key.clone());
        match child {
            Json::Object(inner) if !inner.is_empty() => flatten_object(inner, path, out),
            leaf => {
                out.insert(EntryName::from_path(path), leaf_to_value(leaf));
            }
        }
        path.pop();
    }
}

fn leaf_to_value(leaf: &Json) -> Value {
    match leaf {
        Json::String(s) => Value::new(s.clone(), LeafKind::String),
        Json::Number(n) => Value::new(n.to_string(), LeafKind::Number),
        Json::Bool(b) => Value::new(b.to_string(), LeafKind::Bool),
        Json::Null => Value::new("null", LeafKind::Null),
        // Arrays and (empty) objects: keep the verbatim compact JSON text.
        Json::Array(_) | Json::Object(_) => Value::new(leaf.to_string(), LeafKind::Json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_obj(json: &str) -> Map<String, Json> {
        match serde_json::from_str(json).unwrap() {
            Json::Object(m) => m,
            _ => panic!("test input must be a JSON object"),
        }
    }

    fn name(segs: &[&str]) -> EntryName {
        EntryName::from_path(&segs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn flattens_flat_string_map() {
        let entries = flatten(&parse_obj(r#"{"A":"1","B":"2"}"#));
        let names: Vec<_> = entries.keys().map(|n| n.as_str().to_string()).collect();
        assert_eq!(names, vec!["A", "B"]);
        assert_eq!(entries[&name(&["A"])].kind(), LeafKind::String);
        assert_eq!(entries[&name(&["A"])].expose(), "1");
    }

    #[test]
    fn flattens_nested_to_dotted_path() {
        let entries = flatten(&parse_obj(r#"{"db":{"primary":{"url":"x"}}}"#));
        let v = &entries[&name(&["db", "primary", "url"])];
        assert_eq!(entries.len(), 1);
        assert_eq!(v.expose(), "x");
        assert_eq!(v.kind(), LeafKind::String);
    }

    #[test]
    fn preserves_non_string_leaf_kinds() {
        let entries = flatten(&parse_obj(r#"{"port":5432,"tls":true,"opt":null}"#));
        assert_eq!(entries[&name(&["port"])].kind(), LeafKind::Number);
        assert_eq!(entries[&name(&["port"])].expose(), "5432");
        assert_eq!(entries[&name(&["tls"])].kind(), LeafKind::Bool);
        assert_eq!(entries[&name(&["tls"])].expose(), "true");
        assert_eq!(entries[&name(&["opt"])].kind(), LeafKind::Null);
    }

    #[test]
    fn array_and_empty_object_are_opaque_json_leaves() {
        let entries = flatten(&parse_obj(r#"{"hosts":["a","b"],"meta":{}}"#));
        assert_eq!(entries[&name(&["hosts"])].kind(), LeafKind::Json);
        assert_eq!(entries[&name(&["hosts"])].expose(), r#"["a","b"]"#);
        assert_eq!(entries[&name(&["meta"])].kind(), LeafKind::Json);
        assert_eq!(entries[&name(&["meta"])].expose(), "{}");
    }

    #[test]
    fn literal_dot_key_is_escaped_not_nested() {
        let entries = flatten(&parse_obj(r#"{"a.b":"flat","a":{"b":"nested"}}"#));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[&name(&["a.b"])].expose(), "flat");
        assert_eq!(entries[&name(&["a", "b"])].expose(), "nested");
    }

    #[test]
    fn nested_siblings_keep_correct_prefixes() {
        // Two leaves under the same nested parent: confirms `path` pops back to
        // ["db"] between siblings rather than leaking into the next name.
        let entries = flatten(&parse_obj(r#"{"db":{"host":"h","port":5432}}"#));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[&name(&["db", "host"])].expose(), "h");
        assert_eq!(entries[&name(&["db", "port"])].kind(), LeafKind::Number);
        assert_eq!(entries[&name(&["db", "port"])].expose(), "5432");
    }

    #[test]
    fn empty_top_level_object_yields_no_entries() {
        // A top-level {} has no leaves → zero Entries. (Contrast: a *nested*
        // empty object is itself one Json leaf, per ADR 0008.)
        assert!(flatten(&parse_obj("{}")).is_empty());
    }
}
