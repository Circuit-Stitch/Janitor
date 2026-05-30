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

/// Something went wrong reconstructing JSON from Entries.
#[derive(Debug, thiserror::Error)]
pub enum ShapeError {
    /// A leaf's stored content was not valid for its [`LeafKind`] (e.g. a
    /// `Number` Entry whose content is not a JSON number). Only reachable for
    /// hand-constructed Entries; [`flatten`] never produces such a set.
    #[error("entry {name} has malformed {kind:?} content")]
    MalformedLeaf { name: String, kind: LeafKind },
}

/// Rebuild a JSON object from Entries. Inverse of [`flatten`].
pub fn unflatten(entries: &BTreeMap<EntryName, Value>) -> Result<Json, ShapeError> {
    let mut root = Map::new();
    for (name, value) in entries {
        let leaf = value_to_leaf(name, value)?;
        insert_at_path(&mut root, &name.segments(), leaf);
    }
    Ok(Json::Object(root))
}

fn value_to_leaf(name: &EntryName, value: &Value) -> Result<Json, ShapeError> {
    let malformed = || ShapeError::MalformedLeaf {
        name: name.to_string(),
        kind: value.kind(),
    };
    let content = value.expose();
    let json = match value.kind() {
        LeafKind::String => Json::String(content.to_string()),
        LeafKind::Number => {
            let n: serde_json::Number = serde_json::from_str(content).map_err(|_| malformed())?;
            Json::Number(n)
        }
        LeafKind::Bool => Json::Bool(content.parse().map_err(|_| malformed())?),
        LeafKind::Null => Json::Null,
        LeafKind::Json => serde_json::from_str(content).map_err(|_| malformed())?,
    };
    Ok(json)
}

fn insert_at_path(root: &mut Map<String, Json>, segments: &[String], leaf: Json) {
    // `segments` is always non-empty for Entries produced by `flatten`.
    let Some((first, rest)) = segments.split_first() else {
        return;
    };
    if rest.is_empty() {
        root.insert(first.clone(), leaf);
        return;
    }
    let child = root
        .entry(first.clone())
        .or_insert_with(|| Json::Object(Map::new()));
    if let Json::Object(map) = child {
        insert_at_path(map, rest, leaf);
    }
    // If `child` already exists and isn't an object, the Entry set is internally
    // inconsistent; `flatten` never produces such a set, so we keep the first
    // writer rather than panicking.
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

    #[test]
    fn round_trips_through_flatten_unflatten() {
        let inputs = [
            r#"{"A":"1","B":"2"}"#,
            r#"{"db":{"primary":{"url":"postgres://x"}}}"#,
            r#"{"db":{"host":"h","port":5432}}"#,
            r#"{"port":5432,"tls":true,"opt":null}"#,
            r#"{"hosts":["a","b"],"meta":{}}"#,
            r#"{"a.b":"flat","a":{"b":"nested"}}"#,
            r#"{"":"empty-key","x":{"":"nested-empty-key"}}"#,
            r#"{"big":1.5e3,"neg":-7}"#,
            // Strings that look like other kinds must round-trip AS strings
            // (the reason LeafKind exists — content is never re-coerced).
            r#"{"a":"null","b":"true","c":"5432"}"#,
            r#"{"data":[{"id":1},{"id":2}]}"#, // array of objects (opaque Json leaf)
            r#"{"config":{"sub":{}}}"#,        // nested empty object at depth
            r#"{"a":{"b":{"c":{"d":"deep"}}}}"#, // deep nesting
            r#"{"a\\b":"v1"}"#,                // key containing a literal backslash
            "{}",
        ];
        for input in inputs {
            let original: Json = serde_json::from_str(input).unwrap();
            let object = match &original {
                Json::Object(m) => m.clone(),
                _ => unreachable!(),
            };
            let rebuilt = unflatten(&flatten(&object)).unwrap();
            assert_eq!(rebuilt, original, "round-trip changed value for {input}");
        }
    }

    #[test]
    fn unflatten_rejects_malformed_number_leaf() {
        let mut entries = BTreeMap::new();
        entries.insert(
            name(&["port"]),
            Value::new("not-a-number", LeafKind::Number),
        );
        let err = unflatten(&entries).unwrap_err();
        assert!(matches!(err, ShapeError::MalformedLeaf { .. }));
    }

    #[test]
    fn unflatten_rejects_malformed_bool_and_json_leaves() {
        // The Bool and Json arms are the other two fallible reconstructions.
        for bad in [
            Value::new("maybe", LeafKind::Bool),
            Value::new("{not json", LeafKind::Json),
        ] {
            let mut entries = BTreeMap::new();
            entries.insert(name(&["x"]), bad);
            assert!(matches!(
                unflatten(&entries).unwrap_err(),
                ShapeError::MalformedLeaf { .. }
            ));
        }
    }
}
