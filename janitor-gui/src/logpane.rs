//! The Diagnostic Log (ADR 0017): Janitor's ONLY diagnostic surface. A bounded,
//! in-memory ring buffer fed by a single `tracing` layer — no stderr/fmt layer,
//! no file, no stdout. The GUI drains it into a panel; nothing ever reaches a
//! cross-process channel a sibling could scrape.
//!
//! Capture is restricted to `janitor*` targets so the AWS-SDK/hyper event
//! firehose stays out (lean, per the owner's perf concern). Only error-safe
//! signal is ever emitted at the call-sites (THREAT-MODEL / ADR 0017): never a
//! Value, Credential, or the SSO token.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Oldest lines drop past this cap. Bounded so a long Session cannot grow memory.
const MAX_LINES: usize = 1000;

/// The panel's verbosity filter: **lower = more severe**. The dropdown's value is
/// a *maximum* — `INFO` shows everything, `ERROR` shows only errors. Carried as a
/// 1-based int across the Slint boundary (the dropdown supplies it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FilterLevel(u8);

impl FilterLevel {
    pub const ERROR: FilterLevel = FilterLevel(1);
    pub const WARN: FilterLevel = FilterLevel(2);
    pub const INFO: FilterLevel = FilterLevel(3);
    /// The most verbose selectable level — shows everything. The default.
    pub const MAX: FilterLevel = FilterLevel::INFO;

    /// Clamp a (1-based) dropdown int from the UI into a valid level.
    pub fn from_ui(v: i32) -> FilterLevel {
        FilterLevel((v.clamp(Self::ERROR.0 as i32, Self::INFO.0 as i32)) as u8)
    }

    fn value(self) -> u8 {
        self.0
    }
}

impl Default for FilterLevel {
    fn default() -> Self {
        FilterLevel::MAX
    }
}

/// One captured line: its severity (for the panel's level filter) and the
/// pre-formatted, error-safe text.
pub struct LogLine {
    pub level: Level,
    pub text: String,
}

/// The in-memory ring buffer. `version` bumps on every push so the UI's poll can
/// cheaply tell whether there is anything new to re-render.
#[derive(Default)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
    pub version: u64,
}

/// A line's own verbosity, on the same scale as [`FilterLevel`]. Debug/Trace
/// (never emitted by our call-sites) sit one past `MAX`, above any selectable
/// threshold, so they never show.
fn rank(level: &Level) -> u8 {
    match *level {
        Level::ERROR => FilterLevel::ERROR.value(),
        Level::WARN => FilterLevel::WARN.value(),
        Level::INFO => FilterLevel::INFO.value(),
        _ => FilterLevel::MAX.value() + 1,
    }
}

impl LogBuffer {
    fn push(&mut self, level: Level, text: String) {
        if self.lines.len() >= MAX_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(LogLine { level, text });
        self.version = self.version.wrapping_add(1);
    }

    /// Drop all lines (the panel's Clear button). Bumps `version` so the UI poll
    /// re-renders the now-empty stream.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.version = self.version.wrapping_add(1);
    }

    /// Render the lines at or below `max` verbosity as one newline-joined string,
    /// **newest first** (most recent at the top), for a read-only selectable text
    /// view. Newest-first means the current state is always visible without
    /// scrolling — a stale failure can't masquerade as the live one (the
    /// TextEdit has no auto-scroll-to-bottom). `FilterLevel::INFO` shows all;
    /// `FilterLevel::ERROR` shows only errors.
    pub fn render(&self, max: FilterLevel) -> String {
        let mut out = String::new();
        for line in self.lines.iter().rev() {
            if rank(&line.level) <= max.value() {
                out.push_str(&line.text);
                out.push('\n');
            }
        }
        out
    }
}

/// A shared handle to the buffer. Cloneable; the `tracing` layer and the UI poll
/// both hold one.
pub type SharedLog = Arc<Mutex<LogBuffer>>;

/// UTC `HH:MM:SS` from the wall clock — no `chrono` dependency. UTC is fine for a
/// correlation timestamp; local-tz formatting isn't worth a crate here.
fn hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = secs % 86_400;
    format!("{:02}:{:02}:{:02}", d / 3600, (d % 3600) / 60, d % 60)
}

/// Collects an event's `message` plus its other fields into one line.
struct LineVisitor {
    message: String,
    fields: Vec<String>,
}

impl Visit for LineVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // The `message` field arrives here (a `fmt::Arguments`); strip the
        // surrounding quotes Debug would add to a plain string is unnecessary —
        // Arguments' Debug is the rendered text.
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.message = rendered;
        } else {
            self.fields.push(format!("{}={rendered}", field.name()));
        }
    }
}

/// The one and only `tracing` sink: format each `janitor*` event into the buffer.
struct BufferLayer {
    log: SharedLog,
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // Lean + safe: only our own events, never the SDK/hyper firehose.
        if !meta.target().starts_with("janitor") {
            return;
        }
        let mut v = LineVisitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut v);
        let level = *meta.level();
        let suffix = if v.fields.is_empty() {
            String::new()
        } else {
            format!("  ({})", v.fields.join(" "))
        };
        // e.g. "20:31:04 WARN  GetRoleCredentials failed — AccessDeniedException: …  (op=GetRoleCredentials code=AccessDeniedException)"
        let text = format!("{} {:<5} {}{}", hms(), level, v.message, suffix);
        if let Ok(mut buf) = self.log.lock() {
            buf.push(level, text);
        }
    }
}

/// Install the Diagnostic Log as the process's global `tracing` subscriber and
/// return the shared buffer for the UI to poll. Also silences panics (ADR 0017):
/// Rust's default hook prints to stderr — a cross-process channel we deny — so we
/// replace it with a no-op. A developer still breaks at the unwind point under a
/// debugger.
pub fn install() -> SharedLog {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let log: SharedLog = Arc::new(Mutex::new(LogBuffer::default()));
    tracing_subscriber::registry()
        .with(BufferLayer { log: log.clone() })
        .init();

    std::panic::set_hook(Box::new(|_| { /* zero stderr — ADR 0017 */ }));

    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_threshold_keeps_at_or_below_verbosity() {
        let mut b = LogBuffer::default();
        b.push(Level::INFO, "i".into());
        b.push(Level::WARN, "w".into());
        b.push(Level::ERROR, "e".into());
        // Newest-first: Info → e,w,i; Warn → e,w; Error → e only.
        assert_eq!(b.render(FilterLevel::INFO), "e\nw\ni\n");
        assert_eq!(b.render(FilterLevel::WARN), "e\nw\n");
        assert_eq!(b.render(FilterLevel::ERROR), "e\n");
    }

    #[test]
    fn ring_buffer_drops_oldest_past_cap() {
        let mut b = LogBuffer::default();
        for i in 0..(MAX_LINES + 5) {
            b.push(Level::INFO, format!("line{i}"));
        }
        let rendered = b.render(FilterLevel::INFO);
        assert!(!rendered.contains("line0\n"), "oldest dropped");
        assert!(
            rendered.contains(&format!("line{}\n", MAX_LINES + 4)),
            "newest kept"
        );
        assert_eq!(rendered.lines().count(), MAX_LINES);
    }

    #[test]
    fn version_bumps_on_push() {
        let mut b = LogBuffer::default();
        let v0 = b.version;
        b.push(Level::INFO, "x".into());
        assert_ne!(b.version, v0);
    }
}
