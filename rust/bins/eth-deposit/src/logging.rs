//! A minimal structured logger mirroring the subset of Go's `log/slog` that
//! the CLI uses: leveled key=value text lines or JSON objects on stderr.
//! Hand-rolled (rather than pulling `tracing`) to keep the output format under
//! our control for parity with the Go binary's stderr.

use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

/// A leveled logger writing slog-like records to a shared writer.
pub struct Logger {
    level: Level,
    format: Format,
    w: Mutex<Box<dyn Write + Send>>,
}

impl Logger {
    pub fn new(level: Level, format: Format, w: Box<dyn Write + Send>) -> Self {
        Logger {
            level,
            format,
            w: Mutex::new(w),
        }
    }

    /// A logger that swallows everything (Go: slog with io.Discard).
    #[allow(dead_code)]
    pub fn discard() -> Self {
        Logger::new(Level::Error, Format::Text, Box::new(std::io::sink()))
    }

    pub fn stderr(level: Level, format: Format) -> Self {
        Logger::new(level, format, Box::new(std::io::stderr()))
    }

    pub fn debug(&self, msg: &str, kv: &[(&str, String)]) {
        self.log(Level::Debug, msg, kv);
    }

    pub fn info(&self, msg: &str, kv: &[(&str, String)]) {
        self.log(Level::Info, msg, kv);
    }

    pub fn error(&self, msg: &str, kv: &[(&str, String)]) {
        self.log(Level::Error, msg, kv);
    }

    fn log(&self, level: Level, msg: &str, kv: &[(&str, String)]) {
        if level < self.level {
            return;
        }
        let line = match self.format {
            Format::Text => render_text(level, msg, kv),
            Format::Json => render_json(level, msg, kv),
        };
        if let Ok(mut w) = self.w.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }
}

/// RFC3339 timestamp with millisecond precision in UTC ("Z"), e.g.
/// 2026-07-17T07:20:31.123Z. (Go slog renders local time; we standardise on
/// UTC — timestamps are not part of any parity assertion.)
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Converts days since the Unix epoch to (year, month, day).
/// Howard Hinnant's civil_from_days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Quotes a value slog-style: bare if it contains no whitespace/quote/equals
/// characters, otherwise wrapped in double quotes with escapes.
fn quote_value(v: &str) -> String {
    let needs_quote = v.is_empty()
        || v.chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '=' || c.is_control());
    if !needs_quote {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render_text(level: Level, msg: &str, kv: &[(&str, String)]) -> String {
    let mut line = format!(
        "time={} level={} msg={}",
        timestamp(),
        level.as_str(),
        quote_value(msg)
    );
    for (k, v) in kv {
        let _ = write!(line, " {}={}", k, quote_value(v));
    }
    line.push('\n');
    line
}

fn render_json(level: Level, msg: &str, kv: &[(&str, String)]) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("time".to_string(), serde_json::Value::String(timestamp()));
    obj.insert(
        "level".to_string(),
        serde_json::Value::String(level.as_str().to_string()),
    );
    obj.insert(
        "msg".to_string(),
        serde_json::Value::String(msg.to_string()),
    );
    for (k, v) in kv {
        // Numeric-looking values stay strings for simplicity; parity with
        // slog's typed attrs is not asserted anywhere.
        obj.insert(k.to_string(), serde_json::Value::String(v.clone()));
    }
    let mut line = serde_json::Value::Object(obj).to_string();
    line.push('\n');
    line
}
