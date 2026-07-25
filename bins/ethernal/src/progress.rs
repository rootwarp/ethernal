//! Progress rendering mode and renderers shared by the gen, validator, and
//! account loops. Extracted from `gen_cmd` (D-3) so no namespace owns another's
//! presentation type.

/// How progress is rendered (port of the isTTY branch in gen.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// stderr is a terminal: single updating line using \r.
    Tty,
    /// Pipe/buffer/CI: one log event per 10% boundary and on the last entry.
    NonTty,
}
