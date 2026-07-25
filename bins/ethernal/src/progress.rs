//! Progress rendering mode and renderers shared by the gen, validator, and
//! account loops. Extracted from `gen_cmd` (D-3) so no namespace owns another's
//! presentation type.

use std::io::Write;

/// How progress is rendered (port of the isTTY branch in gen.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// stderr is a terminal: single updating line using \r.
    Tty,
    /// Pipe/buffer/CI: one log event per 10% boundary and on the last entry.
    NonTty,
}

/// One in-flight unit of work, rendered as a transient single line on a TTY and
/// as nothing at all off-TTY.
#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Deriving,
    Checking,
    Encrypting,
    Writing,
    // Verifying label lands with V4-2; kept so the enum is complete.
    #[allow(dead_code)]
    Verifying,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Phase::Deriving => "deriving",
            Phase::Checking => "checking",
            Phase::Encrypting => "encrypting",
            Phase::Writing => "writing",
            Phase::Verifying => "verifying",
        }
    }
}

/// Transient single-line progress reporter. Owns the `dirty` bit so clear() is
/// correct on every exit path, including error and cancel (invariant I-3).
pub(crate) struct PhaseReporter<'a> {
    out: &'a mut dyn Write,
    mode: Progress,
    dirty: bool,
}

impl<'a> PhaseReporter<'a> {
    pub(crate) fn new(out: &'a mut dyn Write, mode: Progress) -> Self {
        Self {
            out,
            mode,
            dirty: false,
        }
    }

    /// Render `[{i}/{total}] {phase}…` in place. Infallible (PR-7).
    /// No-op when `mode == NonTty`.
    pub(crate) fn phase(&mut self, i_1based: usize, total: usize, phase: Phase) {
        if self.mode != Progress::Tty {
            return;
        }
        let label = phase.label();
        let _ = write!(self.out, "\r\x1b[K[{i_1based}/{total}] {label}...");
        let _ = self.out.flush();
        self.dirty = true;
    }

    /// Erase the transient line if one is on screen, leaving the cursor at
    /// column 0 on a clean line. Infallible. Idempotent.
    pub(crate) fn clear(&mut self) {
        if self.mode != Progress::Tty || !self.dirty {
            return;
        }
        let _ = write!(self.out, "\r\x1b[K");
        let _ = self.out.flush();
        self.dirty = false;
    }

    /// Borrow the underlying writer after clearing, for the caller's durable line.
    pub(crate) fn out(&mut self) -> &mut dyn Write {
        self.clear();
        &mut *self.out
    }
}

impl Drop for PhaseReporter<'_> {
    fn drop(&mut self) {
        // Invariant I-3: erase any live phase line on every exit path.
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn tty_phase_writes_csi_line() {
        let mut buf = Vec::new();
        {
            let mut r = PhaseReporter::new(&mut buf, Progress::Tty);
            r.phase(1, 3, Phase::Encrypting);
            // Suppress Drop clear so the phase payload is asserted alone.
            r.dirty = false;
        }
        assert_eq!(buf, b"\r\x1b[K[1/3] encrypting...");
    }

    #[test]
    fn nontty_writes_nothing() {
        let mut buf = Vec::new();
        {
            let mut r = PhaseReporter::new(&mut buf, Progress::NonTty);
            r.phase(1, 3, Phase::Deriving);
            r.phase(2, 3, Phase::Encrypting);
            r.clear();
            r.phase(3, 3, Phase::Writing);
            r.clear();
            let _ = r.out();
        }
        assert!(buf.is_empty(), "NonTty buffer={buf:?}");
        assert!(!buf.contains(&b'\r'));
        assert!(!buf.contains(&0x1b));
    }

    #[test]
    fn clear_is_idempotent() {
        let mut buf = Vec::new();
        {
            let mut r = PhaseReporter::new(&mut buf, Progress::Tty);
            r.phase(1, 2, Phase::Writing);
            r.clear();
            r.clear(); // second clear must append nothing
                       // Drop clear is also a no-op when dirty is already false.
        }
        // Exactly one phase line + one erase CSI.
        assert_eq!(buf, b"\r\x1b[K[1/2] writing...\r\x1b[K");
        assert!(buf.ends_with(b"\r\x1b[K"));
    }

    #[test]
    fn write_errors_do_not_panic_or_propagate() {
        struct FailWrite;
        impl Write for FailWrite {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
            }
        }

        let mut w = FailWrite;
        let mut r = PhaseReporter::new(&mut w, Progress::Tty);
        r.phase(1, 1, Phase::Checking);
        r.clear();
        r.phase(1, 1, Phase::Verifying);
        // Drop also clears — must not panic.
        drop(r);
    }

    #[test]
    fn drop_clears_live_phase_line() {
        let mut buf = Vec::new();
        {
            let mut r = PhaseReporter::new(&mut buf, Progress::Tty);
            r.phase(2, 3, Phase::Encrypting);
            // No explicit clear — Drop must erase (invariant I-3).
        }
        assert!(
            buf.ends_with(b"\r\x1b[K"),
            "Drop must leave buffer ending in CSI erase, got {buf:?}"
        );
        let s = String::from_utf8_lossy(&buf);
        assert!(
            !s.ends_with("encrypting..."),
            "Drop must not leave phase label on screen, got {s:?}"
        );
    }

    #[test]
    fn labels_are_lowercase_and_never_warning() {
        for phase in [
            Phase::Deriving,
            Phase::Checking,
            Phase::Encrypting,
            Phase::Writing,
            Phase::Verifying,
        ] {
            let label = phase.label();
            assert_eq!(label, label.to_lowercase());
            assert!(!label.contains("WARNING"));
            assert!(!label.to_uppercase().contains("WARNING"));
        }
    }

    #[test]
    fn out_clears_then_returns_writer() {
        let mut buf = Vec::new();
        {
            let mut r = PhaseReporter::new(&mut buf, Progress::Tty);
            r.phase(1, 1, Phase::Deriving);
            {
                let w = r.out();
                let _ = writeln!(w, "durable");
            }
            // out() already cleared; Drop is a no-op.
        }
        assert_eq!(buf, b"\r\x1b[K[1/1] deriving...\r\x1b[Kdurable\n");
    }
}
