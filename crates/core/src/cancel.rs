//! Cooperative cancellation, replacing Go's `context.Context` in the ported
//! pipeline. A [`CancelToken`] is cheap to clone and share; the CLI wires a
//! SIGINT handler to `cancel()`, and long-running operations check
//! `is_cancelled()` between units of work. A cancelled operation maps to the
//! user-abort exit code (4), mirroring `context.Canceled`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shareable cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Creates a new, uncancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the token cancelled. Idempotent; visible to all clones.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Reports whether `cancel` has been called on this token or any clone.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
