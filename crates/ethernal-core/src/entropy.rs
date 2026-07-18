//! OS CSPRNG entropy behind an injectable trait.
//!
//! `getrandom` is the only new dependency in the keygen feature (D-1).
//! Production code uses [`OsEntropy`]; deterministic overrides live only in
//! the bin's `#[cfg(test)]` (never here — S-4).

/// Source of cryptographically secure random bytes.
///
/// `Sync` so it can sit behind `&dyn Entropy` in the bin's dependency seam.
pub trait Entropy: Sync {
    /// Fills `buf` with cryptographically secure random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

/// Production entropy: OS CSPRNG via `getrandom::fill`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

/// Errors from the OS entropy backend.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EntropyError {
    /// The OS random source failed.
    #[error("entropy: {0}")]
    Os(String),
}

impl Entropy for OsEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|e| EntropyError::Os(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_and_differs() {
        let eng = OsEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        eng.fill(&mut a).expect("first fill");
        eng.fill(&mut b).expect("second fill");
        // Fully written (not left as zeros) — collision with all-zero is
        // astronomically unlikely for a CSPRNG.
        assert_ne!(a, [0u8; 32], "buffer should be fully written");
        assert_ne!(b, [0u8; 32], "buffer should be fully written");
        assert_ne!(a, b, "two fills should differ");
    }
}
