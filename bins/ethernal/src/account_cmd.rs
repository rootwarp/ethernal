//! Runtime for `account new` / `account recover`.
//!
//! A3-3 ships thin placeholders so clap/TTY/validation can land without the
//! derive→address→encrypt→write pipeline (A3-4).

use ethernal_core::cancel::CancelToken;

use crate::account_cli::AccountConfig;
use crate::errors::AppError;

/// Production entry for `account new`. Pipeline lands in A3-4.
pub fn run_account_new(_cfg: &AccountConfig, _cancel: &CancelToken) -> Result<(), AppError> {
    Ok(())
}

/// Production entry for `account recover`. Pipeline lands in A4-1.
pub fn run_account_recover(_cfg: &AccountConfig, _cancel: &CancelToken) -> Result<(), AppError> {
    Ok(())
}
