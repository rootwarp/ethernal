//! Exit code conventions for ethernal (port of `cmd/ethernal/exit.go`):
//!
//!   0 — success
//!   2 — user / configuration errors (bad input, validation, unknown network,
//!       missing/malformed file, invalid hex, out-of-bounds --index, negative
//!       fees, build-side RPC chain-ID mismatch)
//!   3 — signer / crypto errors (bad key, no Ledger device, Ethereum app not
//!       open, signer-side chain ID mismatch, signer closed)
//!   4 — user abort (SIGINT / cancellation / Ledger device rejection)
//!   5 — broadcast / RPC errors (dial failure, gas/nonce estimation failure,
//!       eth_sendRawTransaction error, broadcast-side chain ID mismatch)
//!   1 — fallback for any other error

use std::fmt;

use ethernal_core::bip39::Bip39Error;
use ethernal_core::bls::BlsError;
use ethernal_core::deposit::DepositError;
use ethernal_core::hd::HdError;
use ethernal_core::hd_secp256k1::Bip32Error;
use ethernal_core::network::NetworkError;
use ethernal_core::output::OutputError;
use ethernal_keystore::KeystoreError;
use ethernal_signer::SignerError;
use ethernal_tx::TxError;

/// The bin-level error type. Every command action returns this; `main` maps
/// it to an exit code via [`exit_code_for`] and logs the Display rendering.
#[derive(Debug)]
pub enum AppError {
    /// A usage/validation error with an explicit exit code — the port of
    /// `ucli.Exit(msg, code)`.
    Exit {
        msg: String,
        code: i32,
    },

    /// A low-level error wrapped as a user/config error — the port of
    /// `WrapInputErr(what, err)`; renders "{what}: invalid input: {source}"
    /// and maps to exit code 2.
    Input {
        what: String,
        source: Box<AppError>,
    },

    /// SIGINT / cancellation — the port of `context.Canceled` +
    /// `ErrUserAborted`. Exit code 4. Also ceremony mismatch abort (F-6).
    Aborted(String),

    /// BIP-39 validation / entropy conversion failure (user input). Exit code 2.
    Bip39(Bip39Error),

    /// EIP-2333 HD derivation failure (crypto). Exit code 3.
    Hd(HdError),

    /// BIP-32 secp256k1 HD derivation failure (crypto). Exit code 3.
    Bip32(Bip32Error),

    Keystore(KeystoreError),
    Deposit(DepositError),
    Network(NetworkError),
    /// Deposit-data write path (`gen`). Exit code 1 via fallback — keystore
    /// writes from `validator new`/`recover` must use call-site `Exit{code:3}` so
    /// this arm stays gen-only (architecture fork (a)).
    Output(OutputError),
    Tx(TxError),

    /// A signer/crypto error from the `signer` crate (build/sign/run paths).
    /// Classification looks *through* the wrapped Context chain via
    /// [`SignerError::sentinel`]; see [`exit_code_for`].
    Signer(SignerError),

    /// A BLS operation failed outside the deposit pipeline (e.g. signer
    /// construction from a decrypted secret). Go leaves these unclassified —
    /// fallback exit code 1.
    Bls(BlsError),

    /// gen: no keystore matched a requested pubkey. Wraps
    /// `KeystoreError::KeystoreNotFound` with pubkey + dir context, mirroring
    /// gen.go's message. Exit code 2.
    KeystoreNotFoundFor {
        pubkey_hex: String,
        dir: String,
    },

    /// gen: BLS library initialisation failed (vestigial with blst, kept for
    /// parity). Exit code 3.
    BlsInit(String),

    /// gen: mainnet without the explicit acknowledgement flag (defense in
    /// depth inside the pipeline; the CLI gate fires first). Exit code 2.
    MainnetAckRequired,

    /// gen: --verify-with-deposit-cli binary not found in PATH. Exit code 2.
    DepositCliNotFound {
        cli_path: String,
        detail: String,
    },

    /// gen: the external staking-deposit-cli exited non-zero. Exit code 3.
    DepositCliFailed {
        output: String,
    },

    /// A derivation or post-write self-check failed (C1–C4). Carries no key material:
    /// check tag, index, HD or file path, and a secret-free detail only. Exit code 3.
    KeyVerifyFailed {
        check: &'static str, // "C1" | "C2" | "C3" | "C4"
        index: u32,
        /// HD path for C1–C3; written file path for C4 (V4-2 retention messaging).
        #[allow(dead_code)] // read by V4-2 C4 multi-line Display; stored now for C1–C3
        path: String,
        detail: String,
    },

    /// A context-message wrapper that preserves the source's classification
    /// (the port of `fmt.Errorf("...: %w", err)`).
    Context {
        msg: String,
        source: Box<AppError>,
    },

    /// Fallback internal error. Exit code 1.
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Exit { msg, .. } => f.write_str(msg),
            AppError::Input { what, source } => {
                write!(f, "{what}: invalid input: {source}")
            }
            AppError::Aborted(detail) if detail.is_empty() => f.write_str("user aborted"),
            AppError::Aborted(detail) => write!(f, "user aborted: {detail}"),
            AppError::Bip39(e) => e.fmt(f),
            AppError::Hd(e) => e.fmt(f),
            AppError::Bip32(e) => e.fmt(f),
            AppError::Keystore(e) => e.fmt(f),
            AppError::Deposit(e) => e.fmt(f),
            AppError::Network(e) => e.fmt(f),
            AppError::Output(e) => e.fmt(f),
            AppError::Tx(e) => e.fmt(f),
            AppError::Signer(e) => e.fmt(f),
            AppError::Bls(e) => e.fmt(f),
            AppError::KeystoreNotFoundFor { pubkey_hex, dir } => write!(
                f,
                "no keystore found for pubkey 0x{pubkey_hex} in {dir}: keystore not found for pubkey"
            ),
            AppError::BlsInit(detail) => write!(f, "bls init failed: {detail}"),
            AppError::MainnetAckRequired => f.write_str(
                "mainnet requires explicit acknowledgement (set Config.MainnetAck = true)",
            ),
            AppError::DepositCliNotFound { cli_path, detail } => write!(
                f,
                "deposit CLI binary not found: \"{cli_path}\" not found in PATH: {detail}"
            ),
            AppError::DepositCliFailed { output } => {
                write!(f, "deposit CLI verification failed: {output}")
            }
            AppError::KeyVerifyFailed {
                check,
                index,
                detail,
                ..
            } => write!(
                f,
                "keystore self-check failed for index {index} ({check}): {detail}"
            ),
            AppError::Context { msg, source } => write!(f, "{msg}: {source}"),
            AppError::Internal(msg) => f.write_str(msg),
        }
    }
}

impl From<Bip39Error> for AppError {
    fn from(e: Bip39Error) -> Self {
        AppError::Bip39(e)
    }
}
impl From<HdError> for AppError {
    fn from(e: HdError) -> Self {
        AppError::Hd(e)
    }
}
impl From<Bip32Error> for AppError {
    fn from(e: Bip32Error) -> Self {
        AppError::Bip32(e)
    }
}
impl From<KeystoreError> for AppError {
    fn from(e: KeystoreError) -> Self {
        AppError::Keystore(e)
    }
}
impl From<DepositError> for AppError {
    fn from(e: DepositError) -> Self {
        AppError::Deposit(e)
    }
}
impl From<NetworkError> for AppError {
    fn from(e: NetworkError) -> Self {
        AppError::Network(e)
    }
}
impl From<OutputError> for AppError {
    fn from(e: OutputError) -> Self {
        AppError::Output(e)
    }
}
impl From<TxError> for AppError {
    fn from(e: TxError) -> Self {
        AppError::Tx(e)
    }
}
impl From<SignerError> for AppError {
    fn from(e: SignerError) -> Self {
        AppError::Signer(e)
    }
}

impl AppError {
    /// The port of `ucli.Exit(msg, 2)`.
    pub fn exit2(msg: impl Into<String>) -> Self {
        AppError::Exit {
            msg: msg.into(),
            code: 2,
        }
    }

    /// The port of `WrapInputErr`.
    pub fn input(what: impl Into<String>, source: AppError) -> Self {
        AppError::Input {
            what: what.into(),
            source: Box::new(source),
        }
    }

    /// The port of `fmt.Errorf("{msg}: %w", source)` — adds context while
    /// preserving classification.
    pub fn context(msg: impl Into<String>, source: AppError) -> Self {
        AppError::Context {
            msg: msg.into(),
            source: Box::new(source),
        }
    }

    /// Walks context wrappers down to the classified error.
    fn unwrap_context(&self) -> &AppError {
        match self {
            AppError::Context { source, .. } => source.unwrap_context(),
            other => other,
        }
    }
}

/// Maps `err` to an exit code per the ethernal convention. The match arms
/// preserve the ORDER of checks in Go's `ExitCodeFor` — in particular the
/// user-abort check precedes the RPC block, so a SIGINT that surfaces through
/// an estimation call is classified as an abort (4), not an RPC failure (5).
pub fn exit_code_for(err: &AppError) -> i32 {
    match err.unwrap_context() {
        // Exit code 4: cancellation (SIGINT) or explicit abort — checked first.
        AppError::Aborted(_) => 4,
        AppError::Deposit(DepositError::Cancelled) => 4,
        AppError::Tx(TxError::Cancelled) => 4,

        // Explicit usage/validation exits carry their own code.
        AppError::Exit { code, .. } => *code,

        // Exit code 2: user / configuration errors (the WrapInputErr class).
        AppError::Input { .. } => 2,

        // Exit code 2: build-side RPC configuration errors (tx).
        AppError::Tx(TxError::ChainIdMismatch { .. }) => 2,
        AppError::Tx(TxError::MissingFromForNonce) => 2,

        // Exit code 2: user / configuration errors (gen + keygen bip39).
        AppError::Bip39(_) => 2,
        AppError::Keystore(e) => match e {
            // Decrypt wrong-passphrase and encrypt failure are crypto (3).
            KeystoreError::WrongPassphrase { .. } | KeystoreError::Encrypt { .. } => 3,
            // PassphraseTooShort / Mismatch / EnvVarEmpty / NoTty / malformed → 2.
            _ => 2,
        },
        AppError::KeystoreNotFoundFor { .. } => 2,
        AppError::Deposit(DepositError::PubkeyMismatch { .. }) => 2,
        AppError::MainnetAckRequired => 2,
        AppError::DepositCliNotFound { .. } => 2,
        AppError::Network(_) => 2,

        // Exit code 3: crypto / signer errors and external verification
        // failures (gen + keygen HD + account BIP-32). Keystore *write* stays
        // call-site Exit{3} so AppError::Output remains fallback 1 for gen
        // (architecture fork a).
        AppError::Hd(_) => 3,
        AppError::Bip32(_) => 3,
        AppError::Deposit(DepositError::SelfVerifyFailed { .. }) => 3,
        AppError::KeyVerifyFailed { .. } => 3,
        AppError::BlsInit(_) => 3,
        AppError::DepositCliFailed { .. } => 3,

        // Signer/crypto errors (build/sign/run). The order mirrors Go's
        // exit.go: user-rejected (a device decision) and cancellation classify
        // as user abort (4); every other signer sentinel is a crypto/signer
        // failure (3). Walk the Context chain via `.sentinel()` — the analogue
        // of Go's `errors.Is`. Cancelled is handled here rather than the exit-4
        // block above because a signer error never also wraps an RPC-estimation
        // tag, so there is no cancel-before-RPC ordering hazard.
        AppError::Signer(e) => match e.sentinel() {
            SignerError::UserRejected | SignerError::Cancelled => 4,
            SignerError::SignerClosed
            | SignerError::NoDevice
            | SignerError::AppNotOpen
            | SignerError::InvalidKey
            | SignerError::InvalidChainId
            | SignerError::ChainIdMismatch
            | SignerError::LedgerNotSupported => 3,
            // A plain `Msg` (Go `fmt.Errorf` without a sentinel) falls back to 1.
            _ => 1,
        },

        // Exit code 5: broadcast / RPC errors (tx).
        AppError::Tx(
            TxError::RpcDial { .. }
            | TxError::RpcEstimation { .. }
            | TxError::BroadcastFailed(_)
            | TxError::BroadcastChainIdMismatch { .. },
        ) => 5,

        // Remaining deposit/tx validation errors reach here only unwrapped
        // (Go wraps them via WrapInputErr at the call sites) — fallback.
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shorthand for `exit_code_for` over a constructed error.
    fn code(e: AppError) -> i32 {
        exit_code_for(&e)
    }

    // Go: TestExitCodeFor + TestExitCodeFor_GenErrorCodes.
    //
    // Divergence from Go's table: `exit_code_for` takes `&AppError`, so error
    // classification is split between the *construction* sites (which decide
    // whether to wrap) and this *map*. We therefore build only the variants the
    // production code actually produces. Notable adaptations:
    //   - `nil → 0`: NOT PORTED (unrepresentable — `main` only calls this on
    //     `Err`).
    //   - "SIGINT mid-estimation → 4": Go's error wraps BOTH `context.Canceled`
    //     and `ErrRPCEstimation`; the Rust builder checks cancellation *before*
    //     the estimation call, so the value produced is `Tx(Cancelled)` → 4.
    // End-to-end construction is pinned by the buildrpc/send/sign/run
    // integration tests.

    // --- exit 2: user / configuration (ErrInvalidInput class) ---
    #[test]
    fn input_wrap_is_exit2() {
        // Go: "ErrInvalidInput wrapped via WrapInputErr".
        assert_eq!(
            code(AppError::input("--flag", AppError::Internal("bad".into()))),
            2
        );
    }

    #[test]
    fn context_over_input_is_exit2() {
        // Go: "ErrInvalidInput wrapped via fmt.Errorf %w".
        let e = AppError::context(
            "wrap",
            AppError::input("--flag", AppError::Internal("bad".into())),
        );
        assert_eq!(code(e), 2);
    }

    #[test]
    fn ucli_exit_carries_its_code() {
        assert_eq!(code(AppError::exit2("bad input")), 2);
        assert_eq!(
            code(AppError::Exit {
                msg: "other".into(),
                code: 1
            }),
            1
        );
    }

    #[test]
    fn unknown_error_is_exit1() {
        assert_eq!(code(AppError::Internal("some unexpected error".into())), 1);
    }

    // --- exit 4: cancellation / user abort ---
    #[test]
    fn aborted_is_exit4() {
        // Go: context.Canceled / ErrUserAborted (direct + wrapped).
        assert_eq!(code(AppError::Aborted(String::new())), 4);
        assert_eq!(
            code(AppError::context(
                "outer",
                AppError::Aborted("sigint".into())
            )),
            4
        );
        assert_eq!(code(AppError::Deposit(DepositError::Cancelled)), 4);
    }

    #[test]
    fn tx_cancelled_wins_over_estimation() {
        // Go: "SIGINT mid-estimation → 4" — the Rust path yields Tx(Cancelled).
        assert_eq!(code(AppError::Tx(TxError::Cancelled)), 4);
    }

    // --- exit 3: signer / crypto ---
    #[test]
    fn signer_sentinels_are_exit3() {
        for e in [
            SignerError::SignerClosed,
            SignerError::NoDevice,
            SignerError::AppNotOpen,
            SignerError::InvalidKey,
            SignerError::InvalidChainId,
            SignerError::ChainIdMismatch,
            SignerError::LedgerNotSupported,
        ] {
            assert_eq!(code(AppError::Signer(e)), 3);
        }
    }

    #[test]
    fn signer_sentinel_wrapped_is_exit3() {
        let e = AppError::context("sign", AppError::Signer(SignerError::SignerClosed));
        assert_eq!(code(e), 3);
    }

    #[test]
    fn user_rejected_is_exit4() {
        assert_eq!(code(AppError::Signer(SignerError::UserRejected)), 4);
        assert_eq!(
            code(AppError::context(
                "ledger",
                AppError::Signer(SignerError::UserRejected)
            )),
            4
        );
    }

    // --- exit 5: broadcast / RPC ---
    #[test]
    fn tx_broadcast_and_rpc_are_exit5() {
        assert_eq!(
            code(AppError::Tx(TxError::RpcDial {
                url: "http://h".into(),
                source: "refused".into()
            })),
            5
        );
        assert_eq!(
            code(AppError::Tx(TxError::BroadcastFailed("node error".into()))),
            5
        );
        assert_eq!(
            code(AppError::Tx(TxError::BroadcastChainIdMismatch {
                signed: 17000,
                rpc: 1
            })),
            5
        );
        assert_eq!(
            code(AppError::Tx(TxError::RpcEstimation {
                call: "EstimateGas",
                source: "dial timeout".into()
            })),
            5
        );
    }

    #[test]
    fn tx_broadcast_failed_wrapped_is_exit5() {
        let e = AppError::context("rpc", AppError::Tx(TxError::BroadcastFailed("x".into())));
        assert_eq!(code(e), 5);
    }

    // --- exit 2: build-side RPC config (Go P1-5) ---
    #[test]
    fn build_side_rpc_config_is_exit2() {
        assert_eq!(
            code(AppError::Tx(TxError::ChainIdMismatch {
                rpc: 1,
                configured: 17000
            })),
            2
        );
        assert_eq!(code(AppError::Tx(TxError::MissingFromForNonce)), 2);
    }

    // --- keystore errors ---
    #[test]
    fn keystore_errors_are_exit2_except_wrong_passphrase() {
        assert_eq!(
            code(AppError::Keystore(KeystoreError::KeystoreMissing {
                path: "/k.json".into()
            })),
            2
        );
        assert_eq!(
            code(AppError::Keystore(KeystoreError::KeystoreMalformed {
                path: "/k.json".into(),
                detail: "x".into()
            })),
            2
        );
        assert_eq!(
            code(AppError::Keystore(KeystoreError::KeystoreVersion {
                path: "/k.json".into(),
                got: 3
            })),
            2
        );
        assert_eq!(
            code(AppError::Keystore(KeystoreError::EnvVarEmpty {
                var: "V".into()
            })),
            2
        );
        assert_eq!(code(AppError::Keystore(KeystoreError::KeystoreNotFound)), 2);
        // Go: keystore.ErrNoTTY (direct + wrapped through "passphrase source").
        assert_eq!(
            code(AppError::Keystore(KeystoreError::NoTty {
                detail: "no tty".into()
            })),
            2
        );
        assert_eq!(
            code(AppError::Keystore(KeystoreError::PassphraseSource(
                Box::new(KeystoreError::NoTty {
                    detail: "no tty".into()
                })
            ))),
            2
        );
        // WrongPassphrase is the exit-3 exception.
        assert_eq!(
            code(AppError::Keystore(KeystoreError::WrongPassphrase {
                detail: "bad checksum".into()
            })),
            3
        );
    }

    // --- gen slice: deposit + deposit-CLI + bls-init ---
    #[test]
    fn gen_error_codes() {
        assert_eq!(
            code(AppError::Deposit(DepositError::PubkeyMismatch {
                index: 0,
                pubkey_hex: "aa".into()
            })),
            2
        );
        assert_eq!(
            code(AppError::KeystoreNotFoundFor {
                pubkey_hex: "aa".into(),
                dir: "/d".into()
            }),
            2
        );
        assert_eq!(code(AppError::MainnetAckRequired), 2);
        assert_eq!(
            code(AppError::DepositCliNotFound {
                cli_path: "deposit".into(),
                detail: "x".into()
            }),
            2
        );
        assert_eq!(
            code(AppError::Deposit(DepositError::SelfVerifyFailed {
                index: 0,
                pubkey_hex: "aa".into()
            })),
            3
        );
        assert_eq!(
            code(AppError::DepositCliFailed {
                output: "boom".into()
            }),
            3
        );
        assert_eq!(code(AppError::BlsInit("herumi Init failed".into())), 3);
    }

    // Go: TestWrapInputErr — a WrapInputErr routes to exit 2.
    #[test]
    fn wrap_input_err_is_exit2() {
        let inner = AppError::Internal("bad hex value".into());
        assert_eq!(code(AppError::input("--max-fee-per-gas", inner)), 2);
    }

    // --- keygen exit map (K3-4 / F-9) ---

    #[test]
    fn bip39_is_exit2() {
        assert_eq!(code(AppError::Bip39(Bip39Error::Checksum)), 2);
        assert_eq!(code(AppError::Bip39(Bip39Error::UnknownWord(1))), 2);
        assert_eq!(code(AppError::Bip39(Bip39Error::WordCount(13))), 2);
        assert_eq!(code(AppError::Bip39(Bip39Error::PassphraseNotUtf8)), 2);
        assert_eq!(
            code(AppError::context(
                "wrap",
                AppError::Bip39(Bip39Error::Checksum)
            )),
            2
        );
    }

    #[test]
    fn hd_is_exit3() {
        assert_eq!(code(AppError::Hd(HdError::Master("too short".into()))), 3);
        assert_eq!(
            code(AppError::context(
                "derive",
                AppError::Hd(HdError::Master("x".into()))
            )),
            3
        );
    }

    #[test]
    fn bip32_is_exit3() {
        assert_eq!(
            code(AppError::Bip32(Bip32Error::Master(
                "I_L is zero or ≥ n".into()
            ))),
            3
        );
        assert_eq!(
            code(AppError::Bip32(Bip32Error::InvalidChildKey(0x8000_0000))),
            3
        );
        assert_eq!(
            code(AppError::context(
                "derive",
                AppError::Bip32(Bip32Error::Master("x".into()))
            )),
            3
        );
        // From impl classifies the same way.
        let e: AppError = Bip32Error::InvalidChildKey(0).into();
        assert_eq!(code(e), 3);
    }

    #[test]
    fn keystore_encrypt_is_exit3() {
        assert_eq!(
            code(AppError::Keystore(KeystoreError::Encrypt {
                detail: "kdf failed".into()
            })),
            3
        );
    }

    #[test]
    fn keystore_passphrase_short_is_exit2() {
        assert_eq!(
            code(AppError::Keystore(KeystoreError::PassphraseTooShort {
                min: 8,
                got: 7
            })),
            2
        );
        assert_eq!(
            code(AppError::Keystore(KeystoreError::PassphraseMismatch)),
            2
        );
    }

    #[test]
    fn output_error_stays_exit1_for_gen() {
        // Architecture: AppError::Output is gen's path → fallback 1.
        // Keystore writes must not use this variant (call-site Exit{3}).
        assert_eq!(code(AppError::Output(OutputError::AlreadyExists)), 1);
        assert_eq!(
            code(AppError::Output(OutputError::WriteTmp(
                std::io::Error::other("disk full")
            ))),
            1
        );
    }

    #[test]
    fn keystore_write_call_site_exit3() {
        // validator_cmd::map_write_err shape — not AppError::Output.
        assert_eq!(
            code(AppError::Exit {
                msg: "output: file already exists".into(),
                code: 3
            }),
            3
        );
    }

    #[test]
    fn ceremony_abort_and_sigint_are_exit4() {
        assert_eq!(
            code(AppError::Aborted(
                "mnemonic re-entry mismatch; no keystores written".into()
            )),
            4
        );
        assert_eq!(code(AppError::Aborted("interrupted".into())), 4);
    }

    // --- keygen self-check (V3-1 / PR-14, PR-16) ---

    #[test]
    fn key_verify_failed_is_exit3() {
        assert_eq!(
            code(AppError::KeyVerifyFailed {
                check: "C1",
                index: 0,
                path: "m/12381/3600/0/0/0".into(),
                detail: "pubkey mismatch".into(),
            }),
            3
        );
        assert_eq!(
            code(AppError::context(
                "derive",
                AppError::KeyVerifyFailed {
                    check: "C4",
                    index: 2,
                    path: "/tmp/keystore.json".into(),
                    detail: "decrypt round-trip failed".into(),
                }
            )),
            3
        );
    }

    #[test]
    fn key_verify_failed_display_has_check_and_index_no_secret() {
        let e = AppError::KeyVerifyFailed {
            check: "C2",
            index: 7,
            path: "m/12381/3600/7/0/0".into(),
            detail: "signature verify failed against derived pubkey".into(),
        };
        let AppError::KeyVerifyFailed {
            check,
            index,
            path,
            detail,
        } = &e
        else {
            panic!("expected KeyVerifyFailed");
        };
        assert_eq!(*check, "C2");
        assert_eq!(*index, 7);
        assert_eq!(path, "m/12381/3600/7/0/0");
        assert!(!detail.is_empty());

        let s = e.to_string();
        assert!(
            s.contains("C2") && s.contains("7"),
            "Display must include check tag and index: {s}"
        );
        assert!(
            s.contains("keystore self-check failed for index 7 (C2):"),
            "Display shape: {s}"
        );
        // PR-16: no secret-shaped material (no 64-hex-char run).
        let has_64_hex = s
            .as_bytes()
            .windows(64)
            .any(|w| w.iter().all(|b| b.is_ascii_hexdigit()));
        assert!(!has_64_hex, "Display must not contain a 64-hex run: {s}");
    }
}
