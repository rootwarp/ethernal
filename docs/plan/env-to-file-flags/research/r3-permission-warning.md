# R3 — What makes the FR-17 permission warning good

**OD-4 is resolved: warn and continue. This page does not reopen it.** It gathers only what makes
the *warning* itself correct — the check OpenSSH actually performs, its wording, and the token
FR-21 needs.

---

## 1. What OpenSSH actually checks

`sshkey_perm_ok`, `authfile.c:82-107` (openssh-portable master, `7e446d3f5917…`):

```c
	if (fstat(fd, &st) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	...
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return SSH_ERR_KEY_BAD_PERMISSIONS;
	}
```

Four things worth taking, one worth leaving:

| Element | Take? |
|---|---|
| Mask `st_mode & 077` | **Yes** — identical to FR-17. |
| `fstat(fd)`, not `stat(path)` | **Yes** — the mode checked belongs to the same inode as the bytes read. In Rust: `File::open` then `File::metadata`. Also gives symlink-following for free (FR-15). See [`r2`](r2-file-reading-policy.md) §2. |
| Message names **path** and **octal mode**, never contents | **Yes** — FR-17 already requires both; the octal is what makes the remedy obvious. |
| States the remedy / consequence in the same breath | **Yes.** |
| `st.st_uid == getuid()` guard — skip the check for files owned by someone else | **No, with a stated cost.** It would need `libc::geteuid()`; `libc` is a dependency of the **bin** crate only (`bins/ethernal/Cargo.toml:26`), while `FileSource` lives in `ethernal-keystore` (FR-26), so adopting it means a new dependency edge against M-4. The cost of omitting it: Docker Swarm secrets (`/run/secrets/*`, mode 0444) and Kubernetes projected secrets (mode 0644, [`r2`](r2-file-reading-policy.md) §2) are typically root-owned and **will** warn. That is not a false positive — those files really are world-readable — but it is a warning the operator cannot act on. Acceptable for warn-and-continue; it would not have been acceptable for reject. |
| The 3-line `@@@@` banner | **No.** Three lines, and FR-17 specifies exactly one. |

## 2. The repo's own convention

Three `WARNING:` emitters exist today, all single-line, all `WARNING: <subject> — <what will
happen>`:

| Message | Site |
|---|---|
| `WARNING: output directory "<path>" is a symlink; keystores will be written to "<real>".` | `fs_util.rs:60-65` |
| `WARNING: --no-verify — keystores will not be decrypted back after writing.` | `validator_cmd.rs:509` |
| `WARNING: could not clear the terminal automatically…` | asserted at `validator_cmd.rs:1119` |

Conventions to match: one line to stderr, `WARNING:` prefix, path in double quotes, the
consequence stated rather than implied, no secret material.

## 3. Recommended message

```
WARNING: file permissions 0644 for "<path>" are too open; the secret is readable by group or other. Fix with: chmod 600 "<path>"
```

- `0%3.3o` of `mode & 0o777`, matching OpenSSH's rendering, so an operator who has seen the ssh
  warning recognises this one.
- Names the path (FR-17), never the contents (M-3, FR-31).
- Ends with the remedy — the one thing OpenSSH's message lacks and every user has to look up.
- Emitted **only for regular files** ([`r2`](r2-file-reading-policy.md) §4, finding 3: the
  recommended `<(...)` pipe is mode 0440 and would otherwise warn on every run).

## 4. The token FR-21 needs

All three exactly-one-`WARNING` assertions filter on the bare substring `"WARNING"`
(`validator_cli.rs:543`, `validator_e2e.rs:495`, `validator_e2e.rs:526`), and the repo already has
three distinct warning kinds — so these assertions are fragile today and a fourth kind breaks
them. FR-21 says to make them kind-specific rather than loosen them to "at least one".

**Stable token: `file permissions`.** It appears in no other message, is not a flag name (so it
survives a future flag rename), and is not a path (so it is host-independent). Recommended shared
test helper, mirroring the existing filter shape:

```rust
fn warnings_of_kind<'a>(text: &'a str, kind: &str) -> Vec<&'a str> {
    text.lines().filter(|l| l.contains("WARNING") && l.contains(kind)).collect()
}
```

Kinds in use: `"is a symlink"`, `"--no-verify"`, `"could not clear the terminal"`, and the new
`"file permissions"`. Each of the three assertions becomes `warnings_of_kind(…, "<its kind>")`
with the same `assert_eq!(…, 1)`, which is strictly stronger than what they assert today.

## 5. Sources

| Source | Reference |
|---|---|
| OpenSSH (master, `7e446d3f5917c2f2770981a89d0e54d5d064bf0c`) | [`authfile.c#L82-L107`](https://github.com/openssh/openssh-portable/blob/7e446d3f5917c2f2770981a89d0e54d5d064bf0c/authfile.c#L82-L107) |
| Docker Swarm secrets (mode `-r--r--r--`) | <https://docs.docker.com/engine/swarm/secrets/> |
| Kubernetes `SecretVolumeSourceDefaultMode = 0644` | [`api/core/v1/types.go#L1572-L1574`](https://github.com/kubernetes/kubernetes/blob/0f317be40dfb054367e4f126845c91ffdd22cdb8/staging/src/k8s.io/api/core/v1/types.go#L1572-L1574) |

**Connections:** [`r2-file-reading-policy.md`](r2-file-reading-policy.md) · [`index.md`](index.md) ·
PRD FR-17, FR-21, OD-4
