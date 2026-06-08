# Remote `.env` write via an interactive (pty) session + data-channel content stream

**Status:** accepted (design); **supersedes the *transport* decision of**
[ADR 0028](0028-remote-dotenv-write-over-ssm-command-channel.md). This is the
implemented design for the write slice (issue **B5 / #70**). The read half it
builds on is live-verified
([ADR 0025](0025-remote-dotenv-over-ssm-provider.md#live-verification-2026-06-07--milestone-b-done)).

**Related:** [ADR 0028](0028-remote-dotenv-write-over-ssm-command-channel.md) (the
write *semantics* this keeps — base64, the `sha256` CAS guard, the atomic
`mktemp`/`--reference`/`mv` replace, the `JANITOR_OK`/`JANITOR_CONFLICT` tokens,
read-write-mode gating — and the SFTP/SCP rejection, all still in force),
[ADR 0025](0025-remote-dotenv-over-ssm-provider.md) (the remote-`.env` Provider +
the MGS transport this extends), [ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md)
(op-based, replay-on-fresh, compare-and-swap — the invariant this honours),
[ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md) (read-only by default),
[THREAT-MODEL.md](../THREAT-MODEL.md).

## Context

ADR 0028 settled the write *semantics* (a `sha256`-guarded, atomic replace) and
chose to carry the new file content as **base64 over stdin** into a single `sudo`
command run by the **`AWS-StartNonInteractiveCommand`** document — the same
document the live-verified read uses. ADR 0028 flagged one open research item:
*"how does the agent see end-of-stdin so `base64 -d` completes?"*

Researching that against the canonical `amazon-ssm-agent` source turned up a
**deeper, fatal fact**: `AWS-StartNonInteractiveCommand` does **not connect a
stdin to the executed command at all.**

- `agent/session/shell/shell_unix.go` `StartCommandExecutor` runs the
  non-interactive command with `os/exec` and **explicitly sets `plugin.stdin =
  nil`** (no pty, no `StdinPipe`); only the interactive/pty branch sets
  `plugin.stdin = ptyFile`. A Go `exec.Cmd` with a nil `Stdin` gives the child
  `/dev/null`, so a `base64 -d` reading stdin would hit EOF immediately and write
  an empty file.
- Worse, the shell plugin's `InputStreamMessageHandler`, when the plugin is
  non-interactive, **never writes incoming `input_stream_data` to stdin**: it
  scans each byte only for a control signal (`Ctrl-C`→SIGINT, `Ctrl-\`→SIGQUIT;
  `appconfig.ByteControlSignalsLinux`) and otherwise **discards the bytes** and
  returns. `Ctrl-D` (0x04) is not even a recognized control byte.

So ADR 0028's transport ("base64 over the non-interactive command's stdin") is
**mechanically impossible**: the agent throws our content away. The open question
"how does the agent see end-of-stdin" resolves to "the agent never delivers your
stdin to that command."

## Decision

**Carry the write over an *interactive* (pty-backed) Session Manager command,
streaming the new file content as `input_stream_data` over the MGS data channel,
and make the remote read self-terminating with a length prefix instead of relying
on tty EOF.** Keep every ADR 0028 *semantic* (base64, the `sha256` CAS guard, the
atomic `--reference`/`mv` replace, the small status tokens, read-write gating).

### Why interactive, and why not "put the base64 in the command body"

The obvious shortcut — keep `AWS-StartNonInteractiveCommand` and embed the base64
*inside* the `sh -c` command string (`printf %s '<b64>' | base64 -d | sudo tee
…`) — was **rejected**: the command travels in the `StartSession` **`Parameters`
map, which CloudTrail logs in plaintext** (only `responseElements.tokenValue` is
redacted; request `Parameters` are not). That would copy the new secret file
content straight into CloudTrail — exactly the leak ADR 0028 chose stdin to
avoid (THREAT-MODEL: nothing secret on argv/logs).

The **interactive** documents (`AWS-StartInteractiveCommand`, sessionType
`InteractiveCommands`) run the command under a **pty**, so the agent's
`InputStreamMessageHandler` **does** write client `input_stream_data` (PayloadType
`Output`) to the command's stdin. The streamed content rides the **encrypted
`wss` data channel**, which is *not* a CloudTrail field — it is captured only if
the org enables session logging to S3/CloudWatch, which is precisely the residual
risk ADR 0025 already detects and warns on (`session_logging_advisory` /
`take_advisories`). So the interactive route is the only one that keeps content
off CloudTrail; it adds **no** new logging surface beyond the read's.

### The write command (shape)

The `command` parameter (a non-secret *template* — it is logged) tames the pty
line discipline first, then runs the CAS-guarded atomic replace reading exactly
`N` bytes of base64 from stdin:

```sh
stty raw -echo -isig 2>/dev/null; sudo -n sh -c '
  cur=$(sha256sum < PATH | cut -d" " -f1)            # stdin: emits "<hash>  -", no filename to escape
  [ "$cur" = EXPECTED ] || { printf "\nJANITOR""_CONFLICT\n"; exit 3; }
  t=$(mktemp -- "$(dirname -- PATH)/.janitor.XXXXXX") || exit 1   # co-located → atomic mv
  trap "rm -f \"$t\"" EXIT                           # remove the temp on any failure
  head -c N | base64 -d > "$t" || exit 1
  { chown --reference=PATH "$t" || chown "$(stat -c %u:%g PATH)" "$t"; } &&
  { chmod --reference=PATH "$t" || chmod "$(stat -c %a PATH)" "$t"; } || exit 1
  mv -f "$t" PATH && printf "\nJANITOR""_OK\n"
'
```

(The status tokens are written *split* in the command source — `JANITOR""_OK` —
so the command body never contains the contiguous token the client scans for;
`printf` concatenates the pieces at runtime. Defense-in-depth against the command
text ever folding into stdout.)

- **`stty raw -echo -isig`** silences the pty line discipline so the base64
  stream passes through verbatim (no echo back into the output, no CR/LF cooking,
  no `MAX_CANON` 4 KB canonical-line limit, no ISIG). base64's alphabet
  (`A–Za–z0–9+/=`) already carries no control bytes, so even residual mangling is
  low-risk — and we still noise-filter + strictly decode the few status bytes we
  read back.
- **`head -c N`** reads *exactly* `N` bytes (`N` = the base64 length, **not
  secret**, passed in the template) and then closes the pipe, so `base64 -d` sees
  EOF deterministically. **This sidesteps tty-EOF entirely** — we never depend on
  `Ctrl-D`/`VEOF` (fragile and mode-dependent). A `FLAG_FIN` on the last input
  frame is sent as a courtesy, but completion does not rely on it.
- **`sha256sum < PATH` guard = the ADR 0001 compare-and-swap.** `EXPECTED` is the
  hex digest of the file *as read*; if it changed since, abort `JANITOR_CONFLICT`
  and re-read — never blind-write. The hash is not secret. **Reading the file on
  stdin (`< PATH`), not as an argument (`-- PATH`)**, is deliberate: GNU `sha256sum`
  *escapes* a filename containing a backslash or newline (prepending a `\` to the
  output line), which `cut` would fold into the "hash" — so an argument form would
  make the CAS never match (a permanent false conflict) for such paths. Stdin emits
  `<hash>  -` (no filename), clean for any path; the redirect is local to the
  command-substitution subshell, so it does not consume the pty stdin the later
  `head -c N` reads.
- **`mktemp` *in the target's directory* + `--reference` (with a `stat` fallback) +
  `mv -f` = atomic replace** preserving owner/mode (`600`). The temp **must be
  co-located with the target** (`mktemp -- "$(dirname PATH)/.janitor.XXXXXX"`): a
  default `mktemp` lands in `/tmp`, often a separate filesystem (tmpfs), which makes
  `mv` a non-atomic copy-then-unlink — a reader could then see a partial file.
  Same-directory keeps `mv` a same-filesystem atomic `rename(2)`. A `trap … EXIT`
  removes the temp on any failure (after a successful `mv` it is already renamed
  away, so the `rm` is a no-op). The `stat -c` fallback covers an image whose
  coreutils lacks `--reference` (ADR 0028 open item #2).
- **`sudo -n` only, no non-sudo fallback.** Unlike the read (whose `sudo || cat`
  fallback re-runs a *stdin-free* command), the write's stdin is consumed once —
  a `||` fallback could not re-read it. The motivating files are root-owned `600`,
  so v1 write requires passwordless `sudo` (already true on the live box).
- Only `JANITOR_OK` / `JANITOR_CONFLICT` come back as small, non-secret tokens,
  parsed to a typed result; their leading `\n` separates them from any pty banner.

### The one genuinely new capability: streaming `input_stream_data` over MGS

The read driver only *sends* acks + the handshake response. The write driver
adds a **`WriteSession`** state machine that, after `handshake_complete`, emits
the base64 content as a sequence of `input_stream_data` / `Output` frames
(chunked, sequenced continuing from the handshake response's seq 0, `FLAG_FIN` on
the last), keeps acking the agent's output frames, accumulates stdout, and parses
the `JANITOR_OK`/`JANITOR_CONFLICT` token at the clean `channel_closed`
completion. Like the read, this is **pure, fake-channel-tested** logic; only the
`wss` socket stays untested. (The agent runs a reliable, ACKed, retransmitting
in-order stream; since the underlying WebSocket is TCP/TLS-reliable, the v1 write
driver streams without client-side retransmit — the live `wss` shell is the place
that would grow it if a real run shows loss, mirroring the read's bring-up.)

### Result surfacing (ADR 0001 replay-on-fresh)

`JANITOR_CONFLICT` (the file changed since read) maps to **re-read → re-apply the
ops onto the fresh file → re-write**, bounded by a small retry cap; exhausting it
returns a typed `Conflict` for the caller (and, once wired, a clear UI signal).
Re-applying the surgical ops onto fresh text preserves a teammate's concurrent
changes to *other* keys (the textual `apply_edits` only rewrites the edited keys'
lines). Per-key conflict-stop (ADR 0001's "an op targets an Entry that changed →
stop for human re-review") needs the human-facing GUI and is deferred with the
read-write-mode unlock UX. Any other non-`OK`/`CONFLICT` close is a masked
failure.

### Gating (ADR 0004)

Built but **unreachable until the user deliberately switches into (lockable)
read-write mode**. This slice lands the engine + transport + a human-gated
`live-verify-ssm-write` binary; it adds **no** write method to the `Provider`
port and no GUI path. v1 ships read-only.

## What stays pure / tested vs. shell

- **Pure + unit-tested:** the write-command builder (`stty`, the `sha256` guard,
  the length-prefixed `head -c N`, the `--reference`/`stat` atomic-replace
  script, quoting); base64 *encode*; the `JANITOR_OK`/`JANITOR_CONFLICT` →
  typed-result parser; the SHA-256 hex of the read file; the op-apply →
  new-content step (`dotenv_edit::apply_edits`, ADR 0001).
- **New protocol logic (pure, fake-channel tested):** `WriteSession` — chunking
  content into `input_stream_data` frames, sequencing, ack handling, `FLAG_FIN`,
  and the completion/parse.
- **Untested shell:** only the live `wss` socket + the `StartSession`
  (interactive document) glue (the `StartSession` SDK call itself is
  replay-tested, ADR 0027).

## Threat-model notes

- New content rides **`input_stream_data` over the encrypted data channel**, never
  argv/`Parameters`/CloudTrail/logs/disk on the Janitor side; held in zeroizing
  buffers (the new file text and its base64) until sent (THREAT-MODEL / ADR 0008).
- The non-secret template (`stty …; sudo -n sh -c '…head -c N…'` with `PATH`,
  `EXPECTED`, `N`) is all that lands in the logged `Parameters` map — no Value,
  no hash-of-anything-secret beyond the public file digest.
- The remote temp file inherits the target's `600`/owner via `--reference`
  **before** `mv`, so plaintext is never world-readable mid-write.
- The CAS guard makes a write **fail closed** on any concurrent change — never a
  silent stomp (ADR 0001).
- Session logging is the only new exposure (data-channel content archived to
  S3/CloudWatch if the org enabled it); the ADR 0025 advisory already warns.

## IAM

Add `arn:aws:ssm:*::document/AWS-StartInteractiveCommand` to the `ssm:StartSession`
resource list (the read needed only `AWS-StartNonInteractiveCommand`). See
[docs/iam_setup.md](../iam_setup.md).

## Open questions for live verification (mirrors the read's bring-up)

1. **pty readiness race** — we begin streaming after `handshake_complete`; confirm
   the remote `stty raw -echo` has taken effect before our bytes reach `head`
   (the input queue should buffer them; in raw mode without echo this is benign).
   If a real run shows echoed/cooked bytes, add a one-byte readiness handshake.
2. **`head -c N` vs base64 length** — confirm `N` equals the streamed byte count
   exactly (no pty byte translation in raw mode) so `base64 -d` gets the whole
   payload and nothing extra.
3. **`--reference` portability** — confirm on the target AMI; the `stat -c`
   fallback covers its absence.
4. **`JANITOR_CONFLICT` round-trip** — force a concurrent change between read and
   write and confirm the typed `Conflict` + re-read/retry path.
5. **session logging / KMS** — unchanged from ADR 0025 (advisory fires; a
   KMS-encrypted session fails masked).
