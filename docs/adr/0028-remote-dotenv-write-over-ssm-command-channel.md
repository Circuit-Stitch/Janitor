# Remote `.env` write over the SSM command channel (non-stomp, base64-over-stdin)

**Status:** accepted (design); **not yet implemented** — this is the handoff design
for the write slice (proposed issue **B5**). The read half it builds on is live-verified
([ADR 0025 Live verification](0025-remote-dotenv-over-ssm-provider.md#live-verification-2026-06-07--milestone-b-done)).

**Related:** [ADR 0025](0025-remote-dotenv-over-ssm-provider.md) (the remote-`.env`
Provider + the MGS transport this extends), [ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md)
(the op-based, replay-on-fresh, compare-and-swap write engine — the invariant this
must honour), [ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md) (read-only by
default; mutating calls unreachable until the user unlocks read-write mode),
[ADR 0002](0002-identity-center-only-memory-only-auth.md) (Identity Center only, no
static keys), [THREAT-MODEL.md](../THREAT-MODEL.md).

## Context

The read path (ADR 0025) runs a one-shot command over the Session Manager MGS data
channel and streams the file back. The next job (the reason Janitor exists — ADR 0001)
is **safe mutation**: change a few Entries in a remote `.env` without ever stomping the
whole file. The question this ADR settles: **what transport carries the write**, given
the live-verified read already works over the command channel.

The trigger was a direct challenge during read bring-up: *"this [command channel] is the
wrong approach — does SSM allow SCP, because eventually we want to write too?"* It does,
and the alternatives were weighed before committing.

## Decision

**Keep the read+write `.env` provider on the MGS command channel** (not SFTP/SCP over an
SSM SSH tunnel). Writes stream the new file content as **base64 over stdin** into a
single `sudo` shell command that does a **hash-guarded, atomic replace**, gated behind
read-write mode.

### Why not SFTP/SCP-over-SSM

SSM *can* do SCP/SFTP, via the `AWS-StartSSHSession` document tunnelling SSH over the
same `wss` data channel we already built. It was rejected for this provider because:

1. **SFTP runs as the SSH login user and cannot `sudo`.** The motivating files are
   root-owned `600` (e.g. `/opt/deferno/.env`). SFTP as `ec2-user` can neither read nor
   write them, and SFTP has no elevation — you'd need root SSH login (usually disabled)
   or to change file ownership. The command channel works *because* it can `sudo`.
2. **It needs `sshd` + an auth path.** The keyless option fitting ADR 0002 is EC2
   Instance Connect (ephemeral in-memory keypair, pushed via the EC2 API for 60 s), but
   that targets the non-root user — looping back to (1) — and adds a large surface (an
   SSH client + SFTP client + EC2IC) for no gain over the command channel.
3. **The MGS transport is reused either way** — SSH-over-SSM rides the same data
   channel — so staying on the command channel discards nothing.

A raw `cat`/`tee` was also rejected for framing (the session's `sudo`/PAM/PTY layer
folds banner bytes into the stream — ADR 0025); **base64** both directions is the fix.

### The write command (shape)

The new content is generated in memory (apply the user's per-Entry ops to the freshly
read Set), base64-encoded, and streamed over **stdin** — never on the command line
(argv lands in CloudTrail / SSM session history; the hash does not). One command does
the compare-and-swap atomically:

```sh
sudo -n sh -c '
  cur=$(sha256sum -- PATH | cut -d" " -f1)
  [ "$cur" = EXPECTED ] || { echo JANITOR_CONFLICT; exit 3; }
  t=$(mktemp) || exit 1
  base64 -d > "$t" || exit 1
  chown --reference=PATH "$t" && chmod --reference=PATH "$t" || exit 1
  mv -f "$t" PATH && echo JANITOR_OK
'
```

- **`sha256sum` guard = the ADR 0001 compare-and-swap.** `EXPECTED` is the hash of the
  file *as read*; if it changed since, abort (`JANITOR_CONFLICT`) and re-read — never
  blind-write. The hash is not secret.
- **`mktemp` + `--reference` + `mv -f` = atomic replace** preserving owner/mode (`600`).
  `mv` within a filesystem is atomic, so a reader never sees a partial file.
- **Only `JANITOR_OK` / `JANITOR_CONFLICT` / a non-zero exit** come back — small,
  non-secret status tokens parsed to a typed result.

### The one genuinely new capability: stdin streaming over MGS

The current driver (`mgs::protocol`) only *sends* acks + the handshake response. A write
must **stream stdin** to the remote: send the base64 content as `input_stream_data`
frames (chunked, sequenced, each acked by the agent), then **signal EOF** so `base64 -d`
finishes. EOF signalling over MGS is the open research item (candidates: a `FIN`-flagged
final `input_stream_data`, or relying on session/command teardown). This is the part to
TDD carefully against the existing `FakeChannel` before any live run.

### Gating (ADR 0004)

The write path is built but **unreachable until the user deliberately switches into
(lockable) read-write mode**. v1 ships read-only. No mutating SSM call is reachable from
the default UI.

## What stays pure / tested vs. shell

Following ADR 0025's discipline — keep the gate green with the untestable socket as the
only uncovered shell:

- **Pure + unit-tested:** the write-command builder (quoting, the `sha256sum` guard, the
  `--reference` atomic-replace script), base64 *encode* of the new content, the
  `JANITOR_OK`/`JANITOR_CONFLICT`/exit-code → typed-result parser, and the op-apply →
  new-content step (likely already in `core` per ADR 0001).
- **New protocol logic (pure, fake-channel tested):** chunking content into
  `input_stream_data` frames, sequencing, ack handling, EOF.
- **Untested shell:** only the live `wss` socket (unchanged from ADR 0025).

## Threat-model notes

- New content rides **stdin over the encrypted data channel**, never argv/logs/disk on
  the Janitor side; held in zeroizing buffers until sent (THREAT-MODEL / ADR 0008).
- The remote temp file inherits the target's `600`/owner via `--reference` **before**
  `mv`, so the plaintext is never world-readable on the box mid-write. (The remote box
  already stores the `.env` in plaintext; Janitor does not worsen that, and the
  session-logging advisory from ADR 0025 still warns if the write would be archived.)
- The CAS guard makes a write **fail closed** on any concurrent change — never a silent
  stomp (ADR 0001).

## Open questions for the implementer (B5)

1. **MGS stdin EOF** — how does the agent see end-of-stdin so `base64 -d` completes?
   Confirm against `amazon-ssm-agent` / `session-manager-plugin` and TDD it.
2. **`--reference` portability** — GNU coreutils has `chown/chmod --reference`; confirm
   on the target AMIs, else fall back to capturing `stat` and re-applying explicitly.
3. **Result surfacing** — map `JANITOR_CONFLICT` to a re-read-and-retry (ADR 0001
   replay-on-fresh) and a clear UI signal; map other non-zero to a masked failure.
4. **Read-write mode UX** — where the lockable unlock lives in the GUI (ADR 0004/0013).
