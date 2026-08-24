# Apache-2.0 replaces GPL-3.0-only, except the Slint shell

**Status:** accepted, 2026-08-24

Closes #102. Amends [ADR 0003](0003-core-gui-split-slint-and-secret-display.md),
which made the whole project GPL because the GUI was GPL.

## Context

The Mac App Store cannot take a GPLv3 app. GPLv3 section 10 forbids imposing
further restrictions on the rights it grants, and the App Store terms impose
them. Section 3's anti-DRM provisions conflict too. Apple has removed GPL apps
over this.

ADR 0035 answered that by writing a second shell in SwiftUI, with no Slint in
it. That removed Slint from the macOS build. It did not remove the GPL, because
all six crates still declared `GPL-3.0-only` and the repository LICENSE was
GPLv3.

**The GPL was never forced on the core.** Resolving the full dependency closure
of `janitor-app` for both Apple targets returns 272 third-party packages. Every
one is permissive: MIT, Apache-2.0, ISC, BSD, Unicode-3.0, or Zlib. The only
copyleft package anywhere in it is `option-ext` at MPL-2.0, which is file-level
and carries no App Store conflict. Slint appears nowhere in the closure.

Slint reaches `janitor-gui` alone, and nothing depends on `janitor-gui`. It is a
leaf binary crate. The dependency arrow runs from the shell into the core, so
Slint's GPL cannot propagate the other way.

So ADR 0003 chose GPL for the whole project because the GUI happened to be GPL.
That was a policy decision, not a propagation, and it can be revisited without
touching Slint.

Relicensing is feasible. `git shortlog -sne --all` returns one human across 246
commits in three repositories, plus one bot commit that bumps a version number.
There is a single copyright holder. Nothing is published to crates.io, so no
registry version is frozen under the old terms.

## Decision

**The core relicenses to Apache-2.0.** All six workspace crates and the
excluded `uniffi-bindgen-swift` build tool declare `license = "Apache-2.0"`. The
repository LICENSE is the Apache-2.0 text with its appendix filled in as
`Copyright 2026 Circuit Stitch`.

**Apache-2.0 rather than MIT.** Janitor brokers IAM Identity Center credentials
and holds secret material, so the explicit patent grant in section 3 is worth
having. Section 6 withholds trademark rights, which keeps the Janitor and
Circuit Stitch names out of the grant while the code is free. Every `aws-sdk-*`
crate Janitor already depends on uses Apache-2.0.

**A fork may ship on the App Store.** That is the accepted cost of a permissive
license, and it was weighed against a source-available license that would
prevent it. Source-available was rejected: it is not open source, and it would
have removed the free-software statement from the README and the About panel.

**The Slint shell stays GPL-3.0-only.** `janitor-gui` cannot be built or used
without Slint under Slint's GPLv3 option, so `GPL-3.0-only` is the truthful
declaration for anyone consuming it or scanning it. Its Linux and Windows
binaries are conveyed under GPLv3. Apache-2.0 is one-way compatible with GPLv3,
so Apache-2.0 core crates combine into that shell unchanged.

**No NOTICE file.** Apache-2.0 section 4(d) obliges downstream consumers to
propagate a NOTICE file if one exists. None of the 272 dependencies ships one,
and adding one here would create that obligation for everyone downstream for no
benefit. The copyright sits in LICENSE instead.

**No per-file license headers.** The `license` field in each manifest and the
repository LICENSE carry the declaration. Every source file in this repository
opens with a narrative header comment explaining what the file does, and legal
boilerplate above those would displace the thing a reader came for.

**Third-party notices ship with the binary.** `scripts/third-party-licenses.py`
resolves the closure from `Cargo.lock` and writes `THIRD-PARTY-LICENSES.txt`.
The publish workflow runs it beside `build-xcframework.sh` and uploads the
result next to the zip, under the same immutable key scheme, so the list is
frozen with the bytes it describes. The macOS shell compiles no Rust and cannot
generate this for itself.

## Considered options

- **MIT.** Shorter and universally compatible. Rejected: no patent grant and no
  trademark clause, both of which matter for a credential broker.
- **MPL-2.0.** Weak copyleft, App Store compatible, keeps a share-alike spirit.
  Rejected: it constrains forks without protecting anything Janitor needs
  protected, and file-level copyleft is harder for a consumer to reason about
  than a permissive grant.
- **Source-available (BUSL, PolyForm, Elastic).** Would keep App Store
  distribution exclusive. Rejected: not open source.
- **Relicense `janitor-gui` too and switch Slint to its Royalty-Free option.**
  Would leave no GPL anywhere. Rejected: it reverses ADR 0003 rather than
  amending it, Royalty-Free 2.0 carries its own conditions, and the Slint shell
  has no attribution surface to satisfy them on.

## Consequences

- **Relicensing is prospective.** The v0.1.4 release binaries and every commit
  before this one remain available under GPLv3. Nobody can be made to give that
  grant back, and nobody needs to.
- **A fork can ship a competing App Store build.** Accepted above.
- **The repository is uniformly Apache-2.0.** `janitor-gui` left in #106, so no
  carve-out is needed here. The exception lives in `Janitor-slint`.
- **`Janitor-macos` follows.** It relicenses to Apache-2.0 in the same pass and
  gains the About and Acknowledgments windows that display the generated notice
  file.
- **The attribution gap closes.** 55 MIT-only packages and 157 dual-licensed
  ones ship inside `JanitorKit.xcframework`, and MIT asks that its copyright
  notice travel with the software. Janitor shipped none of them under GPLv3
  either, which had the same requirement. The generated file is the fix.
- **`cargo deny` and license scanners change verdict.** Anything gating on
  GPL-3.0-only in a downstream consumer now sees Apache-2.0.
