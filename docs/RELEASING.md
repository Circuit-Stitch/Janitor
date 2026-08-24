# Releasing

This repository publishes one artifact: **`JanitorKit.xcframework`**, the macOS
slice of `janitor-app` with the UniFFI-generated Swift compiled into it
(ADR 0035). The tag-triggered [`publish.yml`](../.github/workflows/publish.yml)
workflow builds it and puts it on the depot.

The desktop packages — rpm, deb, AppImage, dmg, and the signed Windows MSIX — are
released from
[`Circuit-Stitch/Janitor-slint`](https://github.com/Circuit-Stitch/Janitor-slint),
which holds the Slint shell and its own `docs/RELEASING.md` (ADR 0036, #106).

## Two tag lanes, one repository each

| Tag | Repository | Versions | Produces |
| --- | --- | --- | --- |
| `kit-vX.Y.Z` | this one | `janitor-app` | `JanitorKit.xcframework.zip` on the depot |
| `vX.Y.Z` | `Janitor-slint` | `janitor-gui` | the desktop packages, on a draft GitHub Release |

They are separate because they version different things. A shared tag would
republish one every time the other moved.

## Publishing JanitorKit

1. Bump `version` in [`janitor-app/Cargo.toml`](../janitor-app/Cargo.toml) and
   merge it to `main`. The tag must equal it — the `version` job fails the run
   otherwise, because the tag decides the URL and the manifest decides what the
   framework's `Info.plist` says it is.
2. Tag and push:
   ```bash
   git tag kit-v0.2.0
   git push origin kit-v0.2.0
   ```
3. Read the checksum out of the run's job summary and put it, with the URL, into
   `JanitorKit/Package.swift` in
   [`Circuit-Stitch/Janitor-macos`](https://github.com/Circuit-Stitch/Janitor-macos).

**A version publishes once.** Every write goes out with `If-None-Match: *`, so S3
refuses the call when the key is taken. A Rust change that the Mac shell needs
requires a new `kit-vX.Y.Z` and a checksum bump — there is no republishing over
the old one.

## What the run does

| Job | What it proves |
| --- | --- |
| `version` | The tag and `janitor-app`'s manifest agree |
| `apple` | The framework builds on a macOS runner, publishes under `open/swift/janitor/<version>/`, and the Maven grant still stops at this artifact |
| `fetched` | The zip downloads over `depot.circuitstitch.com` with no credentials, its checksum matches, and the slice carries the library, both `.swiftinterface` files, and the C header |

The depot's own `publish-dummy.yml` proves the rest of the boundary once: a
version cannot be published twice, a publisher cannot write outside its prefix,
and a publisher cannot read or list.

## Credentials

There are none to rotate. The `apple` job asks GitHub for an OIDC token and
trades it for the `depot-publisher-janitor` role. No AWS key is stored anywhere.

The role, its prefix (`open/swift/janitor`), and the bucket are committed
literals in the workflow's `env` block, matching the depot's no-tfvars
convention. A workflow cannot read Terraform state, so they are duplicated from
it. Run `tofu output` in the depot's `serve/` to check they still agree.

## Building it locally

```bash
rustup target add x86_64-apple-darwin      # aarch64-apple-darwin comes with the Mac
./scripts/build-xcframework.sh
```

The script builds both Darwin slices, assembles the framework, verifies the
emitted interfaces, and then links and runs a consumer against the finished
slice. A stale autolink list in the modulemap fails there rather than in
somebody's app. Full build and test commands are in
[docs/building.md](building.md).
