# Releasing Gloves Binaries

`gloves` publishes binaries and crate artifacts through GitHub Actions (`.github/workflows/publish.yml`).

This release pipeline is tag-driven.

## 1) Prerequisites

- Branch and channel policy:
  - Stable tags: `vX.Y.Z` from `main` or `release/*`
  - Beta tags: `vX.Y.Z-beta.N` from `next`
  - Alpha tags: `vX.Y.Z-alpha.N` from `canary`
- `Cargo.toml` version must match the tag version (without `v` prefix).
- Required workflows (`CI`, `Tests`, `Coverage`) must pass for the tagged commit.
- Repository secret `CARGO_REGISTRY_TOKEN` must be configured for crates.io publish job.

## 2) Local verification on release commit

Run on the exact commit you will tag:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo doc --no-deps
```

## 3) Tag and push

Stable example:

```bash
git checkout main
git pull --ff-only
git tag -a v0.5.0 -m "v0.5.0"
git push origin v0.5.0
```

Beta example:

```bash
git checkout next
git pull --ff-only
git tag -a v0.6.0-beta.1 -m "v0.6.0-beta.1"
git push origin v0.6.0-beta.1
```

## 4) Release outputs

The workflow uploads these assets to GitHub Releases:

- `gloves-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `gloves-<version>-x86_64-apple-darwin.tar.gz`
- `gloves-<version>-aarch64-apple-darwin.tar.gz`
- `gloves-<version>-x86_64-pc-windows-msvc.zip`
- `checksums.txt`

It also runs `cargo publish --locked` to publish to crates.io.

## 5) Post-release validation

- Confirm release notes and attached assets in GitHub Releases.
- Verify checksums from `checksums.txt`.
- Smoke-test one binary install path:

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash -s -- --release-ref vX.Y.Z
gloves --version
```
