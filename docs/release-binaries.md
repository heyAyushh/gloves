# Releasing Gloves Binaries

Back to docs map: [Documentation Index](INDEX.md)

`gloves` publishes binaries and crate artifacts through GitHub Actions (`.github/workflows/publish.yml`).

## 1) Prerequisites

- branch/channel policy:
  - stable tags: `vX.Y.Z` from `main` or `release/*`
  - beta tags: `vX.Y.Z-beta.N` from `next`
  - alpha tags: `vX.Y.Z-alpha.N` from `canary`
- `Cargo.toml` version must match tag version (without `v`)
- required workflows (`CI`, `Tests`, `Coverage`) must pass
- `CARGO_REGISTRY_TOKEN` must be configured with crates.io publish rights for
  `gloves-core`, `gloves-config`, and `gloves`

## 2) Local verification

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo doc --no-deps
cargo publish --dry-run --locked
```

For a fresh version, also validate the publish chain directly:

```bash
cargo publish -p gloves-core --dry-run --locked
cargo package -p gloves-config --list
cargo package -p gloves --list
```

## 3) Tag and push

Stable example:

```bash
git checkout main
git pull --ff-only
git tag -a v0.5.0 -m "v0.5.0"
git push origin v0.5.0
```

## 4) Release outputs

- crates.io publishes in dependency order:
  - `gloves-core`
  - `gloves-config`
  - `gloves`
- `gloves-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `gloves-<version>-x86_64-apple-darwin.tar.gz`
- `gloves-<version>-aarch64-apple-darwin.tar.gz`
- `gloves-<version>-x86_64-pc-windows-msvc.zip`
- `checksums.txt`

## 5) Post-release validation

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash -s -- --release-ref vX.Y.Z
gloves --version
```

## 6) Troubleshooting

If the `Publish to crates.io` job fails with `403 Forbidden`, the workflow token
exists but does not have permission to publish the crate that failed. Update
`CARGO_REGISTRY_TOKEN` with a crates.io token that can publish all three workspace
crates, then rerun the release.

If binary builds and the GitHub release succeed while crates.io publish fails, the
release is only partially complete.

## Related Docs

- [Release Playbook](../RELEASE.md)
- [CHANGELOG](../CHANGELOG.md)
