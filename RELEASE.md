# Release Playbook

This repository uses branch-based release channels with tag-driven publishing.

## Channel Rules

- `stable`:
  - Allowed branches: `main` or `release/*`
  - Tag format: `vX.Y.Z`
- `beta`:
  - Allowed branch: `next`
  - Tag format: `vX.Y.Z-beta.N`
- `alpha`:
  - Allowed branch: `canary`
  - Tag format: `vX.Y.Z-alpha.N`

The publish workflow also enforces:
- tag version equals `Cargo.toml` version
- tag commit belongs to an allowed branch for that channel
- crates publish in dependency order: `gloves-core`, `gloves-config`, then `gloves`
- `CARGO_REGISTRY_TOKEN` must be a crates.io API token with publish rights for
  `gloves-core`, `gloves-config`, and `gloves`

## Release Outputs

For each tag, GitHub Actions `Publish` workflow now produces:

- crates.io publish (`gloves` crate)
- GitHub Release assets:
  - `gloves-<version>-x86_64-unknown-linux-gnu.tar.gz`
  - `gloves-<version>-x86_64-apple-darwin.tar.gz`
  - `gloves-<version>-aarch64-apple-darwin.tar.gz`
  - `gloves-<version>-x86_64-pc-windows-msvc.zip`
  - `checksums.txt` (SHA-256)

Users can install from prebuilt binaries via:

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/gloves/main/scripts/setup-openclaw.sh | bash
```

The setup script installs both OpenClaw skills by default:
- `gloves-cli-usage`
- `gloves-setup-migrate`

## Preflight (all channels)

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
cargo publish --dry-run --locked
```

`cargo publish --dry-run --locked` validates the root crate once its dependency
versions already exist on crates.io. On a fresh release, also dry-run the crates
in publish order:

```bash
cargo publish -p gloves-core --dry-run --locked
cargo package -p gloves-config --list
cargo package -p gloves --list
```

Update release files before tagging:
- `Cargo.toml` version
- `CHANGELOG.md`

## Stable Release (`main` or `release/*`)

Example version: `1.4.0`

```bash
git checkout main
git pull --ff-only

# edit Cargo.toml version -> 1.4.0
# edit CHANGELOG.md

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): 1.4.0"

git tag v1.4.0
git push origin main
git push origin v1.4.0
```

## Beta Release (`next`)

Example version: `1.5.0-beta.1`

```bash
git checkout next
git pull --ff-only

# edit Cargo.toml version -> 1.5.0-beta.1
# edit CHANGELOG.md

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): 1.5.0-beta.1"

git tag v1.5.0-beta.1
git push origin next
git push origin v1.5.0-beta.1
```

## Alpha Release (`canary`)

Example version: `1.5.0-alpha.1`

```bash
git checkout canary
git pull --ff-only

# edit Cargo.toml version -> 1.5.0-alpha.1
# edit CHANGELOG.md

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): 1.5.0-alpha.1"

git tag v1.5.0-alpha.1
git push origin canary
git push origin v1.5.0-alpha.1
```

## Optional: Stabilize from a Release Branch

```bash
git checkout main
git pull --ff-only
git checkout -b release/1.5
git push -u origin release/1.5
```

Apply fixes on `release/1.5`, then create stable tags (`v1.5.Z`) from that branch.

## Troubleshooting

If the `Publish to crates.io` job fails with `403 Forbidden`, the workflow reached
crates.io with a token that does not have publish permission for one or more
workspace crates. Rotate or replace `CARGO_REGISTRY_TOKEN` with a crates.io token
that can publish `gloves-core`, `gloves-config`, and `gloves`, then rerun the tag
workflow.

GitHub release assets can still succeed when crates.io publishing fails. Treat the
release as incomplete until the crates.io publish job is green.
