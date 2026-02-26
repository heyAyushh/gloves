# gloves-setup-migrate

## 0.1.3

### Patch Changes

- Updated migration playbook wording to the grouped CLI syntax (`secrets set`) for consistency with current command model.

## 0.1.2

### Patch Changes

- Added `gloves version --json` to bootstrap verification flow for machine-readable setup checks.

## 0.1.1

### Patch Changes

- Added explicit `gloves --version` verification step before initialization in bootstrap checklist.

## 0.1.0

### Minor Changes

- Initial release of setup and migration skill for gloves.
- Added bootstrap instructions for release/source install and root initialization.
- Added migration playbooks for shared-root ACL and optional separate-roots topologies.
- Added fingerprint/audit verification and per-agent GPG key generation checks.
