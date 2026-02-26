# gloves-cli-usage

## 0.2.6

### Patch Changes

- Updated skill guidance to the grouped CLI model (`secrets ...`, `requests ...`) and removed top-level command examples that cause confusion.
- Updated request workflow examples to use noun-first review commands (`requests list|approve|deny`) and `secrets status`.
- Updated reference help paths to recursive forms (`gloves help [topic...]`, `gloves requests help approve`, `gloves secrets help set`).

## 0.2.5

### Patch Changes

- Added `tui` command reference for ratatui-based interactive navigation.
- Documented `--error-format <text|json>` diagnostics output mode.
- Documented typo suggestion auto-run environment controls and safety gates.

## 0.2.4

### Patch Changes

- Added `requests` grouped workflow coverage (`requests list|approve|deny`, `req` alias).
- Added `explain` command coverage for stable CLI error codes (`gloves explain <code>`).
- Updated troubleshooting guidance to reference `error[E...]` output and direct remediation path.

## 0.2.3

### Patch Changes

- Added guidance to use `gloves help approve|set|request` for command-level recovery examples.
- Documented new remediation hints for common input mistakes (`request-id`, name format, ACL, and TTL).

## 0.2.2

### Patch Changes

- Added `version` command coverage in command reference (`gloves version`, `gloves version --json`).
- Added explicit recovery guidance for `approve`/`deny` request-id mistakes (`gloves list --pending` first).

## 0.2.1

### Patch Changes

- Updated command reference for current CLI flags and subcommands (`get --pipe-to/--pipe-to-args`, `list --pending`, `audit`, `vault exec`).
- Added quick inspection commands (`gloves --help`, `gloves help <command>`, `gloves --version`) to workflow guidance.

## 0.2.0

### Minor Changes

- Renamed package from `gloves-cli` to `gloves-cli-usage`.
- Added task playbooks for config/access visibility and GPG key operations.
- Added guardrails to keep raw secret values out of agent memory and notes.
- Added command reference updates for `vault`, `config validate`, `access paths`, `gpg create`, and `gpg fingerprint`.
