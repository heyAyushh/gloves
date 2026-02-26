# TUI Guide

`gloves tui` is an interactive command navigator for operators and agents.

## What It Does

- Shows a tree of commands and groups.
- Lets you edit global flags and command fields.
- Executes commands with live output streaming.
- Keeps output history cards for previous runs.

## Command Execution Cycle (Enter)

When focus is in the command tree and the selected row is an executable command, `Enter` follows this cycle:

1. Commands pane -> Global Flags pane
2. Global Flags pane -> Command Fields pane
3. Command Fields pane -> Run command
4. After run trigger -> focus returns to Commands pane

If the selected row is a branch/group node, `Enter` toggles expand/collapse.

## Key Controls

- `Up`/`Down` or `j`/`k`: move selection
- `Left`/`Right` or `h`/`l`: collapse/expand groups
- `Tab` / `Shift+Tab`: switch panes
- `Enter`: run cycle (commands -> flags -> fields -> run -> commands)
- `r` or `F5`: run selected command immediately
- `e`: edit selected text field (with live update while editing)
- `Space`: toggle boolean field
- `f`: toggle fullscreen for the focused pane
- `/`: filter command tree
- `?`: run help for selected command
- `c`: clear output history cards
- `Home` or `g`: jump output to top (disable follow-tail)
- `End` or `G`: jump output to bottom (enable follow-tail)
- `Ctrl+C`: cancel active run
- `q` or `Esc`: quit (waits if run is active)

## Output Behavior

- Output pane shows structured run cards (command, phase, exit code, stream content).
- Stdout/stderr stream live while command is running.
- Follow-tail is enabled by default and can be overridden via manual scroll.

## Recommended Operator Flow

1. Select command in tree.
2. Press `Enter` through flags and fields.
3. Confirm command runs and output appears in execution pane.
4. Use `?` for immediate command help in output pane.

## Related Docs

- [Quickstart](quickstart.md)
- [Secrets and Requests](secrets-and-requests.md)
- [Troubleshooting](troubleshooting.md)
