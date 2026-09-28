---
description: "Browse secrets and profiles in the fnox terminal dashboard, inspect values, copy secrets, and understand editing limits."
---

# Terminal dashboard

Use `fnox tui` to browse, filter, and copy secrets in a terminal. Values are masked by default. Changes made in the dashboard are temporary; use `fnox set` to persist a value.

## Launch the TUI

```bash
fnox tui
```

## Features

### Secret list

The main view shows all secrets in the current profile with their status:

- **Name** - The environment variable name
- **Provider** - Which provider manages the secret
- **Value** - Masked by default; press `V` to toggle a truncated preview of the resolved value

Use arrow keys or `j`/`k` to navigate through the list, `g`/`G` to jump to the top or bottom, and `Tab` to switch focus between the providers and secrets panes.

### Search filtering

Press `/` to enter search mode. Type to filter secrets by name. The list updates in real time as you type. Press `Enter` to leave search mode and keep the filter, or `Esc` to clear the search and return to the full list.

### Profile switching

Press `P` to open the profile picker. Select a different profile to view its secrets. This allows you to quickly compare secrets across environments (dev, staging, production).

### Secret details

Press `Enter` on any secret to view its details:

- Provider name
- Provider key (the secret's `value` field, if set)
- Description (if set)
- Default value (if set)
- `if_missing` behavior and source file (if set)
- Resolved value status (shown as a character count, not the value itself)

Press `c` in the detail view to copy the value, or any other key to close it.

### Copy to clipboard

Press `c` to copy the currently selected secret's value to your clipboard. A confirmation message appears briefly at the bottom of the screen.

### Edit secrets

Press `e` to edit the selected secret's value, or `s` to add a new secret. This opens an input field where you can modify the value. Press `Enter` to confirm or `Esc` to cancel.

::: warning
Edits and new secrets created in the TUI are temporary and stored in memory only. They are **not** persisted to your config file, and `d` (delete) is not yet implemented. To permanently change a secret, use `fnox set` or `fnox remove`.
:::

## Keyboard shortcuts

| Key          | Action                                 |
| ------------ | -------------------------------------- |
| `q` or `Esc` | Quit (or close popup)                  |
| `↑` / `k`    | Move up                                |
| `↓` / `j`    | Move down                              |
| `g` / `G`    | Jump to top / bottom                   |
| `Tab`        | Switch focus between providers/secrets |
| `/`          | Enter search mode                      |
| `Enter`      | View secret details                    |
| `c`          | Copy secret value to clipboard         |
| `V`          | Toggle showing values in the list      |
| `e`          | Edit secret (in memory only)           |
| `s`          | Set a new secret (in memory only)      |
| `r`          | Refresh secrets                        |
| `P`          | Open profile picker                    |
| `?`          | Show help                              |

## Mouse support

The TUI supports mouse interactions:

- **Click** on a secret or provider to select it
- **Scroll** to navigate through the list
- **Click** anywhere to dismiss the help or secret detail popup

## Tips

### Quickly find a secret

1. Press `/` to search
2. Type part of the secret name
3. Press `Enter` to leave search mode, then `Enter` again to view the selected match

### Compare environments

1. Press `P` to open the profile picker
2. Switch between profiles to see how secrets differ
3. Use `c` to copy values you need

### Secure viewing

The TUI masks values in the main list by default and never prints the full value on screen. Press `V` to reveal truncated previews when you need them, and use `c` to copy a value to the clipboard without displaying it.

## Next steps

- [Set a secret](/cli/set): save a value to a configured provider.
- [Profiles](/guide/profiles): choose which environment the dashboard displays.
