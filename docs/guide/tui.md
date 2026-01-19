# TUI Dashboard

fnox includes an interactive terminal user interface (TUI) for browsing and managing your secrets visually.

## Launch the TUI

```bash
fnox tui
```

## Features

### Secret List

The main view shows all secrets in the current profile with their status:

- **Name** - The environment variable name
- **Value Preview** - A truncated preview of the decrypted value
- **Provider** - Which provider manages the secret

Use arrow keys or `j`/`k` to navigate through the list.

### Search Filtering

Press `/` to enter search mode. Type to filter secrets by name. The list updates in real-time as you type. Press `Esc` to clear the search and return to the full list.

### Profile Switching

Press `p` to open the profile picker. Select a different profile to view its secrets. This allows you to quickly compare secrets across environments (dev, staging, production).

### Secret Details

Press `Enter` on any secret to view its full details:

- Full decrypted value
- Provider name
- Description (if set)
- Default value (if set)
- Key name in the provider (if different from env var name)

Press `Esc` to close the detail view.

### Copy to Clipboard

Press `c` to copy the currently selected secret's value to your clipboard. A confirmation message appears briefly at the bottom of the screen.

### Edit Secrets

Press `e` to edit the selected secret's value. This opens an input field where you can modify the value. Press `Enter` to confirm or `Esc` to cancel.

::: warning
Edits made in the TUI are temporary and stored in memory only. They are **not** persisted to your config file. To permanently change a secret, use `fnox set`.
:::

## Keyboard Shortcuts

| Key          | Action                         |
| ------------ | ------------------------------ |
| `q` or `Esc` | Quit (or close popup)          |
| `↑` / `k`    | Move up                        |
| `↓` / `j`    | Move down                      |
| `/`          | Enter search mode              |
| `Enter`      | View secret details            |
| `c`          | Copy secret value to clipboard |
| `e`          | Edit secret (in memory only)   |
| `p`          | Open profile picker            |

## Mouse Support

The TUI supports mouse interactions:

- **Click** on a secret to select it
- **Scroll** to navigate through the list
- **Click** on profile picker items to switch profiles

## Tips

### Quickly Find a Secret

1. Press `/` to search
2. Type part of the secret name
3. Press `Enter` to view the first match

### Compare Environments

1. Press `p` to open the profile picker
2. Switch between profiles to see how secrets differ
3. Use `c` to copy values you need

### Secure Viewing

The TUI shows decrypted values only when you explicitly view them (via `Enter`). The main list shows truncated previews to reduce shoulder-surfing risk.
