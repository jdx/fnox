---
description: "Browse, search, and copy secrets across profiles in the fnox terminal UI. Values stay masked unless you reveal them."
---

# Terminal UI

`fnox tui` opens an interactive view of the current project's providers and secrets. Use it to find a secret, compare profiles, or copy a value to the clipboard without printing it.

```sh
fnox tui
```

Values are masked by default. Press `V` to show truncated previews, or `c` to copy a value without displaying it.

## Keys

| Key                | Action                                                                                                     |
| ------------------ | ---------------------------------------------------------------------------------------------------------- |
| `↑` `↓` or `k` `j` | Move                                                                                                       |
| `g` / `G`          | Jump to top / bottom                                                                                       |
| `Tab`              | Switch between the providers and secrets panes                                                             |
| `/`                | Filter by name. `Enter` keeps the filter, `Esc` clears it                                                  |
| `Enter`            | Show details: provider, reference, description, default, `if_missing`, source file, and the value's length |
| `c`                | Copy the selected value to the clipboard                                                                   |
| `V`                | Toggle value previews in the list                                                                          |
| `P`                | Switch profile                                                                                             |
| `r`                | Re-resolve secrets                                                                                         |
| `e` / `s`          | Edit the selected value / add a secret (in memory only, see below)                                         |
| `?`                | Help                                                                                                       |
| `q` or `Esc`       | Close a popup, or quit                                                                                     |

You can also click to select and scroll with the mouse.

## Editing is temporary

`e` and `s` change values only for the current session; nothing is written to `fnox.toml`. Deleting isn't supported. To make a change permanent, use `fnox set` or `fnox remove`.

## See also

- [Profiles](/guide/profiles): what the profile picker switches between.
- [`fnox set`](/cli/set): store a value permanently.
