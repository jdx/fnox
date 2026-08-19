# usage 6.x adoption experiment

This generated crate proves that usage's static tables can express fnox's current
checked-in spec: 47 commands, 71 flags, and 18 positional arguments are emitted
without dropping a spec field. It intentionally pins usage to a git revision and
is not intended to merge before usage 6.x.

It is not yet the typed fnox CLI. Converting the real clap structs still has to
resolve:

- clap value enums and domain parsers without duplicating their declared values;
- expression-valued defaults such as `DEFAULT_CONFIG_FILENAME`;
- append actions and alternate parser entry points used by shell integration;
- value hints, aliases, environment fallback, and hidden internal commands;
- trailing command arguments with hyphen values;
- the nested provider, lease, proxy, and daemon command graphs.

The generated source is a concrete compile target and baseline for the typed
conversion. Regenerate it from the usage repository with:

```console
cargo run -p xtask -- gen-shadow /path/to/fnox/fnox.usage.kdl /path/to/fnox/experiments/usage6 usage
```

