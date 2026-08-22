# usage 6.x migration status

This branch converts fnox's real typed CLI from clap to usage-rs and removes
clap from the runtime dependencies. The workspace compiles and all fnox and
fnox-core tests pass. The crates.io pin is `usage-rs` 6.

The working port still demonstrates release gaps tracked in jdx/usage's plan:

- command-with-arguments completion hints have no usage equivalent, although
  double-dash forwarding preserves parsing;
- bare unit Args structs require braces, and the same Args body mounted under
  multiple commands requires thin wrapper types;
- a positional relationship is enforced after binding because the spec cannot
  attach conflicts to positional arguments;
- mutable spec generation pulls in usage-lib and its newer MSRV rather than
  staying on the argv/derive tier;
- parser tests need a local argv0-skipping helper because usage's `parse_from`
  contract takes only the words after the executable.
