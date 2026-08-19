# usage 6.x migration status

This branch converts fnox's real CLI structs and attributes from clap to
usage-rs and removes clap from the runtime dependencies. It remains an
experimental PR until usage 6.x can support the complete typed command tree.

`cargo check` reaches the usage derives and currently reports 326 diagnostics,
mostly cascades from these underlying blockers:

- `ValueHint::CommandWithArguments` has no usage completion type;
- cfg-gated value-enum variants cannot form usage's required const list;
- usage's `ValueEnum` implementation conflicts with existing `FromStr`
  implementations on fnox import/export formats;
- expression-valued defaults such as `DEFAULT_CONFIG_FILENAME` do not map to a
  literal usage attribute;
- several command structs are reused or shaped as independent clap parser roots
  in ways that do not implement usage `CommandArgs` after conversion;
- clap `CommandFactory`-based spec generation and command sorting have no direct
  replacement at their existing call sites;
- positional placeholders, hidden command structs, and some relationship
  selectors need semantic rather than textual attribute translation.

The branch keeps the compiler failures on the real types visible. A generated
String shadow would not exercise any of these constraints.
