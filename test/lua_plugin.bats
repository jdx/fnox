#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup --git
}

teardown() {
	_common_teardown
}

# Create a git repository at $1 whose provider.lua returns "<ref> (<label>)".
make_plugin_repo() {
	local repo="$1"
	mkdir -p "$repo"
	cat >"$repo/provider.lua" <<'LUA'
return {
  get = function(ctx, ref)
    return ctx.options.greeting .. " " .. ref .. " (v1)"
  end,
}
LUA
	git -C "$repo" init --quiet
	git -C "$repo" add provider.lua
	git -C "$repo" commit --quiet -m v1
	git -C "$repo" tag v1
	sed -i.bak 's/(v1)/(v2)/' "$repo/provider.lua"
	git -C "$repo" commit --quiet -am v2
}

@test "lua provider loads a plugin file relative to the config" {
	mkdir -p plugins sub
	cat >plugins/reverse.lua <<'LUA'
return {
  get = function(ctx, ref) return ref:reverse() end,
}
LUA
	cat >fnox.toml <<'EOF2'
root = true

[providers.rev]
type = "lua"
plugin = "./plugins/reverse.lua"

[secrets]
WORD = { provider = "rev", value = "stressed" }
EOF2

	cd sub
	run "$FNOX_BIN" get WORD
	assert_success
	assert_output "desserts"
}

@test "lua provider stores secrets with a put hook" {
	cat >store.lua <<'LUA'
local json = require("fnox.json")
local function path(ctx) return ctx.plugin_dir .. "/store.json" end
local function load(ctx)
  local f = io.open(path(ctx))
  if not f then return {} end
  local data = json.decode(f:read("a"))
  f:close()
  return data
end
return {
  get = function(ctx, ref) return load(ctx)[ref] end,
  put = function(ctx, key, value)
    local data = load(ctx)
    data["s/" .. key] = value
    local f = assert(io.open(path(ctx), "w"))
    f:write(json.encode(data))
    f:close()
    return "s/" .. key
  end,
}
LUA
	cat >fnox.toml <<'EOF2'
root = true

[providers.store]
type = "lua"
plugin = "store.lua"
EOF2

	run "$FNOX_BIN" set TOKEN hunter2 --provider store
	assert_success
	assert_config_contains 's/TOKEN'
	run grep -q hunter2 fnox.toml
	assert_failure

	run "$FNOX_BIN" get TOKEN
	assert_success
	assert_output "hunter2"
}

@test "lua provider reports auth errors from plugins" {
	cat >locked.lua <<'LUA'
local fnox = require("fnox")
return {
  get = function() fnox.auth_error("vault is locked") end,
}
LUA
	cat >fnox.toml <<'EOF2'
root = true

[providers.locked]
type = "lua"
plugin = "locked.lua"

[secrets]
S = { provider = "locked", value = "x" }
EOF2

	FNOX_PROMPT_AUTH=false run "$FNOX_BIN" get S
	assert_failure
	assert_output --partial "authentication failed: vault is locked"
}

@test "declared plugins install on first use and update to a new ref" {
	make_plugin_repo "$TEST_TEMP_DIR/repo"
	cat >fnox.toml <<EOF2
root = true

[plugins]
demo = "file://$TEST_TEMP_DIR/repo#v1"

[providers.demo]
type = "lua"
plugin = "demo"
options = { greeting = "hello" }

[secrets]
WHO = { provider = "demo", value = "world" }
EOF2

	run "$FNOX_BIN" get WHO
	assert_success
	assert_output --partial "hello world (v1)"
	assert_dir_exist "$HOME/.local/share/fnox/plugins/demo"

	run "$FNOX_BIN" plugin ls
	assert_success
	assert_output --partial "demo"

	sed -i.bak 's/#v1/#main/' fnox.toml
	run "$FNOX_BIN" plugin update demo
	assert_success

	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "hello world (v2)"

	run "$FNOX_BIN" plugin uninstall demo
	assert_success
	assert_dir_not_exist "$HOME/.local/share/fnox/plugins/demo"

	run "$FNOX_BIN" plugin ls
	assert_success
	assert_output --partial "(not installed)"
}

@test "plugins can be pinned to a commit SHA" {
	make_plugin_repo "$TEST_TEMP_DIR/repo"
	sha="$(git -C "$TEST_TEMP_DIR/repo" rev-parse v1)"
	cat >fnox.toml <<'EOF2'
root = true

[providers.demo]
type = "lua"
plugin = "demo"
options = { greeting = "hey" }

[secrets]
WHO = { provider = "demo", value = "you" }
EOF2

	run "$FNOX_BIN" plugin install demo "file://$TEST_TEMP_DIR/repo#$sha"
	assert_success
	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "hey you (v1)"

	cat >>fnox.toml <<EOF2

[plugins]
demo = "file://$TEST_TEMP_DIR/repo#$sha"
EOF2
	run "$FNOX_BIN" plugin update demo
	assert_success
	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "hey you (v1)"
}

@test "failed plugin updates and reinstalls keep the working install" {
	make_plugin_repo "$TEST_TEMP_DIR/repo"
	git -C "$TEST_TEMP_DIR/repo" rm --quiet provider.lua
	git -C "$TEST_TEMP_DIR/repo" commit --quiet -m "drop entry file"
	git -C "$TEST_TEMP_DIR/repo" tag broken
	cat >fnox.toml <<EOF2
root = true

[plugins]
demo = "file://$TEST_TEMP_DIR/repo#v1"

[providers.demo]
type = "lua"
plugin = "demo"
options = { greeting = "hi" }

[secrets]
WHO = { provider = "demo", value = "again" }
EOF2

	run "$FNOX_BIN" plugin install
	assert_success

	sed -i.bak 's/#v1/#broken/' fnox.toml
	run "$FNOX_BIN" plugin update demo
	assert_failure
	assert_output --partial "no provider.lua"
	run "$FNOX_BIN" plugin install demo --force
	assert_failure

	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "hi again (v1)"
}

@test "set fails instead of storing plaintext when a plugin cannot load" {
	echo 'return {' >broken.lua
	cat >fnox.toml <<'EOF2'
root = true

[providers.broken]
type = "lua"
plugin = "broken.lua"
EOF2

	run "$FNOX_BIN" set TOKEN hunter2 --provider broken
	assert_failure
	assert_output --partial "fnox::plugin::error"
	run grep -q hunter2 fnox.toml
	assert_failure
}

@test "plugin install, link, and missing-plugin errors" {
	make_plugin_repo "$TEST_TEMP_DIR/repo"
	cat >fnox.toml <<'EOF2'
root = true

[providers.demo]
type = "lua"
plugin = "demo"
options = { greeting = "hi" }

[secrets]
WHO = { provider = "demo", value = "there" }
EOF2

	run "$FNOX_BIN" get WHO
	assert_failure
	assert_output --partial "plugin 'demo': not installed"

	run "$FNOX_BIN" plugin install demo "file://$TEST_TEMP_DIR/repo#v1"
	assert_success
	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "hi there (v1)"

	run "$FNOX_BIN" plugin install demo "file://$TEST_TEMP_DIR/repo"
	assert_failure
	assert_output --partial "already installed"

	mkdir dev
	echo 'return { get = function(ctx, ref) return "dev " .. ref end }' >dev/provider.lua
	run "$FNOX_BIN" plugin link demo dev --force
	assert_success
	run "$FNOX_BIN" get WHO
	assert_success
	assert_output "dev there"

	run "$FNOX_BIN" plugin update demo
	assert_success
	assert_output --partial "Skipped linked plugin 'demo'"
}
