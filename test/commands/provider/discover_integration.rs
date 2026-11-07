use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    directory: tempfile::TempDir,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir(root.join("bin")).unwrap();
        std::fs::create_dir(root.join("config")).unwrap();
        let config = root.join("fnox.toml");
        std::fs::write(
            &config,
            r#"root = true
[providers.op]
type = "1password"
vault = "Engineering"
account = "example.1password.test"
token = { secret = "OP_TOKEN" }
[providers.plain]
type = "plain"
[secrets]
OP_TOKEN = { provider = "plain", value = "discovery-test-token", env = false }
"#,
        )
        .unwrap();
        let stub = root.join("bin/op");
        std::fs::write(&stub, r#"#!/bin/sh
# Only metadata discovery is accepted; any field read fails the test.
[ "$1" = item ] && [ "$2" = list ] || exit 91
shift 2
tags=''
format=false
vault=false
archive=false
account=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --tags=*) tags="${1#--tags=}" ;;
        --format=json) format=true ;;
        --vault=Engineering) vault=true ;;
        --include-archive=false) archive=true ;;
        --account) shift; [ "$1" = example.1password.test ] || exit 92; account=true ;;
        *) exit 93 ;;
    esac
    shift
done
[ "$format/$vault/$archive/$account" = true/true/true/true ] || exit 94
[ "$OP_SERVICE_ACCOUNT_TOKEN" = discovery-test-token ] || exit 95
case "$tags" in
    empty) printf '[]' ;;
    invalid) printf 'not-json' ;;
    fail) printf '[ERROR] authentication failed\n' >&2; exit 1 ;;
    project/example|project/example,development)
        printf '[{"id":"example-id","title":"Example API","tags":["project/example/development"],"vault":{"id":"vault-id","name":"Engineering"},"fields":[{"value":"must-not-leak"}]}]' ;;
    '') printf '[{"id":"other-id","title":"Other","vault":{"id":"vault-id","name":"Engineering"}},{"id":"example-id","title":"Example API","tags":["project/example"],"vault":{"id":"vault-id","name":"Engineering"}}]' ;;
    *) exit 96 ;;
esac
"#).unwrap();
        std::fs::set_permissions(stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { directory, config }
    }
    fn run(&self, args: &[&str]) -> Output {
        let root = self.directory.path();
        let existing_path = std::env::var_os("PATH").unwrap_or_default();
        let paths = std::iter::once(root.join("bin")).chain(std::env::split_paths(&existing_path));
        let mut command = Command::new(env!("CARGO_BIN_EXE_fnox"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("FNOX_")
                || name.to_string_lossy().starts_with("OP_")
            {
                command.env_remove(name);
            }
        }
        command
            .current_dir(root)
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("FNOX_CONFIG_DIR", root.join("config"))
            .env("FNOX_DAEMON", "off")
            .env("FNOX_PROMPT_AUTH", "false")
            .args(["--non-interactive", "-c"])
            .arg(&self.config)
            .args(["provider", "discover"])
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn tags_narrow_results_using_configured_account_vault_and_token() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.config).unwrap();
    for tags in [
        vec!["--tags", "project/example"],
        vec!["--tags", "project/example,development"],
        vec!["--tags", "project/example", "--tags", "development"],
    ] {
        let mut args = vec!["op", "--json"];
        args.extend(tags);
        let result = fixture.run(&args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            value,
            serde_json::json!([{"id":"example-id","title":"Example API","tags":["project/example/development"],"vault":{"id":"vault-id","name":"Engineering"}}])
        );
    }
    assert_eq!(std::fs::read(&fixture.config).unwrap(), before);
    assert!(
        std::fs::read_dir(fixture.directory.path().join("config"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn omitted_tags_list_all_in_scope_and_no_matches_return_an_empty_array() {
    let fixture = Fixture::new();
    let result = fixture.run(&["op", "--json"]);
    assert!(result.status.success());
    let items: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(items.as_array().unwrap().len(), 2);
    assert_eq!(items[0]["title"], "Example API");
    let result = fixture.run(&["op", "--tags", "empty", "--json"]);
    assert!(result.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn errors_do_not_produce_successful_empty_results_or_secret_output() {
    let fixture = Fixture::new();
    for args in [
        vec!["op", "--tags", "invalid", "--json"],
        vec!["op", "--tags", "fail", "--json"],
        vec!["plain", "--tags", "project/example"],
        vec!["missing", "--json"],
    ] {
        let result = fixture.run(&args);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("must-not-leak"));
    }
}
