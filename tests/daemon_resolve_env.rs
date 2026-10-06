//! `fnox-client` against a real daemon started by the fnox binary.
#![cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    )
))]

use fnox_client::document::EnvScope;
use fnox_client::wire::{CallOptions, Request, ResolveEnvRequest, Response};
use fnox_client::{CliFlags, Client, EnvOutcome, EnvRequest, RuntimeEnv, SocketKey};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const FNOX: &str = env!("CARGO_BIN_EXE_fnox");

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    runtime: PathBuf,
    p: PathBuf,
    q: PathBuf,
    env: Vec<(String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let runtime = root.join("run");
        let p = root.join("p");
        let q = root.join("q");
        for path in [&home, &runtime, &p, &q] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            p.join("fnox.toml"),
            r#"root = true

[daemon]
enabled = true
idle_timeout = "60s"

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "foo" }
BAR = { provider = "plain", value = "bar", env = "exec" }
HID = { provider = "plain", value = "hid", env = false }
QUX = { provider = "plain", value = "qux" }
"#,
        )
        .unwrap();
        // Project Q does not enable the daemon.
        std::fs::write(
            q.join("fnox.toml"),
            r#"root = true

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "foo" }
"#,
        )
        .unwrap();
        let env = vec![
            ("HOME".to_string(), home.to_string_lossy().into_owned()),
            (
                "XDG_RUNTIME_DIR".to_string(),
                runtime.to_string_lossy().into_owned(),
            ),
            (
                "PATH".to_string(),
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
            ),
        ];
        Self {
            _dir: dir,
            home,
            runtime,
            p,
            q,
            env,
        }
    }

    fn client(&self, env: &[(String, String)]) -> Client {
        let get = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        Client::new(
            SocketKey::from_cli_env(&CliFlags::default(), &get),
            &RuntimeEnv::from_env(&get),
        )
    }

    fn resolve(&self, cwd: &Path, keys: &[&str], env: &[(String, String)]) -> EnvOutcome {
        let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        self.client(env).resolve_env(&EnvRequest {
            cwd,
            config: Path::new("fnox.toml"),
            scope: EnvScope::Exec,
            keys: Some(&keys),
            env,
        })
    }

    fn fnox(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(FNOX);
        cmd.args(args).current_dir(cwd).env_clear();
        for (key, value) in &self.env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }
}

/// Stops the daemon even when an assertion fails.
struct StopDaemon<'a>(&'a Fixture);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.fnox(&self.0.p, &["daemon", "stop"]);
    }
}

#[test]
fn the_client_reads_what_the_cli_cached() {
    let f = Fixture::new();
    let _stop = StopDaemon(&f);

    // 1. Nothing runs: Absent, and the client created nothing.
    assert!(matches!(
        f.resolve(&f.p, &["FOO", "BAR"], &f.env),
        EnvOutcome::Absent
    ));
    assert!(
        std::fs::read_dir(&f.runtime).unwrap().next().is_none(),
        "the client must not create the runtime dir"
    );

    // 2. `fnox env --json` auto-starts the daemon and fills its cache.
    let out = f.fnox(&f.p, &["env", "--json", "--keys", "FOO,BAR"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cli: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(cli["set"]["FOO"], "foo");

    // 3. The client now hits, with the document the CLI printed.
    let EnvOutcome::Hit(doc) = f.resolve(&f.p, &["FOO", "BAR"], &f.env) else {
        panic!("expected a hit");
    };
    let hit: serde_json::Value = serde_json::to_value(&doc).unwrap();
    assert_eq!(hit, cli, "the daemon's document equals the CLI's");
    assert_eq!(doc.set["FOO"].expose(), "foo");
    assert_eq!(doc.set["BAR"].expose(), "bar");
    assert!(doc.remove.contains(&"HID".to_string()));

    // 4. Not cached: a miss. An env = false key: rejected.
    let EnvOutcome::Miss { keys } = f.resolve(&f.p, &["QUX"], &f.env) else {
        panic!("expected a miss");
    };
    assert_eq!(keys, ["QUX"]);
    let EnvOutcome::Rejected(rejection) = f.resolve(&f.p, &["HID"], &f.env) else {
        panic!("expected a rejection");
    };
    assert_eq!(rejection.not_injectable[0].key, "HID");

    // 5. A project that does not enable the daemon is not served from it.
    assert!(matches!(
        f.resolve(&f.q, &["FOO"], &f.env),
        EnvOutcome::Disabled
    ));

    // 6. FNOX_DAEMON=0 in the request's env, without I/O.
    let mut off = f.env.clone();
    off.push(("FNOX_DAEMON".to_string(), "0".to_string()));
    assert!(matches!(
        f.resolve(&f.p, &["FOO", "BAR"], &off),
        EnvOutcome::Disabled
    ));

    // 7. hello.
    let info = f.client(&f.env).hello().unwrap();
    assert_eq!(info.protocol, 6);
    assert_eq!(info.min_protocol, 6);
    assert_eq!(info.fnox_version, env!("CARGO_PKG_VERSION"));
    assert!(info.pid > 0);

    // 8. V9: the daemon re-reads the global config on every request, so a global
    //    `[daemon] enabled = true` now serves project Q.
    let config_dir = f.home.join(".config/fnox");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), "[daemon]\nenabled = true\n").unwrap();
    assert!(
        matches!(
            f.resolve(&f.q, &["FOO"], &f.env),
            EnvOutcome::Miss { .. } | EnvOutcome::Hit(_)
        ),
        "Q is served once the global config enables the daemon"
    );
}

#[test]
fn an_undeclared_profile_is_an_error_not_a_hit() {
    let f = Fixture::new();
    let _stop = StopDaemon(&f);
    let out = f.fnox(&f.p, &["env", "--json", "--keys", "FOO"]);
    assert!(out.status.success());

    let client = f.client(&f.env);
    let request = Request::ResolveEnv(ResolveEnvRequest {
        protocol: 6,
        cwd: f.p.clone(),
        config: PathBuf::from("fnox.toml"),
        profile: vec!["nope".to_string()],
        age_key_file: None,
        if_missing: None,
        no_defaults: false,
        scope: EnvScope::Exec,
        keys: Some(vec!["FOO".to_string()]),
        env: f.env.clone(),
    });
    let response = fnox_client::wire::call(
        client.socket_path(),
        &request,
        &CallOptions::with_timeout(std::time::Duration::from_secs(10)),
    )
    .unwrap();
    assert!(
        matches!(&response, Response::Error { message } if message.contains("nope")),
        "{response:?}"
    );
}
