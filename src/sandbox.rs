//! OS sandbox for `fnox proxy run`.
//!
//! The credential proxy only controls where credentials are sent; a child
//! running as the same user could still skip the proxy, read fnox's
//! configuration, or ask another credential store. The sandbox closes those
//! routes:
//!
//! - **Network**: the child can reach nothing but the proxy.
//! - **Files**: the filesystem is read-only except for the working directory
//!   and temporary files, and fnox's configuration, keys, state and common
//!   credential directories are hidden.
//! - **Sockets**: on Linux the whole `/run` tree is hidden, which takes the
//!   fnox daemon, D-Bus, gpg-agent and the Docker socket with it.
//!
//! Linux uses `bwrap` (bubblewrap). The proxy listens on a Unix socket that is
//! bind-mounted into the sandbox, and `fnox sandbox-bridge` runs inside it to
//! offer that socket to the child as an ordinary `127.0.0.1` proxy. macOS uses
//! `sandbox-exec` and lets the child reach the proxy's loopback port. Other
//! platforms are not supported, and an unavailable sandbox is an error: the
//! command is never run unsandboxed.

use crate::commands::Cli;
use crate::config::{Config, ProxyConfig, all_config_filenames, uses_config_discovery};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::proxy::{ProxyListener, RunningProxy};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Port of the bridge inside the sandbox. The sandbox has its own network
/// namespace, so nothing else can be using it.
pub const BRIDGE_PORT: u16 = 18099;

/// Where the sandbox sees the files fnox hands it.
const SANDBOX_DIR: &str = "/tmp/.fnox-sandbox";

/// Directories under the home directory that hold credentials other than
/// fnox's own.
const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".azure",
    ".kube",
    ".gnupg",
    ".password-store",
    ".config/gcloud",
    ".config/gh",
    ".config/op",
    ".config/doppler",
    ".config/rclone",
    ".docker/config.json",
    ".local/share/keyrings",
    ".local/share/gopass",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".vault-token",
    ".terraform.d/credentials.tfrc.json",
];

/// Variables that point a child at a credential store outside the sandbox.
pub const UNSET_ENV: &[&str] = &[
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "DOCKER_HOST",
];

/// What the command may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub cwd: PathBuf,
    /// Paths the command may not read. One that does not exist yet is inside
    /// a writable path, and is kept from being created.
    pub hide: Vec<HiddenPath>,
    /// Paths the command may write.
    pub writable: Vec<PathBuf>,
    /// Paths inside a writable one that the command may not write, whether
    /// or not they exist yet.
    pub read_only: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenPath {
    pub path: PathBuf,
    pub is_dir: bool,
}

/// Everything the policy is derived from, so tests can supply their own.
pub struct PolicyInputs<'a> {
    pub cwd: PathBuf,
    pub home: PathBuf,
    /// fnox's own configuration, state and data directories.
    pub fnox_dirs: Vec<PathBuf>,
    /// Configuration files and key files that live outside those directories.
    pub fnox_files: Vec<PathBuf>,
    /// Sockets and directories named by the environment.
    pub environment: Vec<PathBuf>,
    pub config: &'a ProxyConfig,
}

impl SandboxPolicy {
    pub fn build(inputs: PolicyInputs<'_>) -> Self {
        let PolicyInputs {
            cwd,
            home,
            fnox_dirs,
            fnox_files,
            environment,
            config,
        } = inputs;
        let resolve = |entry: &String| expand(entry, &home, &cwd);

        let mut writable = vec![cwd.clone()];
        writable.extend(config.sandbox_allow_write.iter().map(resolve));
        writable.retain(|path| path.exists());
        let writable_path = |path: &Path| writable.iter().any(|bound| path.starts_with(bound));

        let mut candidates: Vec<PathBuf> = Vec::new();
        candidates.extend(fnox_dirs);
        candidates.extend(fnox_files);
        candidates.extend(environment);
        candidates.extend(CREDENTIAL_PATHS.iter().map(|path| home.join(path)));
        candidates.extend(config.sandbox_deny_read.iter().map(resolve));

        let allowed: Vec<PathBuf> = config.sandbox_allow_read.iter().map(resolve).collect();
        let mut hide: Vec<HiddenPath> = Vec::new();
        let mut read_only: Vec<PathBuf> = Vec::new();
        for path in candidates {
            let path = canonicalize_lossy(&path);
            let metadata = std::fs::metadata(&path).ok();
            if allowed.iter().any(|allow| path.starts_with(allow)) {
                // Readable, but a mask also stopped writes, and the command
                // must not be able to rewrite its own configuration.
                // A path that does not exist yet is kept from being created.
                if writable_path(&path) {
                    read_only.push(path);
                }
                continue;
            }
            match metadata {
                Some(metadata) => hide.push(HiddenPath {
                    path,
                    is_dir: metadata.is_dir(),
                }),
                // The command could create it, and fnox or git would read it
                // later outside the sandbox. Elsewhere it cannot be created.
                None if writable_path(&path) => hide.push(HiddenPath {
                    path,
                    is_dir: false,
                }),
                None => {}
            }
        }
        hide.sort_by(|a, b| a.path.cmp(&b.path));
        hide.dedup_by(|b, a| a.path == b.path);
        // Hiding a directory already hides what is inside it, and bwrap cannot
        // mount over a path that the first mount removed.
        let all: Vec<PathBuf> = hide.iter().map(|hidden| hidden.path.clone()).collect();
        hide.retain(|hidden| {
            !all.iter()
                .any(|other| other != &hidden.path && hidden.path.starts_with(other))
        });

        // A command that can edit these runs code outside the sandbox the
        // next time git does. They are protected even when missing, so the
        // command cannot create them.
        if cwd.join(".git").is_dir() {
            read_only.extend([".git/hooks", ".git/config"].map(|path| cwd.join(path)));
        }
        read_only.sort();
        read_only.dedup();

        Self {
            cwd,
            hide,
            writable,
            read_only,
        }
    }

    /// Gathers the inputs from the running process and the loaded config.
    pub fn from_environment(cli: &Cli, config: &Config, proxy: &ProxyConfig) -> Result<Self> {
        let cwd = env::current_dir()
            .and_then(std::fs::canonicalize)
            .map_err(|error| {
                FnoxError::Config(format!("failed to read the working directory: {error}"))
            })?;
        let requested = Config::get_profiles(&cli.profile);
        // Profiles that the requested ones inherit have files of their own.
        let profile = config
            .resolve_profiles(&requested)
            .unwrap_or_else(|_| requested.clone());

        let mut fnox_files = Vec::new();
        if uses_config_discovery(&cli.config) {
            let names = all_config_filenames(&profile);
            for dir in cwd.ancestors() {
                fnox_files.extend(names.iter().map(|name| dir.join(name)));
            }
        } else {
            fnox_files.push(if cli.config.is_relative() {
                cwd.join(&cli.config)
            } else {
                cli.config.clone()
            });
        }
        fnox_files.push(Config::global_config_path());
        let imports = fnox_files
            .iter()
            .flat_map(|file| imported_files(file))
            .collect::<Vec<_>>();
        fnox_files.extend(imports);
        fnox_files.extend(config.age_key_file.clone());
        fnox_files.extend(cli.age_key_file.clone());
        fnox_files.extend(provider_key_files(config, &profile, &cwd)?);
        fnox_files.extend(env::var_os("FNOX_AGE_KEY_FILE").map(PathBuf::from));

        let environment = ["XDG_RUNTIME_DIR", "SSH_AUTH_SOCK"]
            .iter()
            .filter_map(env::var_os)
            .map(PathBuf::from)
            .collect();

        Ok(Self::build(PolicyInputs {
            cwd,
            home: env::HOME_DIR.clone(),
            fnox_dirs: vec![
                env::FNOX_CONFIG_DIR.clone(),
                env::FNOX_STATE_DIR.clone(),
                env::FNOX_DATA_DIR.clone(),
            ],
            fnox_files,
            environment,
            config: proxy,
        }))
    }
}

/// The `key_file` of every provider the profiles use, such as an age identity.
///
/// A `key_file` that is not a literal path, such as a reference to a secret,
/// names a file only once it is resolved, and the policy is built before any
/// secret is. That is an error rather than a file left readable.
fn provider_key_files(config: &Config, profile: &[String], cwd: &Path) -> Result<Vec<PathBuf>> {
    let providers = config.get_providers(profile)?;
    let mut files = Vec::new();
    for (name, provider) in &providers {
        let Ok(value) = serde_json::to_value(provider) else {
            continue;
        };
        match value.get("key_file") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(path)) => {
                files.push(expand(path, &env::HOME_DIR, cwd));
            }
            Some(_) => {
                return Err(FnoxError::Config(format!(
                    "provider '{name}' sets key_file to something other than a path, \
                     so the sandbox cannot tell which file to hide; use a literal path"
                )));
            }
        }
    }
    Ok(files)
}

/// The files `path` imports, if it can be read as a fnox config.
fn imported_files(path: &Path) -> Vec<PathBuf> {
    #[derive(serde::Deserialize)]
    struct Imports {
        #[serde(default)]
        import: Vec<String>,
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = toml_edit::de::from_str::<Imports>(&content) else {
        return Vec::new();
    };
    let dir = path.parent();
    parsed
        .import
        .iter()
        .map(|import| crate::config_path::resolve_relative_to_dir(import, dir))
        .collect()
}

/// Resolves symlinks in the part of `path` that exists.
fn canonicalize_lossy(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonicalize_lossy(parent).join(name),
        _ => path.to_path_buf(),
    }
}

/// What to mount over so that `path` cannot be created: the first ancestor
/// (or `path` itself) that does not exist yet.
fn mask_target(path: &Path) -> PathBuf {
    let mut target = path;
    while let Some(parent) = target.parent() {
        if parent.exists() {
            break;
        }
        target = parent;
    }
    target.to_path_buf()
}

/// Empty files that `bwrap` left behind as mount points for `policy`'s
/// missing paths. Call before the command starts.
pub fn pending_mount_points(policy: &SandboxPolicy) -> Vec<PathBuf> {
    policy
        .hide
        .iter()
        .map(|hidden| &hidden.path)
        .chain(&policy.read_only)
        .filter(|path| !path.exists())
        .map(|path| mask_target(path))
        .collect()
}

/// Removes the mount points from [`pending_mount_points`] once the sandbox is
/// gone, so a missing `fnox.local.toml` does not appear as an empty file.
pub fn remove_mount_points(paths: &[PathBuf]) {
    for path in paths {
        if let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.is_file()
            && metadata.len() == 0
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Expands `~` and resolves a relative path against `cwd`.
fn expand(entry: &str, home: &Path, cwd: &Path) -> PathBuf {
    let path = if entry == "~" {
        home.to_path_buf()
    } else if let Some(rest) = entry.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(entry)
    };
    let path = if path.is_relative() {
        cwd.join(path)
    } else {
        path
    };
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Whether the sandbox's own `/tmp` or `/run` already hides `path`, so that it
/// is not worth (or possible) mounting over.
fn hidden_by_tmpfs(path: &Path, policy: &SandboxPolicy) -> bool {
    (path.starts_with("/tmp") || path.starts_with("/run"))
        && !policy
            .writable
            .iter()
            .chain(&policy.read_only)
            .any(|bound| path.starts_with(bound))
}

/// The `bwrap` arguments up to and including the command to run inside.
/// The `bwrap` flags that every sandbox starts with. The startup check uses
/// them too, so a machine that would reject one fails before secrets are
/// resolved.
const BASE_FLAGS: &[&str] = &[
    "--die-with-parent",
    // Without a session of its own the command could push keystrokes into the
    // terminal that started it.
    "--new-session",
    "--unshare-net",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run",
];

pub fn bwrap_args(
    policy: &SandboxPolicy,
    exe: &Path,
    socket: &Path,
    ca: &Path,
    command: &[String],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = BASE_FLAGS.iter().map(OsString::from).collect();
    let mut push = |parts: &[&std::ffi::OsStr]| args.extend(parts.iter().map(|p| p.to_os_string()));
    let s = |text: &'static str| std::ffi::OsStr::new(text);

    for path in &policy.writable {
        push(&[s("--bind"), path.as_os_str(), path.as_os_str()]);
    }
    for path in &policy.read_only {
        if path.exists() {
            push(&[s("--ro-bind"), path.as_os_str(), path.as_os_str()]);
        } else {
            push(&[
                s("--ro-bind"),
                s("/dev/null"),
                mask_target(path).as_os_str(),
            ]);
        }
    }
    let dir = Path::new(SANDBOX_DIR);
    let (bridge_exe, bridge_socket, bridge_ca) =
        (dir.join("fnox"), dir.join("proxy.sock"), dir.join("ca.pem"));
    push(&[s("--ro-bind"), exe.as_os_str(), bridge_exe.as_os_str()]);
    push(&[s("--bind"), socket.as_os_str(), bridge_socket.as_os_str()]);
    push(&[s("--ro-bind"), ca.as_os_str(), bridge_ca.as_os_str()]);
    for hidden in &policy.hide {
        if hidden_by_tmpfs(&hidden.path, policy) {
            continue;
        }
        if !hidden.path.exists() {
            push(&[
                s("--ro-bind"),
                s("/dev/null"),
                mask_target(&hidden.path).as_os_str(),
            ]);
        } else if hidden.is_dir {
            push(&[s("--tmpfs"), hidden.path.as_os_str()]);
        } else {
            push(&[s("--ro-bind"), s("/dev/null"), hidden.path.as_os_str()]);
        }
    }
    push(&[s("--chdir"), policy.cwd.as_os_str(), s("--")]);

    args.push(bridge_exe.into_os_string());
    args.extend(
        [
            "sandbox-bridge",
            "--port",
            &BRIDGE_PORT.to_string(),
            "--socket",
        ]
        .map(OsString::from),
    );
    args.push(bridge_socket.into_os_string());
    args.push("--".into());
    args.extend(command.iter().map(OsString::from));
    args
}

/// The seatbelt profile for `sandbox-exec`: everything is allowed except
/// network access (other than to `proxy_port` on this machine), writes
/// outside `policy.writable` and temporary directories, reads of hidden
/// paths, and launching apps through Launch Services (`open`), which would
/// start them outside the sandbox.
pub fn seatbelt_profile(policy: &SandboxPolicy, proxy_port: u16) -> String {
    let quote = |path: &Path| {
        let text = path.to_string_lossy();
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    };
    let mut profile =
        String::from("(version 1)\n(allow default)\n(deny network*)\n(deny lsopen)\n");
    profile.push_str(&format!(
        "(allow network-outbound (remote ip \"localhost:{proxy_port}\"))\n"
    ));
    profile.push_str("(deny file-write*)\n(allow file-write*\n");
    profile.push_str(
        "  (regex #\"^/dev/(null|zero|tty|ttys[0-9]+|dtracehelper|random|urandom|fd/[0-9]+)$\")\n",
    );
    for temp in ["/private/tmp", "/private/var/folders"] {
        profile.push_str(&format!("  (subpath \"{temp}\")\n"));
    }
    for path in &policy.writable {
        profile.push_str(&format!("  (subpath {})\n", quote(path)));
    }
    profile.push_str(")\n");
    for path in &policy.read_only {
        profile.push_str(&format!("(deny file-write* (subpath {}))\n", quote(path)));
    }
    for hidden in &policy.hide {
        let kind = if hidden.is_dir { "subpath" } else { "literal" };
        profile.push_str(&format!(
            "(deny file-read* file-write* ({kind} {}))\n",
            quote(&hidden.path)
        ));
    }
    profile
}

/// A command ready to start, and what the child needs to know about it.
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// The `HTTPS_PROXY` URL as the child sees it.
    pub proxy_url: String,
    /// The proxy's CA bundle as the child sees it.
    pub ca_path: PathBuf,
    /// Empty files the sandbox may leave behind; pass to
    /// [`remove_mount_points`] after the command exits.
    pub mount_points: Vec<PathBuf>,
}

/// A sandbox that has been checked to work on this machine.
pub struct Sandbox {
    policy: SandboxPolicy,
    #[cfg(target_os = "linux")]
    socket_dir: tempfile::TempDir,
}

impl Sandbox {
    /// Fails unless the platform's sandbox tool is present and works.
    pub fn prepare(policy: SandboxPolicy) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            check_bwrap()?;
            let socket_dir = tempfile::Builder::new()
                .prefix("fnox-sandbox-")
                .tempdir()
                .map_err(|error| {
                    FnoxError::Config(format!("failed to create the sandbox directory: {error}"))
                })?;
            Ok(Self { policy, socket_dir })
        }
        #[cfg(target_os = "macos")]
        {
            if !Path::new(SANDBOX_EXEC).exists() {
                return Err(FnoxError::Config(format!(
                    "the sandbox needs {SANDBOX_EXEC}, which was not found"
                )));
            }
            Ok(Self { policy })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = policy;
            Err(FnoxError::Config(
                "the proxy sandbox is only supported on Linux and macOS".to_string(),
            ))
        }
    }

    /// How the proxy should accept the sandboxed command's connections.
    pub fn listener(&self) -> ProxyListener {
        #[cfg(target_os = "linux")]
        {
            ProxyListener::Unix(self.socket_dir.path().join("proxy.sock"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            ProxyListener::Loopback
        }
    }

    /// Wraps `command` so it runs inside the sandbox.
    pub fn launch(&self, running: &RunningProxy, command: &[String]) -> Result<Launch> {
        #[cfg(target_os = "linux")]
        {
            let exe = env::current_exe().map_err(|error| {
                FnoxError::Config(format!("failed to locate the fnox executable: {error}"))
            })?;
            let socket = self.socket_dir.path().join("proxy.sock");
            let args = bwrap_args(&self.policy, &exe, &socket, running.ca_path(), command);
            let bridge: std::net::SocketAddr = ([127, 0, 0, 1], BRIDGE_PORT).into();
            Ok(Launch {
                program: "bwrap".into(),
                args,
                proxy_url: running.session_url(bridge),
                ca_path: Path::new(SANDBOX_DIR).join("ca.pem"),
                mount_points: pending_mount_points(&self.policy),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let address = running
                .local_addr()
                .expect("a loopback proxy has an address");
            let mut args = vec![
                OsString::from("-p"),
                OsString::from(seatbelt_profile(&self.policy, address.port())),
            ];
            args.extend(command.iter().map(OsString::from));
            Ok(Launch {
                program: SANDBOX_EXEC.into(),
                args,
                proxy_url: running
                    .proxy_url()
                    .expect("a loopback proxy has a proxy URL"),
                ca_path: running.ca_path().to_path_buf(),
                mount_points: Vec::new(),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (running, command);
            unreachable!("prepare fails on this platform")
        }
    }
}

#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Runs a throwaway command in a sandbox with the flags the real one uses, so
/// a machine that forbids user namespaces is reported before secrets are
/// resolved.
#[cfg(target_os = "linux")]
fn check_bwrap() -> Result<()> {
    let exe = env::current_exe().map_err(|error| {
        FnoxError::Config(format!("failed to locate the fnox executable: {error}"))
    })?;
    let bridge_exe = Path::new(SANDBOX_DIR).join("fnox");
    let output = std::process::Command::new("bwrap")
        .args(BASE_FLAGS)
        // Bound in as the real launch does, since the tmpfs on /tmp and /run
        // would hide a binary that lives there.
        .arg("--ro-bind")
        .arg(&exe)
        .arg(&bridge_exe)
        .arg("--")
        .arg(&bridge_exe)
        .arg("--version")
        .output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(FnoxError::Config(format!(
            "the sandbox could not start: {}. bwrap needs unprivileged user namespaces; \
             see https://fnox.jdx.dev/guide/proxy#sandbox",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(FnoxError::Config(
            "the sandbox needs `bwrap` (bubblewrap) on PATH; install the bubblewrap package"
                .to_string(),
        )),
        Err(error) => Err(FnoxError::Config(format!("failed to run bwrap: {error}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_in(root: &Path, config: &ProxyConfig) -> SandboxPolicy {
        let home = root.join("home");
        let cwd = root.join("project");
        for dir in [".ssh", ".config/fnox", ".aws"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::create_dir_all(cwd.join(".git/hooks")).unwrap();
        std::fs::write(cwd.join("fnox.toml"), "").unwrap();
        std::fs::write(cwd.join(".git/config"), "").unwrap();
        std::fs::write(home.join(".config/fnox/age.txt"), "").unwrap();
        SandboxPolicy::build(PolicyInputs {
            cwd: std::fs::canonicalize(&cwd).unwrap(),
            home: std::fs::canonicalize(&home).unwrap(),
            fnox_dirs: vec![home.join(".config/fnox"), home.join("missing")],
            fnox_files: vec![cwd.join("fnox.toml"), home.join(".config/fnox/age.txt")],
            environment: Vec::new(),
            config,
        })
    }

    fn hidden(policy: &SandboxPolicy) -> Vec<String> {
        policy
            .hide
            .iter()
            .map(|hidden| {
                hidden
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn hides_fnox_state_and_credentials_that_exist() {
        let root = tempfile::tempdir().unwrap();
        let policy = policy_in(root.path(), &ProxyConfig::default());
        // `age.txt` is inside the hidden `fnox` directory, and `missing` and
        // `.kube` do not exist.
        assert_eq!(hidden(&policy), [".aws", "fnox", ".ssh", "fnox.toml"]);
        let fnox = policy
            .hide
            .iter()
            .find(|h| h.path.ends_with("fnox"))
            .unwrap();
        assert!(fnox.is_dir);
    }

    #[test]
    fn allow_read_unhides_a_path_and_what_it_contains() {
        let root = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            sandbox_allow_read: vec!["fnox.toml".to_string(), "~/.aws".to_string()],
            ..ProxyConfig::default()
        };
        let policy = policy_in(root.path(), &config);
        assert_eq!(hidden(&policy), ["fnox", ".ssh"]);
    }

    #[test]
    fn deny_read_and_allow_write_resolve_relative_to_the_project() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("project/secrets")).unwrap();
        std::fs::create_dir_all(root.path().join("home/.cache")).unwrap();
        let config = ProxyConfig {
            sandbox_deny_read: vec!["secrets".to_string()],
            sandbox_allow_write: vec!["~/.cache".to_string(), "~/missing".to_string()],
            ..ProxyConfig::default()
        };
        let policy = policy_in(root.path(), &config);
        assert!(hidden(&policy).contains(&"secrets".to_string()));
        assert_eq!(policy.writable.len(), 2);
        assert!(policy.writable[1].ends_with("home/.cache"));
    }

    #[test]
    fn git_hooks_and_config_are_read_only() {
        let root = tempfile::tempdir().unwrap();
        let policy = policy_in(root.path(), &ProxyConfig::default());
        assert_eq!(policy.read_only.len(), 2);
        assert!(
            policy
                .read_only
                .iter()
                .all(|path| path.starts_with(&policy.cwd))
        );
    }

    /// A policy for a project directory inside `root`; `root` also holds the
    /// home directory, which is therefore outside the writable project.
    fn project(root: &Path, fnox_files: &[&str], config: &ProxyConfig) -> SandboxPolicy {
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        let cwd = std::fs::canonicalize(root.join("project")).unwrap();
        SandboxPolicy::build(PolicyInputs {
            cwd: cwd.clone(),
            home: std::fs::canonicalize(root.join("home")).unwrap(),
            fnox_dirs: Vec::new(),
            fnox_files: fnox_files.iter().map(|file| cwd.join(file)).collect(),
            environment: Vec::new(),
            config,
        })
    }

    #[test]
    fn config_files_that_do_not_exist_yet_cannot_be_created() {
        let root = tempfile::tempdir().unwrap();
        let policy = project(
            root.path(),
            &["fnox.local.toml", ".config/fnox.toml"],
            &ProxyConfig::default(),
        );
        assert_eq!(hidden(&policy), ["fnox.toml", "fnox.local.toml"]);
        let args = argv(&policy);
        let local = policy
            .cwd
            .join("fnox.local.toml")
            .to_string_lossy()
            .to_string();
        // `.config` is missing too, so it is what gets masked.
        let config_dir = policy.cwd.join(".config").to_string_lossy().to_string();
        assert!(position(&args, &["--ro-bind", "/dev/null", &local]).is_some());
        assert!(position(&args, &["--ro-bind", "/dev/null", &config_dir]).is_some());
        let pending = pending_mount_points(&policy);
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&policy.cwd.join(".config")));
    }

    #[test]
    fn missing_paths_outside_writable_locations_are_skipped() {
        let root = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(root.path()).unwrap();
        let policy = SandboxPolicy::build(PolicyInputs {
            cwd: cwd.clone(),
            home: PathBuf::from("/nonexistent-fnox-test/home"),
            fnox_dirs: Vec::new(),
            fnox_files: vec![PathBuf::from("/nonexistent-fnox-test/fnox.toml")],
            environment: Vec::new(),
            config: &ProxyConfig::default(),
        });
        assert!(policy.hide.is_empty());
    }

    #[test]
    fn git_hooks_are_protected_before_they_exist() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("project/.git")).unwrap();
        let policy = project(root.path(), &[], &ProxyConfig::default());
        assert_eq!(policy.read_only.len(), 2);
        let hooks = policy.cwd.join(".git/hooks").to_string_lossy().to_string();
        assert!(position(&argv(&policy), &["--ro-bind", "/dev/null", &hooks]).is_some());
        // Without a repository there is nothing to protect.
        let bare = tempfile::tempdir().unwrap();
        assert!(
            project(bare.path(), &[], &ProxyConfig::default())
                .read_only
                .is_empty()
        );
    }

    #[test]
    fn unhidden_files_in_the_project_stay_read_only() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("project")).unwrap();
        std::fs::write(root.path().join("project/fnox.toml"), "").unwrap();
        let config = ProxyConfig {
            sandbox_allow_read: vec!["fnox.toml".to_string()],
            ..ProxyConfig::default()
        };
        let policy = project(root.path(), &["fnox.toml"], &config);
        assert!(policy.hide.is_empty());
        assert_eq!(policy.read_only, [policy.cwd.join("fnox.toml")]);
    }

    #[cfg(unix)]
    #[test]
    fn allow_read_follows_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("project")).unwrap();
        std::fs::write(root.path().join("project/real.toml"), "").unwrap();
        std::os::unix::fs::symlink("real.toml", root.path().join("project/link.toml")).unwrap();
        let config = ProxyConfig {
            sandbox_allow_read: vec!["link.toml".to_string()],
            ..ProxyConfig::default()
        };
        let policy = project(root.path(), &["real.toml"], &config);
        assert!(policy.hide.is_empty());
    }

    #[test]
    fn provider_key_files_are_collected() {
        let config: Config = toml_edit::de::from_str(
            r#"
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
key_file = "/keys/private-age.txt"
"#,
        )
        .unwrap();
        let files = provider_key_files(&config, &[], Path::new("/work")).unwrap();
        assert_eq!(files, [PathBuf::from("/keys/private-age.txt")]);
    }

    #[test]
    fn a_missing_file_that_is_allowed_to_be_read_cannot_be_created() {
        let root = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            sandbox_allow_read: vec!["fnox.local.toml".to_string()],
            ..ProxyConfig::default()
        };
        let policy = project(root.path(), &["fnox.local.toml"], &config);
        assert!(policy.hide.is_empty());
        assert_eq!(policy.read_only, [policy.cwd.join("fnox.local.toml")]);
        let local = policy
            .cwd
            .join("fnox.local.toml")
            .to_string_lossy()
            .to_string();
        assert!(position(&argv(&policy), &["--ro-bind", "/dev/null", &local]).is_some());
    }

    #[test]
    fn a_key_file_that_is_not_a_path_is_an_error() {
        let config: Config = toml_edit::de::from_str(
            r#"
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
key_file = { secret = "AGE_KEY_PATH" }
"#,
        )
        .unwrap();
        let error = provider_key_files(&config, &[], Path::new("/work")).unwrap_err();
        assert!(error.to_string().contains("key_file"), "{error}");
    }

    #[test]
    fn only_empty_mount_points_are_removed() {
        let root = tempfile::tempdir().unwrap();
        let empty = root.path().join("empty");
        let kept = root.path().join("kept");
        std::fs::write(&empty, "").unwrap();
        std::fs::write(&kept, "data").unwrap();
        remove_mount_points(&[empty.clone(), kept.clone(), root.path().join("gone")]);
        assert!(!empty.exists());
        assert!(kept.exists());
    }

    fn argv(policy: &SandboxPolicy) -> Vec<String> {
        bwrap_args(
            policy,
            Path::new("/usr/bin/fnox"),
            Path::new("/tmp/fnox-sandbox-x/proxy.sock"),
            Path::new("/tmp/fnox-proxy-ca.pem"),
            &["node".to_string(), "agent.js".to_string()],
        )
        .into_iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect()
    }

    fn position(args: &[String], window: &[&str]) -> Option<usize> {
        args.windows(window.len())
            .position(|candidate| candidate == window)
    }

    #[test]
    fn bwrap_isolates_and_runs_the_bridge() {
        let root = tempfile::tempdir().unwrap();
        let policy = policy_in(root.path(), &ProxyConfig::default());
        let args = argv(&policy);
        for flag in [
            "--unshare-net",
            "--unshare-pid",
            "--new-session",
            "--die-with-parent",
        ] {
            assert!(args.contains(&flag.to_string()), "missing {flag}");
        }
        let cwd = policy.cwd.to_string_lossy().to_string();
        assert!(position(&args, &["--bind", &cwd, &cwd]).is_some());
        assert!(position(&args, &["--tmpfs", "/run"]).is_some());
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            args[separator + 1..],
            [
                "/tmp/.fnox-sandbox/fnox",
                "sandbox-bridge",
                "--port",
                "18099",
                "--socket",
                "/tmp/.fnox-sandbox/proxy.sock",
                "--",
                "node",
                "agent.js"
            ]
        );
    }

    #[test]
    fn bwrap_masks_come_after_the_writable_binds() {
        let root = tempfile::tempdir().unwrap();
        let policy = policy_in(root.path(), &ProxyConfig::default());
        let args = argv(&policy);
        let cwd = policy.cwd.to_string_lossy().to_string();
        let bind = position(&args, &["--bind", &cwd, &cwd]).unwrap();
        let config = policy.cwd.join("fnox.toml").to_string_lossy().to_string();
        let mask = position(&args, &["--ro-bind", "/dev/null", &config]).unwrap();
        assert!(mask > bind, "fnox.toml must be masked after cwd is bound");
    }

    #[test]
    fn paths_the_sandbox_tmpfs_already_hides_are_not_mounted_over() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("fnox.toml"), "").unwrap();
        let policy = SandboxPolicy {
            cwd: PathBuf::from("/work"),
            hide: vec![
                HiddenPath {
                    path: PathBuf::from("/run/user/1000"),
                    is_dir: true,
                },
                HiddenPath {
                    path: project.join("fnox.toml"),
                    is_dir: false,
                },
            ],
            writable: vec![project.clone()],
            read_only: Vec::new(),
        };
        let args = argv(&policy);
        assert!(position(&args, &["--tmpfs", "/run/user/1000"]).is_none());
        // Inside a bound path the mask is still needed.
        let config = project.join("fnox.toml").to_string_lossy().to_string();
        assert!(position(&args, &["--ro-bind", "/dev/null", &config]).is_some());
    }

    #[test]
    fn seatbelt_profile_limits_network_writes_and_reads() {
        let policy = SandboxPolicy {
            cwd: PathBuf::from("/work"),
            hide: vec![
                HiddenPath {
                    path: PathBuf::from("/Users/me/.ssh"),
                    is_dir: true,
                },
                HiddenPath {
                    path: PathBuf::from("/work/fnox.toml"),
                    is_dir: false,
                },
            ],
            writable: vec![PathBuf::from("/work"), PathBuf::from("/odd\"dir")],
            read_only: vec![PathBuf::from("/work/.git/hooks")],
        };
        let profile = seatbelt_profile(&policy, 4242);
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(deny lsopen)"));
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:4242\"))"));
        assert!(profile.contains("(subpath \"/work\")"));
        assert!(profile.contains("(subpath \"/odd\\\"dir\")"));
        assert!(profile.contains("(deny file-write* (subpath \"/work/.git/hooks\"))"));
        assert!(profile.contains("(deny file-read* file-write* (subpath \"/Users/me/.ssh\"))"));
        assert!(profile.contains("(deny file-read* file-write* (literal \"/work/fnox.toml\"))"));
        // Later rules win, so the denies must follow the write allowance.
        assert!(
            profile.find("(allow file-write*").unwrap() < profile.find("(deny file-read*").unwrap()
        );
    }
}
