//! Where a daemon's socket lives, and which daemon serves which invocation.

use crate::WIRE_VERSION;
use crate::profile;
use std::io;
use std::path::{Path, PathBuf};

/// The socket file name, after the 16-hex-digit key hash and a dash.
pub const SOCKET_NAME: &str = "fnoxd.sock";

/// The flags of an `fnox` invocation that decide which daemon serves it.
#[derive(Clone, Debug, Default)]
pub struct CliFlags {
    /// `-P/--profile` values, repeated or comma-separated.
    pub profile: Vec<String>,
    /// `--no-defaults`.
    pub no_defaults: bool,
    /// `--if-missing <VALUE>`.
    pub if_missing: Option<String>,
}

impl CliFlags {
    /// The arguments to put before the subcommand: `-P p` for each profile,
    /// `--no-defaults`, `--if-missing v`.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for profile in &self.profile {
            args.push("-P".to_string());
            args.push(profile.clone());
        }
        if self.no_defaults {
            args.push("--no-defaults".to_string());
        }
        if let Some(if_missing) = &self.if_missing {
            args.push("--if-missing".to_string());
            args.push(if_missing.clone());
        }
        args
    }
}

/// What picks the daemon: the settings its cache was filled under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketKey {
    profile: Vec<String>,
    no_defaults: bool,
    if_missing: Option<String>,
    age_key_file: Option<PathBuf>,
}

impl SocketKey {
    /// `profile` is normalized: split on commas, trimmed, invalid names
    /// dropped, and empty becomes `["default"]`.
    pub fn new(
        profile: &[String],
        no_defaults: bool,
        if_missing: Option<String>,
        age_key_file: Option<PathBuf>,
    ) -> Self {
        Self {
            profile: profile::normalize(profile),
            no_defaults,
            if_missing,
            age_key_file,
        }
    }

    /// What `fnox <flags.to_args()>` resolves given the environment `get`
    /// reads, mirroring how the fnox CLI builds its settings:
    ///
    /// - profile: the flags, else `FNOX_PROFILE`, else `["default"]`;
    /// - no_defaults: the flag, or `FNOX_NO_DEFAULTS` set to a true word
    ///   (`1`, `true`, `yes`, `y`, `on`, in any case);
    /// - if_missing: the flag, else `FNOX_IF_MISSING`;
    /// - age key file: `FNOX_AGE_KEY_FILE`, with a leading `~` expanded from
    ///   `HOME` in the same environment.
    pub fn from_cli_env(flags: &CliFlags, get: &dyn Fn(&str) -> Option<String>) -> Self {
        let profile = if flags.profile.is_empty() {
            get("FNOX_PROFILE")
                .map(|value| vec![value])
                .unwrap_or_default()
        } else {
            flags.profile.clone()
        };
        let no_defaults =
            flags.no_defaults || get("FNOX_NO_DEFAULTS").is_some_and(|value| is_true_word(&value));
        let if_missing = flags.if_missing.clone().or_else(|| get("FNOX_IF_MISSING"));
        let age_key_file = get("FNOX_AGE_KEY_FILE").map(|value| expand_tilde(&value, get));
        Self::new(&profile, no_defaults, if_missing, age_key_file)
    }

    pub(crate) fn no_defaults(&self) -> bool {
        self.no_defaults
    }

    pub(crate) fn if_missing(&self) -> Option<&str> {
        self.if_missing.as_deref()
    }

    pub(crate) fn age_key_file(&self) -> Option<&Path> {
        self.age_key_file.as_deref()
    }

    /// The normalized profile list.
    pub fn profile(&self) -> &[String] {
        &self.profile
    }

    /// The socket a daemon for this key listens on.
    pub fn socket_path(&self, rt: &RuntimeEnv) -> PathBuf {
        fn field(hasher: &mut blake3::Hasher, s: &[u8]) {
            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s);
        }
        fn opt(hasher: &mut blake3::Hasher, s: Option<&str>) {
            match s {
                None => {
                    hasher.update(&[0]);
                }
                Some(s) => {
                    hasher.update(&[1]);
                    field(hasher, s.as_bytes());
                }
            }
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fnoxd-socket\0");
        hasher.update(&[WIRE_VERSION]);
        field(&mut hasher, self.profile.join(",").as_bytes());
        field(&mut hasher, if self.no_defaults { b"1" } else { b"0" });
        opt(&mut hasher, self.if_missing.as_deref());
        let age_key_file = self
            .age_key_file
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned());
        opt(&mut hasher, age_key_file.as_deref());
        runtime_dir(rt).join(format!(
            "{}-{}",
            &hasher.finalize().to_hex()[..16],
            SOCKET_NAME
        ))
    }
}

/// The words usage-rs reads as true for a boolean setting. Anything else is
/// false here; fnox itself fails to resolve its settings for an unrecognized
/// word.
fn is_true_word(value: &str) -> bool {
    value == "1"
        || ["true", "yes", "y", "on"]
            .iter()
            .any(|word| value.eq_ignore_ascii_case(word))
}

/// Expands a leading `~` the way `shellexpand::tilde` does, by string
/// concatenation, so the socket hash sees the same bytes as fnox's.
fn expand_tilde(path: &str, get: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    match (
        path.strip_prefix('~'),
        get("HOME").filter(|h| !h.is_empty()),
    ) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            PathBuf::from(format!("{home}{rest}"))
        }
        _ => PathBuf::from(path),
    }
}

/// What decides the runtime directory.
#[derive(Clone, Debug)]
pub struct RuntimeEnv {
    /// `XDG_RUNTIME_DIR`; empty counts as unset.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// The temporary directory: `TMPDIR`, else what std uses when it is
    /// absent (on Apple, the per-user directory from `confstr`).
    pub tmpdir: PathBuf,
    /// The effective user id.
    pub euid: u32,
}

impl RuntimeEnv {
    /// From this process: its environment and `std::env::temp_dir()`.
    pub fn from_process() -> Self {
        Self {
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR")
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from),
            tmpdir: std::env::temp_dir(),
            euid: process_euid(),
        }
    }

    /// From the environment `get` reads, which a daemon started under that
    /// environment would have seen. `TMPDIR` falls back to what std uses when
    /// it is absent.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Self {
        Self {
            xdg_runtime_dir: get("XDG_RUNTIME_DIR")
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from),
            tmpdir: get("TMPDIR")
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(default_tmpdir),
            euid: process_euid(),
        }
    }
}

/// What std uses when `TMPDIR` is absent: on Apple, the per-user directory
/// from `confstr`; elsewhere `/tmp` (`/data/local/tmp` on Android).
#[cfg(target_vendor = "apple")]
fn default_tmpdir() -> PathBuf {
    darwin_user_temp_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(not(target_vendor = "apple"))]
fn default_tmpdir() -> PathBuf {
    if cfg!(target_os = "android") {
        PathBuf::from("/data/local/tmp")
    } else if cfg!(windows) {
        std::env::temp_dir()
    } else {
        PathBuf::from("/tmp")
    }
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`, as std reads it, trailing `/` included.
/// Not `std::env::temp_dir()`, which would read this process's `TMPDIR`.
#[cfg(target_vendor = "apple")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    loop {
        // SAFETY: the pointer and capacity describe `buf`'s allocation.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.capacity(),
            )
        };
        if n == 0 {
            return None;
        }
        if n <= buf.capacity() {
            // SAFETY: confstr wrote `n` bytes, the last being the NUL.
            unsafe { buf.set_len(n - 1) };
            return Some(PathBuf::from(OsString::from_vec(buf)));
        }
        buf.reserve(n);
    }
}

fn process_euid() -> u32 {
    #[cfg(unix)]
    {
        crate::peer::current_euid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// The directory daemon sockets live in: `$XDG_RUNTIME_DIR/fnox`, else
/// `<tmpdir>/fnox-<euid>/fnox`. A base that would make the socket path too
/// long for `sun_path` moves to `/tmp/fnox-<euid>/<hash of base>/fnox`.
pub fn runtime_dir(rt: &RuntimeEnv) -> PathBuf {
    let base = rt
        .xdg_runtime_dir
        .clone()
        .unwrap_or_else(|| rt.tmpdir.join(format!("fnox-{}", rt.euid)));
    let dir = base.join("fnox");
    if socket_path_fits(&dir) {
        return dir;
    }

    let digest = blake3::hash(base.to_string_lossy().as_bytes()).to_hex();
    PathBuf::from("/tmp")
        .join(format!("fnox-{}", rt.euid))
        .join(&digest[..8])
        .join("fnox")
}

fn socket_path_fits(dir: &Path) -> bool {
    let socket_name_len = 16 + 1 + SOCKET_NAME.len();
    dir.to_string_lossy().len() + 1 + socket_name_len < 100
}

/// Every daemon socket in the runtime directory, sorted. Empty when the
/// directory does not exist.
pub fn daemon_socket_paths(rt: &RuntimeEnv) -> io::Result<Vec<PathBuf>> {
    let dir = runtime_dir(rt);
    let read_error = |e: io::Error| {
        io::Error::new(
            e.kind(),
            format!("Failed to read daemon runtime dir {}: {e}", dir.display()),
        )
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(read_error(e)),
    };

    let suffix = format!("-{SOCKET_NAME}");
    let expected_len = 16 + suffix.len();
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(read_error)?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.len() == expected_len && name.ends_with(&suffix) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn rt() -> RuntimeEnv {
        RuntimeEnv {
            xdg_runtime_dir: Some(PathBuf::from("/run/user/1000")),
            tmpdir: PathBuf::from("/tmp"),
            euid: 1000,
        }
    }

    fn key(profile: &[&str]) -> SocketKey {
        SocketKey::new(&s(profile), false, None, None)
    }

    fn name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn socket_path_is_pinned() {
        let dir = "/run/user/1000/fnox";
        let sock = |k: SocketKey| k.socket_path(&rt()).to_string_lossy().into_owned();
        assert_eq!(
            sock(key(&["default"])),
            format!("{dir}/c52edaa4e3e0612e-fnoxd.sock")
        );
        assert_eq!(
            sock(key(&["dev", "prod"])),
            format!("{dir}/719875940e90eaab-fnoxd.sock")
        );
        assert_eq!(
            sock(SocketKey::new(&s(&["default"]), true, None, None)),
            format!("{dir}/47ccb2a523dfa157-fnoxd.sock")
        );
        assert_eq!(
            sock(SocketKey::new(
                &s(&["default"]),
                false,
                Some("x".into()),
                None
            )),
            format!("{dir}/8693d140ff5d910d-fnoxd.sock")
        );
        assert_eq!(
            sock(SocketKey::new(
                &s(&["default"]),
                false,
                None,
                Some("x".into())
            )),
            format!("{dir}/cbf74949680cfa3c-fnoxd.sock")
        );
    }

    // The preimage, spelled out byte by byte, as the protocol documents it.
    #[test]
    fn socket_hash_preimage_layout() {
        let mut pre = Vec::new();
        pre.extend_from_slice(b"fnoxd-socket\0");
        pre.push(6);
        pre.extend_from_slice(&7u64.to_le_bytes());
        pre.extend_from_slice(b"default");
        pre.extend_from_slice(&1u64.to_le_bytes());
        pre.extend_from_slice(b"0");
        pre.push(1);
        pre.extend_from_slice(&1u64.to_le_bytes());
        pre.extend_from_slice(b"x");
        pre.push(0);
        let want = &blake3::hash(&pre).to_hex()[..16];
        let k = SocketKey::new(&s(&["default"]), false, Some("x".into()), None);
        assert_eq!(name(&k.socket_path(&rt())), format!("{want}-fnoxd.sock"));
    }

    #[test]
    fn empty_xdg_is_unset() {
        let env = |xdg: &'static str| {
            RuntimeEnv::from_env(&move |k| match k {
                "XDG_RUNTIME_DIR" => Some(xdg.to_string()),
                "TMPDIR" => Some("/var/tmp".to_string()),
                _ => None,
            })
        };
        let empty = env("");
        assert_eq!(empty.xdg_runtime_dir, None);
        assert_eq!(
            runtime_dir(&RuntimeEnv { euid: 7, ..empty }),
            PathBuf::from("/var/tmp/fnox-7/fnox")
        );
        assert_eq!(
            runtime_dir(&RuntimeEnv {
                euid: 7,
                ..env("/run/user/7")
            }),
            PathBuf::from("/run/user/7/fnox")
        );
    }

    #[test]
    fn tmpdir_defaults_like_std_when_absent() {
        let rt = RuntimeEnv::from_env(&|_| None);
        assert_eq!(rt.xdg_runtime_dir, None);
        #[cfg(target_vendor = "apple")]
        {
            let out = std::process::Command::new("/usr/bin/getconf")
                .arg("DARWIN_USER_TEMP_DIR")
                .output()
                .unwrap();
            let want = String::from_utf8(out.stdout).unwrap();
            assert_eq!(rt.tmpdir, PathBuf::from(want.trim()));
            assert_ne!(rt.tmpdir, PathBuf::from("/tmp"));
        }
        #[cfg(all(unix, not(target_vendor = "apple"), not(target_os = "android")))]
        assert_eq!(rt.tmpdir, PathBuf::from("/tmp"));
        if std::env::var_os("TMPDIR").is_none() && !cfg!(windows) {
            assert_eq!(rt.tmpdir, std::env::temp_dir());
        }
    }

    #[test]
    fn long_base_falls_back_to_a_short_hashed_dir() {
        let long = format!("/{}", "x".repeat(120));
        let rt = RuntimeEnv {
            xdg_runtime_dir: Some(PathBuf::from(&long)),
            tmpdir: PathBuf::from("/tmp"),
            euid: 1000,
        };
        let dir = runtime_dir(&rt);
        let digest = blake3::hash(long.as_bytes()).to_hex();
        assert_eq!(
            dir,
            PathBuf::from(format!("/tmp/fnox-1000/{}/fnox", &digest[..8]))
        );
        assert_eq!(dir, PathBuf::from("/tmp/fnox-1000/573cebf8/fnox"));
        assert!(socket_path_fits(&dir));
        assert_eq!(
            key(&["default"]).socket_path(&rt).parent().unwrap(),
            dir.as_path()
        );
    }

    #[test]
    fn every_input_changes_the_socket() {
        let base = key(&["default"]).socket_path(&rt());
        let all = [
            SocketKey::new(&s(&["prod"]), false, None, None),
            SocketKey::new(&s(&["default"]), true, None, None),
            SocketKey::new(&s(&["default"]), false, Some("x".into()), None),
            SocketKey::new(&s(&["default"]), false, None, Some("x".into())),
        ];
        let mut seen = vec![name(&base)];
        for k in &all {
            let n = name(&k.socket_path(&rt()));
            assert!(!seen.contains(&n), "{n} collides");
            seen.push(n);
        }
    }

    #[test]
    fn if_missing_and_age_key_file_do_not_collide() {
        let a = SocketKey::new(&s(&["default"]), false, Some("x".into()), None);
        let b = SocketKey::new(&s(&["default"]), false, None, Some("x".into()));
        assert_ne!(a.socket_path(&rt()), b.socket_path(&rt()));
    }

    #[test]
    fn profiles_are_normalized() {
        assert_eq!(key(&["dev, prod"]), key(&["dev", "prod"]));
        assert_eq!(
            key(&["dev, prod"]).socket_path(&rt()),
            key(&["dev", "prod"]).socket_path(&rt())
        );
        assert_eq!(key(&["../bad", "ok"]).profile(), ["ok"]);
        assert_eq!(key(&["../bad"]), key(&["default"]));
        assert_eq!(key(&[]).profile(), ["default"]);
    }

    #[test]
    fn fields_are_length_prefixed() {
        // Without prefixes, profile "a" + no_defaults "1" and profile "a1" + ... could collide.
        let a = SocketKey::new(&s(&["a"]), true, None, None);
        let b = SocketKey::new(&s(&["a1"]), false, None, None);
        assert_ne!(a.socket_path(&rt()), b.socket_path(&rt()));
    }

    #[test]
    fn cli_flags_to_args() {
        let flags = CliFlags {
            profile: s(&["dev", "prod"]),
            no_defaults: true,
            if_missing: Some("warn".to_string()),
        };
        assert_eq!(
            flags.to_args(),
            s(&[
                "-P",
                "dev",
                "-P",
                "prod",
                "--no-defaults",
                "--if-missing",
                "warn"
            ])
        );
        assert!(CliFlags::default().to_args().is_empty());
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn from_cli_env_reads_the_environment() {
        let env = env_of(&[
            ("FNOX_PROFILE", "staging, prod"),
            ("FNOX_NO_DEFAULTS", "TRUE"),
            ("FNOX_IF_MISSING", "ignore"),
            ("FNOX_AGE_KEY_FILE", "~/k"),
            ("HOME", "/h"),
        ]);
        let key = SocketKey::from_cli_env(&CliFlags::default(), &env);
        assert_eq!(
            key,
            SocketKey::new(
                &s(&["staging", "prod"]),
                true,
                Some("ignore".into()),
                Some(PathBuf::from("/h/k"))
            )
        );
    }

    #[test]
    fn cli_profile_wins_over_fnox_profile() {
        let env = env_of(&[("FNOX_PROFILE", "env")]);
        let flags = CliFlags {
            profile: s(&["cli"]),
            ..CliFlags::default()
        };
        assert_eq!(SocketKey::from_cli_env(&flags, &env).profile(), ["cli"]);
        assert_eq!(
            SocketKey::from_cli_env(&CliFlags::default(), &env).profile(),
            ["env"]
        );
    }

    #[test]
    fn flags_round_trip_through_to_args_and_from_cli_env() {
        let flags = CliFlags {
            profile: s(&["a", "b"]),
            no_defaults: true,
            if_missing: Some("error".to_string()),
        };
        let from_flags = SocketKey::from_cli_env(&flags, &env_of(&[]));
        // The same invocation, spelled as the environment instead of as flags.
        let from_env = SocketKey::from_cli_env(
            &CliFlags::default(),
            &env_of(&[
                ("FNOX_PROFILE", "a,b"),
                ("FNOX_NO_DEFAULTS", "1"),
                ("FNOX_IF_MISSING", "error"),
            ]),
        );
        assert_eq!(from_flags, from_env);
        assert_eq!(flags.to_args().len(), 7);
    }

    #[test]
    fn tilde_expands_only_a_leading_tilde_with_a_home() {
        let env = env_of(&[("HOME", "/h")]);
        assert_eq!(expand_tilde("~", &env), PathBuf::from("/h"));
        assert_eq!(expand_tilde("~/k", &env), PathBuf::from("/h/k"));
        assert_eq!(expand_tilde("~other/k", &env), PathBuf::from("~other/k"));
        assert_eq!(expand_tilde("/a/~/k", &env), PathBuf::from("/a/~/k"));
        assert_eq!(expand_tilde("~/k", &env_of(&[])), PathBuf::from("~/k"));
        // Concatenation, not path joining: a trailing slash in HOME survives.
        let slash = env_of(&[("HOME", "/h/")]);
        assert_eq!(expand_tilde("~/k", &slash), PathBuf::from("/h//k"));
        assert_eq!(expand_tilde("~", &slash), PathBuf::from("/h/"));
    }

    #[test]
    fn tilde_matches_shellexpand() {
        for home in ["/h", "/h/", "/h//"] {
            let pairs = [("HOME", home)];
            let env = env_of(&pairs);
            for path in ["~", "~/k", "~other/k", "/a/k"] {
                let want = shellexpand::tilde_with_context(path, || Some(home)).into_owned();
                assert_eq!(
                    expand_tilde(path, &env),
                    PathBuf::from(want),
                    "{home} {path}"
                );
            }
        }
    }

    #[test]
    fn true_words() {
        for word in ["1", "true", "TRUE", "True", "yes", "y", "on", "ON"] {
            assert!(is_true_word(word), "{word}");
        }
        for word in ["0", "false", "no", "n", "off", "", "maybe", " 1"] {
            assert!(!is_true_word(word), "{word:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_paths_lists_only_daemon_sockets_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = RuntimeEnv {
            xdg_runtime_dir: Some(tmp.path().to_path_buf()),
            tmpdir: PathBuf::from("/tmp"),
            euid: 1,
        };
        assert!(daemon_socket_paths(&rt).unwrap().is_empty());
        let dir = tmp.path().join("fnox");
        std::fs::create_dir_all(&dir).unwrap();
        for file in [
            "bbbbbbbbbbbbbbbb-fnoxd.sock",
            "aaaaaaaaaaaaaaaa-fnoxd.sock",
            "short-fnoxd.sock",
            "other.txt",
        ] {
            std::fs::write(dir.join(file), "").unwrap();
        }
        let names: Vec<_> = daemon_socket_paths(&rt)
            .unwrap()
            .iter()
            .map(|p| name(p))
            .collect();
        assert_eq!(
            names,
            ["aaaaaaaaaaaaaaaa-fnoxd.sock", "bbbbbbbbbbbbbbbb-fnoxd.sock"]
        );
    }
}
