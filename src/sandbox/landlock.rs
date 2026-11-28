//! The `landlock` sandbox: Landlock and a seccomp filter, with no namespaces.
//!
//! `bwrap` needs unprivileged user namespaces, which many machines forbid,
//! Docker's default seccomp profile among them. This sandbox only asks the
//! kernel to restrict the command, which any process may do:
//!
//! - **Files**: Landlock. The command may read everything but the hidden
//!   paths, `/tmp`, `/run` and `/dev/shm`, and may write only a private
//!   temporary directory, `sandbox_allow_write` and a few devices. Landlock
//!   can only grant access, so it could not keep a writable working directory's
//!   `fnox.toml` or `.git/hooks` from being replaced; the working directory is
//!   therefore read-only, and a writable path that contains a protected one is
//!   an error.
//! - **Network**: every `connect()` stops in a seccomp user notification, and
//!   fnox answers it. A connection to the proxy is made by fnox on a socket of
//!   its own, which then replaces the command's socket; anything else is
//!   refused. fnox never lets the command's own `connect()` run, so the command
//!   cannot change the address after fnox checks it. Datagram, raw and other
//!   kinds of sockets cannot be created, nothing can listen, and io_uring,
//!   which would skip the filter, is unavailable.
//! - **Processes**: Landlock keeps the command from signalling, tracing or
//!   reading the memory of processes outside the sandbox, fnox among them, and
//!   from reaching abstract Unix sockets created outside it.
//!
//! Landlock ABI 6 (Linux 6.12) is required, on x86_64 or aarch64.

use crate::error::{FnoxError, Result};
use crate::sandbox::SandboxPolicy;
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, Scope,
};
use std::ffi::OsString;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// The Landlock ABI that this sandbox is written against.
const LANDLOCK_ABI: ABI = ABI::V6;

/// Always hidden, as under `bwrap`, where they are empty. They hold other
/// processes' sockets and temporary files.
const ALWAYS_HIDDEN: &[&str] = &["/tmp", "/run", "/dev/shm"];

/// Devices the command may write.
const DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/pts",
];

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// A sandbox that has been checked to work on this machine.
pub struct Confinement {
    /// Holds the command's temporary directory and a copy of the proxy's CA.
    dir: tempfile::TempDir,
    ruleset: OwnedFd,
    filter: Vec<libc::sock_filter>,
}

impl Confinement {
    /// Builds the Landlock ruleset and the seccomp filter, and confines a
    /// throwaway process with them, so that a machine that cannot run the
    /// sandbox fails before any secret is resolved.
    pub fn prepare(policy: &SandboxPolicy) -> Result<Self> {
        check_abi()?;
        check_writable(policy)?;
        let dir = tempfile::Builder::new()
            .prefix("fnox-sandbox-")
            .tempdir()
            .map_err(|error| {
                FnoxError::Config(format!("failed to create the sandbox directory: {error}"))
            })?;
        std::fs::create_dir(dir.path().join("tmp")).map_err(|error| {
            FnoxError::Config(format!("failed to create the sandbox directory: {error}"))
        })?;
        let ruleset = ruleset(policy, dir.path())?;
        let confinement = Self {
            dir,
            ruleset,
            filter: filter(),
        };
        confinement.check()?;
        Ok(confinement)
    }

    /// The temporary directory the command may write.
    pub fn temp_dir(&self) -> PathBuf {
        self.dir.path().join("tmp")
    }

    /// Copies the proxy's CA bundle to where the command can read it.
    pub fn place_ca(&self, ca: &Path) -> Result<PathBuf> {
        let target = self.dir.path().join("ca.pem");
        std::fs::copy(ca, &target).map_err(|error| {
            FnoxError::Config(format!(
                "failed to copy the proxy CA into the sandbox: {error}"
            ))
        })?;
        Ok(target)
    }

    /// The variables that point the command at its temporary directory.
    pub fn env(&self) -> Vec<(String, OsString)> {
        let temp = self.temp_dir().into_os_string();
        ["TMPDIR", "TMP", "TEMP"]
            .map(|key| (key.to_string(), temp.clone()))
            .into()
    }

    /// Confines `command` when it is spawned, and answers its connections
    /// from a thread that lets through only those to `proxy`.
    pub fn apply(&self, command: &mut tokio::process::Command, proxy: SocketAddrV4) -> Result<()> {
        // A process the command leaves behind is handed to fnox rather than
        // to init, so fnox can still read its connect() address (which Yama
        // allows only to an ancestor) and stop it when the command exits.
        // SAFETY: prctl takes only integer arguments.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let (ours, theirs) = channel()?;
        let ruleset = self.ruleset.as_raw_fd();
        let filter = self.filter.clone();
        std::thread::Builder::new()
            .name("fnox-sandbox".to_string())
            .spawn(move || supervise(ours, proxy))
            .map_err(|error| {
                FnoxError::Config(format!("failed to start the sandbox supervisor: {error}"))
            })?;
        // SAFETY: the closure only makes system calls, without allocating.
        // `theirs` lives as long as `command`, so if the spawn fails the
        // supervisor sees the channel close and returns.
        unsafe {
            command.pre_exec(move || {
                confine_self(ruleset, &filter, theirs.as_raw_fd())
                    .map_err(|(_, errno)| io::Error::from_raw_os_error(errno))
            });
        }
        Ok(())
    }

    /// Forks a process that confines itself and tries one connection, which
    /// must reach fnox and be refused.
    fn check(&self) -> Result<()> {
        let fail = |what: String| {
            FnoxError::Config(format!(
                "the landlock sandbox could not start: {what}; see https://fnox.jdx.dev/guide/proxy#sandbox"
            ))
        };
        let (ours, theirs) = channel().map_err(|error| fail(error.to_string()))?;
        // SAFETY: the child only makes system calls before `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(fail(io::Error::last_os_error().to_string()));
        }
        if pid == 0 {
            // SAFETY: as above; nothing here allocates.
            unsafe {
                if let Err((step, errno)) =
                    confine_self(self.ruleset.as_raw_fd(), &self.filter, theirs.as_raw_fd())
                {
                    let mut message = [0u8; 5];
                    message[0] = step as u8;
                    message[1..].copy_from_slice(&errno.to_le_bytes());
                    libc::write(theirs.as_raw_fd(), message.as_ptr().cast(), message.len());
                    libc::_exit(2);
                }
                let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let address = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 9u16.to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                let result = libc::connect(
                    socket,
                    (&raw const address).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                let refused = result < 0 && *libc::__errno_location() == libc::EACCES;
                libc::_exit(if refused { 0 } else { 3 });
            }
        }
        drop(theirs);
        let outcome = (|| {
            let listener = match receive(&ours) {
                Received::Listener(listener) => listener,
                Received::Failed(step, errno) => {
                    return Err(format!(
                        "{}: {}",
                        step.describe(),
                        io::Error::from_raw_os_error(errno)
                    ));
                }
                Received::Nothing => return Err("the test process exited early".to_string()),
            };
            if !wait_readable(listener.as_raw_fd(), 5000) {
                return Err("the test process did not connect".to_string());
            }
            match answer(listener.as_raw_fd(), "127.0.0.1:1".parse().unwrap()) {
                Ok(Answer::Refused) => Ok(()),
                Ok(Answer::Unreadable(error)) => Err(format!(
                    "fnox cannot read the sandboxed process's memory ({error}); \
                     kernel.yama.ptrace_scope must be 0 or 1"
                )),
                Ok(other) => Err(format!("unexpected answer {other:?}")),
                Err(error) => Err(error.to_string()),
            }
        })();
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        outcome.map_err(fail)?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(fail(format!(
                "the test process's connection was not refused (status {status})"
            )));
        }
        Ok(())
    }
}

/// Fails unless the kernel supports [`LANDLOCK_ABI`].
fn check_abi() -> Result<()> {
    // SAFETY: with a null attribute and this flag, the call only reports the
    // ABI version.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    let reason = if abi >= LANDLOCK_ABI as i64 {
        return Ok(());
    } else if abi >= 0 {
        format!("the kernel offers Landlock ABI {abi}")
    } else {
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EOPNOTSUPP) => "Landlock is disabled on this machine".to_string(),
            Some(libc::ENOSYS) => "the kernel does not support Landlock".to_string(),
            _ => format!("Landlock is unavailable: {}", io::Error::last_os_error()),
        }
    };
    Err(FnoxError::Config(format!(
        "the landlock sandbox needs Landlock ABI {} (Linux 6.12 or later), but {reason}",
        LANDLOCK_ABI as i64
    )))
}

/// Landlock can only grant access, so a writable path cannot have a part
/// that stays hidden or read-only.
fn check_writable(policy: &SandboxPolicy) -> Result<()> {
    for writable in &policy.writable {
        let protected = policy
            .hide
            .iter()
            .map(|hidden| &hidden.path)
            .chain(&policy.read_only)
            .find(|path| path.starts_with(writable));
        if let Some(path) = protected {
            return Err(FnoxError::Config(format!(
                "the landlock sandbox cannot let the command write {} without letting it \
                 change {}, which it must not read or change; allow a narrower directory in \
                 sandbox_allow_write",
                writable.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

/// The paths the command may read files beneath: everything except the
/// hidden paths. A directory with a hidden path inside is not granted as a
/// whole; its other entries are granted one by one, as they are now.
fn read_roots(root: &Path, hidden: &[PathBuf]) -> Vec<PathBuf> {
    fn walk(path: &Path, hidden: &[PathBuf], roots: &mut Vec<PathBuf>) {
        if hidden.iter().any(|hidden| hidden == path) {
            return;
        }
        if !hidden.iter().any(|hidden| hidden.starts_with(path)) {
            roots.push(path.to_path_buf());
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            // A rule follows a symlink, which could lead into a hidden path.
            // The symlink's target has rules of its own.
            if entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
                continue;
            }
            walk(&entry.path(), hidden, roots);
        }
    }
    let mut roots = Vec::new();
    walk(root, hidden, &mut roots);
    roots
}

fn ruleset(policy: &SandboxPolicy, dir: &Path) -> Result<OwnedFd> {
    let error = |error: &dyn std::fmt::Display| {
        FnoxError::Config(format!("failed to build the landlock sandbox: {error}"))
    };
    let all = AccessFs::from_all(LANDLOCK_ABI);
    let read: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::Execute;
    let device: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev;

    let mut hidden: Vec<PathBuf> = policy
        .hide
        .iter()
        .map(|hidden| hidden.path.clone())
        .filter(|path| path.exists())
        .collect();
    hidden.extend(ALWAYS_HIDDEN.iter().map(PathBuf::from));

    // Listing directories reveals names, not contents, and without it on
    // every ancestor of a hidden path the command could not list `~`.
    let mut rules: Vec<(PathBuf, BitFlags<AccessFs>)> =
        vec![(PathBuf::from("/"), AccessFs::ReadDir.into())];
    rules.extend(
        read_roots(Path::new("/"), &hidden)
            .into_iter()
            .map(|path| (path, read)),
    );
    // As under `bwrap`, which mounts it back over its empty /tmp, the
    // working directory stays readable even inside an always-hidden path.
    if ALWAYS_HIDDEN
        .iter()
        .any(|always| policy.cwd.starts_with(always))
    {
        rules.extend(
            read_roots(&policy.cwd, &hidden)
                .into_iter()
                .map(|path| (path, read)),
        );
    }
    rules.extend(
        DEVICES
            .iter()
            .map(|path| (PathBuf::from(path), device | AccessFs::ReadDir)),
    );
    rules.push((dir.to_path_buf(), AccessFs::ReadFile | AccessFs::ReadDir));
    rules.push((dir.join("tmp"), all));
    rules.extend(policy.writable.iter().map(|path| (path.clone(), all)));

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)
        .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(LANDLOCK_ABI)))
        .and_then(|ruleset| ruleset.scope(Scope::from_all(LANDLOCK_ABI)))
        .and_then(|ruleset| ruleset.create())
        .map_err(|e| error(&e))?;
    for (path, access) in rules {
        // A path that vanished since it was listed has nothing to grant.
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        let Ok(fd) = PathFd::new(&path) else {
            continue;
        };
        let access = if metadata.is_dir() {
            access
        } else {
            access & AccessFs::from_file(LANDLOCK_ABI)
        };
        if access.is_empty() {
            continue;
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| error(&e))?;
    }
    // No network rules: binding and connecting are denied, and the
    // proxy connections are made by fnox outside the sandbox.
    Option::<OwnedFd>::from(ruleset).ok_or_else(|| error(&"Landlock is not enforced"))
}

/// Classic BPF, as `seccomp` takes it.
mod bpf {
    use libc::sock_filter;

    const LD_W_ABS: u16 = 0x20;
    const ALU_AND_K: u16 = 0x54;
    pub const JEQ: u16 = 0x15;
    pub const JSET: u16 = 0x45;
    const RET_K: u16 = 0x06;

    /// Loads the 32-bit word at `offset` in `seccomp_data`.
    pub fn load(offset: u32) -> sock_filter {
        sock_filter {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    /// Loads the low 32 bits of the system call's argument `index`; every
    /// argument checked here is an `int` to the kernel.
    pub fn arg(index: u32) -> sock_filter {
        load(16 + 8 * index)
    }

    pub fn and(mask: u32) -> sock_filter {
        sock_filter {
            code: ALU_AND_K,
            jt: 0,
            jf: 0,
            k: mask,
        }
    }

    pub fn ret(action: u32) -> sock_filter {
        sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: action,
        }
    }

    /// Runs `block` if the comparison holds, and skips it otherwise. The
    /// block must return on every path, so a skipped one leaves the
    /// accumulator as it was.
    pub fn when(code: u16, value: u32, block: Vec<sock_filter>) -> Vec<sock_filter> {
        let length = u8::try_from(block.len()).expect("a BPF block fits a jump");
        let mut program = vec![sock_filter {
            code,
            jt: 0,
            jf: length,
            k: value,
        }];
        program.extend(block);
        program
    }
}

/// The seccomp filter: `connect()` goes to fnox, and the system calls that
/// could reach the network another way are refused.
fn filter() -> Vec<libc::sock_filter> {
    use bpf::{JEQ, JSET, and, arg, load, ret, when};
    let allow = || ret(libc::SECCOMP_RET_ALLOW);
    let deny = |errno: i32| ret(libc::SECCOMP_RET_ERRNO | errno as u32);
    let nr = |number: libc::c_long| number as u32;
    let stream_types = || {
        [
            // SOCK_TYPE_MASK, without SOCK_NONBLOCK and SOCK_CLOEXEC
            vec![arg(1), and(0xf)],
            when(JEQ, libc::SOCK_STREAM as u32, vec![allow()]),
            when(JEQ, libc::SOCK_SEQPACKET as u32, vec![allow()]),
            vec![deny(libc::EACCES)],
        ]
        .concat()
    };
    let tcp = || {
        [
            vec![arg(1), and(0xf)],
            when(
                JEQ,
                libc::SOCK_STREAM as u32,
                [
                    vec![arg(2)],
                    when(JEQ, 0, vec![allow()]),
                    when(JEQ, libc::IPPROTO_TCP as u32, vec![allow()]),
                    vec![deny(libc::EACCES)],
                ]
                .concat(),
            ),
            vec![deny(libc::EACCES)],
        ]
        .concat()
    };
    let socket = [
        vec![arg(0)],
        // Datagram Unix sockets take an address with every message, which
        // the filter cannot see.
        when(JEQ, libc::AF_UNIX as u32, stream_types()),
        when(JEQ, libc::AF_INET as u32, tcp()),
        when(JEQ, libc::AF_INET6 as u32, tcp()),
        // Interface and route lookups, as getaddrinfo makes.
        when(
            JEQ,
            libc::AF_NETLINK as u32,
            [
                vec![arg(2)],
                when(JEQ, 0 /* NETLINK_ROUTE */, vec![allow()]),
                vec![deny(libc::EACCES)],
            ]
            .concat(),
        ),
        vec![deny(libc::EAFNOSUPPORT)],
    ]
    .concat();

    let mut program = vec![
        load(4), // arch
        libc::sock_filter {
            code: JEQ,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH,
        },
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        load(0), // nr
    ];
    #[cfg(target_arch = "x86_64")]
    program.extend(when(
        JSET,
        0x4000_0000, // __X32_SYSCALL_BIT
        vec![ret(libc::SECCOMP_RET_KILL_PROCESS)],
    ));
    program.extend(when(
        JEQ,
        nr(libc::SYS_connect),
        vec![ret(libc::SECCOMP_RET_USER_NOTIF)],
    ));
    program.extend(when(JEQ, nr(libc::SYS_socket), socket));
    program.extend(when(JEQ, nr(libc::SYS_socketpair), stream_types()));
    // TCP Fast Open connects as it sends.
    for (number, flags) in [
        (libc::SYS_sendto, 3),
        (libc::SYS_sendmsg, 2),
        (libc::SYS_sendmmsg, 3),
    ] {
        program.extend(when(
            JEQ,
            nr(number),
            [
                vec![arg(flags)],
                when(JSET, libc::MSG_FASTOPEN as u32, vec![deny(libc::EACCES)]),
                vec![allow()],
            ]
            .concat(),
        ));
    }
    // Listening on a socket that is not bound binds it to a port.
    program.extend(when(JEQ, nr(libc::SYS_listen), vec![deny(libc::EACCES)]));
    // io_uring makes its connections without system calls the filter sees.
    for number in [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        program.extend(when(JEQ, nr(number), vec![deny(libc::ENOSYS)]));
    }
    // The kernel keyrings are shared with processes outside the sandbox.
    for number in [libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key] {
        program.extend(when(JEQ, nr(number), vec![deny(libc::EPERM)]));
    }
    // Typing into, or reading, a terminal outside the sandbox.
    program.extend(when(
        JEQ,
        nr(libc::SYS_ioctl),
        [
            vec![arg(1)],
            when(JEQ, libc::TIOCSTI as u32, vec![deny(libc::EPERM)]),
            when(JEQ, libc::TIOCLINUX as u32, vec![deny(libc::EPERM)]),
            vec![allow()],
        ]
        .concat(),
    ));
    // A newer filter's listener would take the command's connect() calls
    // ahead of fnox's.
    program.extend(when(
        JEQ,
        nr(libc::SYS_seccomp),
        [
            vec![arg(1)],
            when(
                JSET,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as u32,
                vec![deny(libc::EPERM)],
            ),
            vec![allow()],
        ]
        .concat(),
    ));
    program.push(allow());
    program
}

/// The step of [`confine_self`] that failed.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum Step {
    Session = 1,
    Capabilities,
    NoNewPrivileges,
    Landlock,
    Seccomp,
    Channel,
}

impl Step {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Session,
            2 => Self::Capabilities,
            3 => Self::NoNewPrivileges,
            4 => Self::Landlock,
            5 => Self::Seccomp,
            _ => Self::Channel,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Session => "starting a session",
            Self::Capabilities => "dropping capabilities",
            Self::NoNewPrivileges => "setting no_new_privs",
            Self::Landlock => "entering the Landlock domain",
            Self::Seccomp => "installing the seccomp filter",
            Self::Channel => "handing the seccomp listener to fnox",
        }
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Confines the calling process, which must be single-threaded, and sends
/// the seccomp listener over `channel`. Runs between `fork` and `exec`, so it
/// only makes system calls.
///
/// # Safety
///
/// `ruleset` must be a Landlock ruleset and `channel` a Unix socket.
unsafe fn confine_self(
    ruleset: RawFd,
    filter: &[libc::sock_filter],
    channel: RawFd,
) -> std::result::Result<(), (Step, i32)> {
    let errno = || {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    };
    // SAFETY: each call takes integers or pointers to live locals.
    unsafe {
        // Without a terminal of its own the command cannot push keystrokes
        // into the one that started it.
        if libc::setsid() < 0 {
            return Err((Step::Session, errno()));
        }
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);

        // A root user in a container keeps capabilities such as
        // CAP_DAC_READ_SEARCH, which opens files by handle, past Landlock.
        // The bounding set needs CAP_SETPCAP to drop, and an unprivileged
        // user has nothing in it to fear.
        for capability in 0..64 {
            libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0);
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        let mut header = CapHeader {
            version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
            pid: 0,
        };
        let data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) < 0 {
            return Err((Step::Capabilities, errno()));
        }
        // Also keeps a set-user-ID program from regaining them.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err((Step::NoNewPrivileges, errno()));
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) < 0 {
            return Err((Step::Landlock, errno()));
        }
        let program = libc::sock_fprog {
            len: filter.len() as libc::c_ushort,
            filter: filter.as_ptr().cast_mut(),
        };
        let listener = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const program,
        );
        if listener < 0 {
            return Err((Step::Seccomp, errno()));
        }
        let listener = listener as RawFd;
        let sent = send_fd(channel, listener);
        libc::close(listener);
        if !sent {
            return Err((Step::Channel, errno()));
        }
    }
    Ok(())
}

/// A `SOCK_SEQPACKET` pair, so a message arrives whole or not at all.
fn channel() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for both descriptors.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Room for one `SCM_RIGHTS` descriptor, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct ControlBuffer([u8; 32]);

/// Sends `fd` over `channel` without allocating.
///
/// # Safety
///
/// Both must be open descriptors.
unsafe fn send_fd(channel: RawFd, fd: RawFd) -> bool {
    // SAFETY: the message points at live locals that fit what it claims.
    unsafe {
        let mut control = ControlBuffer([0; 32]);
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&raw mut byte).cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd);
        libc::sendmsg(channel, &raw const message, 0) == 1
    }
}

enum Received {
    Listener(OwnedFd),
    /// [`confine_self`] failed at this step with this errno.
    Failed(Step, i32),
    /// The channel closed, as when the process exited first.
    Nothing,
}

fn receive(channel: &OwnedFd) -> Received {
    // SAFETY: the message points at live locals that fit what it claims, and
    // a descriptor is only taken from a control message the kernel filled.
    unsafe {
        let mut control = ControlBuffer([0; 32]);
        let mut data = [0u8; 5];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = control.0.len() as _;
        let length = loop {
            let length = libc::recvmsg(
                channel.as_raw_fd(),
                &raw mut message,
                libc::MSG_CMSG_CLOEXEC,
            );
            if length < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break length;
        };
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        if !header.is_null()
            && (*header).cmsg_level == libc::SOL_SOCKET
            && (*header).cmsg_type == libc::SCM_RIGHTS
        {
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>());
            return Received::Listener(OwnedFd::from_raw_fd(fd));
        }
        if length == 5 {
            let errno = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            return Received::Failed(Step::from_u8(data[0]), errno);
        }
        Received::Nothing
    }
}

/// Waits up to `timeout` milliseconds (or forever, if negative) for `fd` to
/// be readable. False if it was not, or hung up instead.
fn wait_readable(fd: RawFd, timeout: i32) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: `poll` is one live pollfd.
        let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return ready > 0 && poll.revents & libc::POLLIN != 0;
    }
}

/// Answers the command's connections until every process that has the
/// filter is gone, at which point the listener hangs up.
fn supervise(channel: OwnedFd, proxy: SocketAddrV4) {
    let Received::Listener(listener) = receive(&channel) else {
        return;
    };
    drop(channel);
    while wait_readable(listener.as_raw_fd(), -1) {
        match answer(listener.as_raw_fd(), proxy) {
            Ok(Answer::Unreadable(error)) => tracing::warn!(
                "fnox proxy sandbox: refused a connection whose address fnox could not read: {error}"
            ),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!("fnox proxy sandbox: stopped answering connections: {error}");
                return;
            }
        }
    }
}

#[derive(Debug)]
enum Answer {
    Connected,
    Refused,
    /// Refused, because fnox could not read the address.
    Unreadable(io::Error),
    /// The process left before fnox answered.
    Gone,
}

/// Which socket fnox connects to the proxy in place of the command's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    V4,
    /// `::ffff:127.0.0.1`, as a dual-stack socket names an IPv4 address.
    MappedV4,
}

/// Whether the `sockaddr` the command passed to `connect()` is the proxy.
fn destination(address: &[u8], proxy: SocketAddrV4) -> Option<Destination> {
    let family = u16::from_ne_bytes(address.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(address.get(2..4)?.try_into().ok()?);
    if port != proxy.port() {
        return None;
    }
    match i32::from(family) {
        libc::AF_INET if address.len() >= size_of::<libc::sockaddr_in>() => {
            let ip: [u8; 4] = address[4..8].try_into().ok()?;
            (std::net::Ipv4Addr::from(ip) == *proxy.ip()).then_some(Destination::V4)
        }
        libc::AF_INET6 if address.len() >= size_of::<libc::sockaddr_in6>() => {
            let ip: [u8; 16] = address[8..24].try_into().ok()?;
            (std::net::Ipv6Addr::from(ip).to_ipv4_mapped() == Some(*proxy.ip()))
                .then_some(Destination::MappedV4)
        }
        _ => None,
    }
}

/// Receives one `connect()` notification and answers it.
fn answer(listener: RawFd, proxy: SocketAddrV4) -> io::Result<Answer> {
    // SAFETY: the kernel fills a zeroed notification and reads back the
    // response and addfd structures it defines.
    unsafe {
        let mut request: libc::seccomp_notif = std::mem::zeroed();
        if libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, &raw mut request) < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::EINTR) => Ok(Answer::Gone),
                _ => Err(error),
            };
        }
        let respond = |error: i32| {
            let mut response = libc::seccomp_notif_resp {
                id: request.id,
                val: 0,
                error: -error,
                flags: 0,
            };
            libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, &raw mut response);
        };
        let tid = request.pid as libc::pid_t;
        let fd = request.data.args[0] as RawFd;
        let length =
            (request.data.args[2] as u32 as usize).min(size_of::<libc::sockaddr_storage>());
        let mut address = [0u8; size_of::<libc::sockaddr_storage>()];
        let local = libc::iovec {
            iov_base: address.as_mut_ptr().cast(),
            iov_len: length,
        };
        let remote = libc::iovec {
            iov_base: request.data.args[1] as *mut libc::c_void,
            iov_len: length,
        };
        let read = libc::process_vm_readv(tid, &raw const local, 1, &raw const remote, 1, 0);
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EFAULT) {
                respond(libc::EFAULT);
                return Ok(Answer::Refused);
            }
            respond(libc::EACCES);
            return Ok(Answer::Unreadable(error));
        }
        // The thread could have exited, and its ID been reused, while its
        // memory was read.
        let mut id = request.id;
        if libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &raw mut id) < 0 {
            return Ok(Answer::Gone);
        }
        let Some(destination) = destination(&address[..read as usize], proxy) else {
            respond(libc::EACCES);
            return Ok(Answer::Refused);
        };
        match connect_in_place(listener, request.id, tid, fd, destination, proxy) {
            Ok(()) => {
                respond(0);
                Ok(Answer::Connected)
            }
            Err(error) => {
                respond(error.raw_os_error().unwrap_or(libc::ECONNREFUSED));
                Ok(Answer::Refused)
            }
        }
    }
}

/// Connects a socket of fnox's own to the proxy and installs it as the
/// command's `fd`, with the flags the command gave its own socket. Socket
/// options the command set before connecting are not carried over.
fn connect_in_place(
    listener: RawFd,
    id: u64,
    tid: libc::pid_t,
    fd: RawFd,
    destination: Destination,
    proxy: SocketAddrV4,
) -> io::Result<()> {
    let flags = file_flags(tid, fd)?;
    let address = match destination {
        Destination::V4 => SocketAddr::V4(proxy),
        Destination::MappedV4 => SocketAddr::V6(SocketAddrV6::new(
            proxy.ip().to_ipv6_mapped(),
            proxy.port(),
            0,
            0,
        )),
    };
    let stream = TcpStream::connect(address)?;
    if flags & libc::O_NONBLOCK != 0 {
        stream.set_nonblocking(true)?;
    }
    let addfd = libc::seccomp_notif_addfd {
        id,
        flags: libc::SECCOMP_ADDFD_FLAG_SETFD as u32,
        srcfd: stream.as_raw_fd() as u32,
        newfd: fd as u32,
        newfd_flags: (flags & libc::O_CLOEXEC) as u32,
    };
    // SAFETY: the kernel reads the addfd structure it defines.
    if unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ADDFD, &raw const addfd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The `open` flags of the command's `fd`, as `/proc` reports them.
fn file_flags(tid: libc::pid_t, fd: RawFd) -> io::Result<i32> {
    let info = std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}"))?;
    info.lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| i32::from_str_radix(flags.trim(), 8).ok())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
}

/// Kills what the command left behind. Its processes, which have one more
/// seccomp filter than fnox, are handed to fnox when their parent exits.
pub fn stop_remaining() {
    // SAFETY: getpid takes no arguments.
    let me = unsafe { libc::getpid() };
    let Some(own) = seccomp_filters(me) else {
        return;
    };
    for _ in 0..100 {
        let stragglers: Vec<libc::pid_t> = children(me)
            .into_iter()
            .filter(|pid| seccomp_filters(*pid).is_some_and(|filters| filters > own))
            .collect();
        if stragglers.is_empty() {
            return;
        }
        for pid in stragglers {
            // SAFETY: both take integers; `pid` is fnox's own child, so it
            // cannot be reused until it is waited for here.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn seccomp_filters(pid: libc::pid_t) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .and_then(|count| count.trim().parse().ok())
}

fn children(parent: libc::pid_t) -> Vec<libc::pid_t> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    // The name in parentheses may hold spaces.
                    let rest = &stat[stat.rfind(')')? + 1..];
                    rest.split_whitespace().nth(1)?.parse::<libc::pid_t>().ok()
                })
                == Some(parent)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    use crate::sandbox::{HiddenPath, PolicyInputs};

    /// Runs a seccomp program the way the kernel does, for the instructions
    /// [`filter`] uses.
    fn run(program: &[libc::sock_filter], nr: libc::c_long, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&(nr as i32).to_ne_bytes());
        data[4..8].copy_from_slice(&AUDIT_ARCH.to_ne_bytes());
        for (index, arg) in args.iter().enumerate() {
            data[16 + 8 * index..24 + 8 * index].copy_from_slice(&arg.to_ne_bytes());
        }
        let mut accumulator = 0u32;
        let mut pc = 0;
        loop {
            let insn = program[pc];
            pc += 1;
            match insn.code {
                0x20 => {
                    let k = insn.k as usize;
                    accumulator = u32::from_ne_bytes(data[k..k + 4].try_into().unwrap());
                }
                0x54 => accumulator &= insn.k,
                0x15 | 0x45 => {
                    let taken = if insn.code == 0x15 {
                        accumulator == insn.k
                    } else {
                        accumulator & insn.k != 0
                    };
                    pc += usize::from(if taken { insn.jt } else { insn.jf });
                }
                0x06 => return insn.k,
                code => panic!("unexpected BPF instruction {code:#x}"),
            }
        }
    }

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const fn errno(errno: i32) -> u32 {
        libc::SECCOMP_RET_ERRNO | errno as u32
    }

    fn socket(domain: i32, kind: i32, protocol: i32) -> u32 {
        run(
            &filter(),
            libc::SYS_socket,
            [domain as u64, kind as u64, protocol as u64, 0, 0, 0],
        )
    }

    #[test]
    fn connect_goes_to_fnox() {
        assert_eq!(
            run(&filter(), libc::SYS_connect, [3, 0, 16, 0, 0, 0]),
            libc::SECCOMP_RET_USER_NOTIF
        );
    }

    #[test]
    fn only_stream_sockets_can_be_created() {
        let cloexec = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
        assert_eq!(socket(libc::AF_INET, libc::SOCK_STREAM, 0), ALLOW);
        assert_eq!(
            socket(libc::AF_INET6, libc::SOCK_STREAM | cloexec, 6),
            ALLOW
        );
        assert_eq!(socket(libc::AF_UNIX, libc::SOCK_STREAM, 0), ALLOW);
        assert_eq!(socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0), ALLOW);
        assert_eq!(socket(libc::AF_NETLINK, libc::SOCK_RAW, 0), ALLOW);
        let denied = errno(libc::EACCES);
        assert_eq!(socket(libc::AF_INET, libc::SOCK_DGRAM, 0), denied);
        assert_eq!(socket(libc::AF_INET6, libc::SOCK_RAW, 1), denied);
        assert_eq!(socket(libc::AF_INET, libc::SOCK_STREAM, 132), denied); // SCTP
        assert_eq!(socket(libc::AF_UNIX, libc::SOCK_DGRAM | cloexec, 0), denied);
        assert_eq!(socket(libc::AF_NETLINK, libc::SOCK_RAW, 4), denied); // SOCK_DIAG
        assert_eq!(
            socket(libc::AF_PACKET, libc::SOCK_RAW, 0),
            errno(libc::EAFNOSUPPORT)
        );
        assert_eq!(
            socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            errno(libc::EAFNOSUPPORT)
        );
        let pair = |kind: i32| {
            run(
                &filter(),
                libc::SYS_socketpair,
                [libc::AF_UNIX as u64, kind as u64, 0, 0, 0, 0],
            )
        };
        assert_eq!(pair(libc::SOCK_STREAM), ALLOW);
        assert_eq!(pair(libc::SOCK_DGRAM), denied);
    }

    #[test]
    // The ioctl request constants are c_int on musl.
    #[allow(clippy::unnecessary_cast)]
    fn other_routes_out_are_refused() {
        let program = filter();
        let fastopen = libc::MSG_FASTOPEN as u64;
        assert_eq!(run(&program, libc::SYS_sendto, [3, 0, 1, 0, 0, 0]), ALLOW);
        assert_eq!(
            run(&program, libc::SYS_sendto, [3, 0, 1, fastopen, 0, 0]),
            errno(libc::EACCES)
        );
        assert_eq!(
            run(&program, libc::SYS_sendmsg, [3, 0, fastopen, 0, 0, 0]),
            errno(libc::EACCES)
        );
        assert_eq!(
            run(&program, libc::SYS_listen, [3, 1, 0, 0, 0, 0]),
            errno(libc::EACCES)
        );
        assert_eq!(
            run(&program, libc::SYS_io_uring_setup, [8, 0, 0, 0, 0, 0]),
            errno(libc::ENOSYS)
        );
        assert_eq!(
            run(
                &program,
                libc::SYS_ioctl,
                [0, libc::TIOCSTI as u64, 0, 0, 0, 0]
            ),
            errno(libc::EPERM)
        );
        assert_eq!(
            run(
                &program,
                libc::SYS_ioctl,
                [0, libc::TCGETS as u64, 0, 0, 0, 0]
            ),
            ALLOW
        );
        let listener = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
        assert_eq!(
            run(&program, libc::SYS_seccomp, [1, listener, 0, 0, 0, 0]),
            errno(libc::EPERM)
        );
        assert_eq!(run(&program, libc::SYS_seccomp, [1, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(run(&program, libc::SYS_read, [0; 6]), ALLOW);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_system_calls_are_killed() {
        assert_eq!(
            run(&filter(), 0x4000_0000 | libc::SYS_read, [0; 6]),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    fn sockaddr_in(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut address = vec![0u8; size_of::<libc::sockaddr_in>()];
        address[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        address[2..4].copy_from_slice(&port.to_be_bytes());
        address[4..8].copy_from_slice(&ip);
        address
    }

    fn sockaddr_in6(ip: std::net::Ipv6Addr, port: u16) -> Vec<u8> {
        let mut address = vec![0u8; size_of::<libc::sockaddr_in6>()];
        address[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        address[2..4].copy_from_slice(&port.to_be_bytes());
        address[8..24].copy_from_slice(&ip.octets());
        address
    }

    #[test]
    fn only_the_proxy_is_a_destination() {
        let proxy: SocketAddrV4 = "127.0.0.1:4242".parse().unwrap();
        assert_eq!(
            destination(&sockaddr_in([127, 0, 0, 1], 4242), proxy),
            Some(Destination::V4)
        );
        let mapped = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert_eq!(
            destination(&sockaddr_in6(mapped, 4242), proxy),
            Some(Destination::MappedV4)
        );
        assert_eq!(destination(&sockaddr_in([127, 0, 0, 1], 80), proxy), None);
        assert_eq!(destination(&sockaddr_in([1, 1, 1, 1], 4242), proxy), None);
        assert_eq!(
            destination(&sockaddr_in6(std::net::Ipv6Addr::LOCALHOST, 4242), proxy),
            None
        );
        // Truncated, or another family.
        assert_eq!(
            destination(&sockaddr_in([127, 0, 0, 1], 4242)[..6], proxy),
            None
        );
        let mut unix = sockaddr_in([127, 0, 0, 1], 4242);
        unix[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        assert_eq!(destination(&unix, proxy), None);
    }

    #[test]
    fn read_roots_skip_hidden_paths_and_split_their_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        for dir in ["home/.ssh", "home/src", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("home/.bashrc"), "").unwrap();
        std::os::unix::fs::symlink(root.join("home/.ssh"), root.join("home/keys")).unwrap();
        let mut roots = read_roots(&root, &[root.join("home/.ssh")]);
        roots.sort();
        assert_eq!(
            roots,
            [
                root.join("etc"),
                root.join("home/.bashrc"),
                root.join("home/src")
            ]
        );
        assert_eq!(read_roots(&root, &[]), [root]);
    }

    #[test]
    fn a_writable_path_cannot_hold_a_protected_one() {
        let root = tempfile::tempdir().unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(project.join("target")).unwrap();
        std::fs::write(project.join("fnox.toml"), "").unwrap();
        let policy = |allow_write: &str| {
            SandboxPolicy::build(PolicyInputs {
                cwd: project.clone(),
                cwd_writable: false,
                home: project.join("home"),
                fnox_dirs: Vec::new(),
                fnox_files: vec![project.join("fnox.toml")],
                environment: Vec::new(),
                config: &ProxyConfig {
                    sandbox_allow_write: vec![allow_write.to_string()],
                    ..ProxyConfig::default()
                },
            })
        };
        let narrow = policy("target");
        assert_eq!(narrow.writable, [project.join("target")]);
        assert_eq!(
            narrow.hide,
            [HiddenPath {
                path: project.join("fnox.toml"),
                is_dir: false
            }]
        );
        check_writable(&narrow).unwrap();
        let error = check_writable(&policy(".")).unwrap_err().to_string();
        assert!(error.contains("fnox.toml"), "{error}");
    }
}
