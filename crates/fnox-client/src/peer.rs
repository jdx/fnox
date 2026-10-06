//! Mutual peer verification: both ends of the daemon socket must belong to the
//! same user.

use std::io;
use std::os::fd::RawFd;

/// Checks that the process on the other end of the socket `fd` runs as the
/// current effective user.
pub fn verify_peer(fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` outlive the call and `len` is its size.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(credentials_error(io::Error::last_os_error()));
        }
        check(cred.uid)
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        // SAFETY: both out-pointers are valid for the duration of the call.
        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return Err(credentials_error(io::Error::last_os_error()));
        }
        check(euid)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fnox daemon peer verification is not supported on this Unix platform",
        ))
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
))]
fn credentials_error(source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        format!("Failed to verify daemon peer credentials: {source}"),
    )
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
))]
fn check(peer_uid: libc::uid_t) -> io::Result<()> {
    if peer_uid == current_euid() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Daemon client is not owned by the current user",
        ))
    }
}

/// The effective user id of this process.
pub fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}
