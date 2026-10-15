//! Mutual peer verification for the daemon's named pipe: both ends must run as
//! the same user, and the pipe itself only admits that user.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::RawHandle;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful open call and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The `TOKEN_USER` of a process: its user's SID, which points into `buf`.
struct UserSid {
    // u64 elements keep the buffer aligned for TOKEN_USER.
    buf: Vec<u64>,
}

impl UserSid {
    fn from_token(token: &OwnedHandle) -> io::Result<Self> {
        let mut needed = 0u32;
        // SAFETY: a null buffer of length 0 only asks for the required size.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` is writable for the `buf.len() * 8` bytes passed.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { buf })
    }

    fn of_process(process: HANDLE) -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `token` is a valid out-pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_token(&OwnedHandle(token))
    }

    fn of_current_process() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing.
        Self::of_process(unsafe { GetCurrentProcess() })
    }

    fn of_pid(pid: u32) -> io::Result<Self> {
        // SAFETY: plain call; a null result means failure.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedHandle(process);
        Self::of_process(process.0)
    }

    fn psid(&self) -> *mut c_void {
        // SAFETY: `buf` holds a TOKEN_USER filled in by GetTokenInformation.
        unsafe { (*self.buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn to_sid_string(&self) -> io::Result<String> {
        let mut wide: *mut u16 = null_mut();
        // SAFETY: the SID is valid and `wide` receives a LocalAlloc'd string.
        if unsafe { ConvertSidToStringSidW(self.psid(), &mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `wide` is NUL-terminated, and freed once after copying.
        let sid = unsafe {
            let mut len = 0;
            while *wide.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
            LocalFree(wide.cast());
            sid
        };
        Ok(sid)
    }

    fn same_user(&self, other: &Self) -> bool {
        // SAFETY: both SIDs are valid.
        unsafe { EqualSid(self.psid(), other.psid()) != 0 }
    }
}

/// The current user's SID in its `S-1-5-...` string form. It names the user in
/// the pipe name, which lives in a namespace shared by every user.
pub fn current_user_sid_string() -> io::Result<String> {
    UserSid::of_current_process()?.to_sid_string()
}

fn check(pid: u32) -> io::Result<()> {
    let peer = UserSid::of_pid(pid).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to verify daemon peer credentials: {e}"),
        )
    })?;
    let current = UserSid::of_current_process()?;
    if peer.same_user(&current) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Daemon peer is not owned by the current user",
        ))
    }
}

/// Checks that the process serving the pipe `handle` (a client's end) runs as
/// the current user. Call it before sending anything.
pub fn verify_pipe_server(handle: RawHandle) -> io::Result<()> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out-pointer and `handle` is an open pipe handle.
    if unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check(pid)
}

/// Checks that the process connected to the pipe `handle` (a server's end)
/// runs as the current user.
pub fn verify_pipe_client(handle: RawHandle) -> io::Result<()> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out-pointer and `handle` is an open pipe handle.
    if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check(pid)
}

/// Security attributes whose DACL admits only the current user, in place of the
/// default pipe DACL, which grants read access to Everyone.
pub struct PipeSecurity {
    descriptor: *mut c_void,
    attributes: SECURITY_ATTRIBUTES,
}

// SAFETY: the descriptor is a private, never-mutated allocation.
unsafe impl Send for PipeSecurity {}

impl PipeSecurity {
    pub fn current_user_only() -> io::Result<Self> {
        // D:P is a protected DACL; the one ACE allows everything to this user.
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{})", current_user_sid_string()?)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: `sddl` is NUL-terminated and `descriptor` is a valid out-pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: FALSE,
            },
        })
    }

    /// A `SECURITY_ATTRIBUTES*` for `CreateNamedPipe`, valid while `self` is.
    pub fn as_raw_attributes(&mut self) -> *mut c_void {
        (&mut self.attributes as *mut SECURITY_ATTRIBUTES).cast()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from LocalAlloc and is freed once.
        unsafe { LocalFree(self.descriptor) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_looks_like_a_sid() {
        let sid = current_user_sid_string().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    #[test]
    fn security_descriptor_builds() {
        let mut security = PipeSecurity::current_user_only().unwrap();
        assert!(!security.as_raw_attributes().is_null());
    }
}
