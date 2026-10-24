use crate::commands::Cli;
use crate::error::{FnoxError, Result};
use std::net::TcpListener;
use std::path::PathBuf;

/// Offer the proxy's Unix socket on a local port and run a command (internal)
///
/// `fnox proxy run` starts this inside its sandbox, where the only network is
/// an empty loopback interface. Most HTTP clients cannot use a proxy on a Unix
/// socket, so this forwards `127.0.0.1:PORT` to SOCKET for as long as COMMAND
/// runs, then exits with the command's status.
#[derive(Debug, usage_rs::Args)]
pub struct SandboxBridgeCommand {
    /// Port to listen on at 127.0.0.1
    #[usage(long, value_name = "PORT")]
    port: u16,

    /// Unix socket of the proxy
    #[usage(long, value_name = "PATH")]
    socket: PathBuf,

    /// Command to run, with its arguments
    #[usage(arg, double_dash = "automatic")]
    command: Vec<String>,
}

impl SandboxBridgeCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;

            if self.command.is_empty() {
                return Err(FnoxError::CommandNotSpecified);
            }
            let listener = TcpListener::bind(("127.0.0.1", self.port)).map_err(|error| {
                FnoxError::Config(format!("failed to listen on port {}: {error}", self.port))
            })?;
            let socket = self.socket.clone();
            std::thread::spawn(move || {
                for client in listener.incoming().flatten() {
                    let socket = socket.clone();
                    std::thread::spawn(move || forward(client, &socket));
                }
            });

            let status = std::process::Command::new(&self.command[0])
                .args(&self.command[1..])
                .status()
                .map_err(|source| FnoxError::CommandExecutionFailed {
                    command: self.command.join(" "),
                    source,
                })?;
            std::process::exit(
                status
                    .code()
                    .or_else(|| status.signal().map(|signal| 128 + signal))
                    .unwrap_or(1),
            );
        }
        #[cfg(not(unix))]
        {
            let _ = (&self.port, &self.socket, &self.command);
            Err(FnoxError::Config(
                "sandbox-bridge is only available on Unix".to_string(),
            ))
        }
    }
}

#[cfg(unix)]
fn forward(client: std::net::TcpStream, socket: &std::path::Path) {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    let Ok(upstream) = UnixStream::connect(socket) else {
        return;
    };
    let (Ok(mut client_reader), Ok(mut upstream_writer)) =
        (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let (mut upstream_reader, mut client_writer) = (upstream, client);
    let upload = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream_reader, &mut client_writer);
    let _ = client_writer.shutdown(Shutdown::Write);
    let _ = upload.join();
}
