#![cfg(unix)]
//! The client against a scripted daemon: a std `UnixListener` on a thread.

use fnox_client::document::EnvScope;
use fnox_client::wire::MAX_LINE_BYTES;
use fnox_client::{CallError, CliFlags, Client, EnvOutcome, EnvRequest, RuntimeEnv, SocketKey};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::thread::JoinHandle;
use std::time::Duration;

enum Script {
    Reply(Vec<u8>),
    Close,
    Sleep(Duration),
    /// A reply of exactly this many bytes, then a newline.
    Big(usize),
}

struct Fixture {
    _dir: tempfile::TempDir,
    client: Client,
    listener: UnixListener,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let rt = RuntimeEnv {
        xdg_runtime_dir: Some(dir.path().to_path_buf()),
        tmpdir: dir.path().to_path_buf(),
        euid: fnox_client::peer::current_euid(),
    };
    let key = SocketKey::from_cli_env(&CliFlags::default(), &|_| None);
    let client = Client::new(key, &rt);
    std::fs::create_dir_all(client.socket_path().parent().unwrap()).unwrap();
    let listener = UnixListener::bind(client.socket_path()).unwrap();
    Fixture {
        _dir: dir,
        client,
        listener,
    }
}

/// Serves one connection; returns the request line it read.
fn serve(listener: UnixListener, script: Script) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        let mut stream = stream;
        match script {
            Script::Reply(mut bytes) => {
                bytes.push(b'\n');
                let _ = stream.write_all(&bytes);
            }
            Script::Close => {}
            Script::Sleep(duration) => std::thread::sleep(duration),
            Script::Big(len) => {
                let chunk = vec![b'a'; 64 * 1024];
                let mut left = len;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        return request;
                    }
                    left -= n;
                }
                let _ = stream.write_all(b"\n");
            }
        }
        request
    })
}

fn keys() -> Vec<String> {
    vec!["A".to_string(), "B".to_string()]
}

fn ask(client: &Client, keys: Option<&[String]>, env: &[(String, String)]) -> EnvOutcome {
    client.resolve_env(&EnvRequest {
        cwd: Path::new("/p"),
        config: Path::new("fnox.toml"),
        scope: EnvScope::Exec,
        keys,
        env,
    })
}

fn reply(json: &str) -> Script {
    Script::Reply(json.as_bytes().to_vec())
}

const DOC: &str = r#"{"status":"env","document":{"schema":1,"fnox_version":"1.40.0","scope":"exec","profile":["default"],"set":{"B":"2","A":"1"},"files":{},"remove":["R"],"missing":[],"leases":[]}}"#;

#[test]
fn env_is_a_hit_and_the_request_carries_what_it_should() {
    let f = fixture();
    let server = serve(f.listener, reply(DOC));
    let env = vec![("HOME".to_string(), "/home/u".to_string())];
    let keys = keys();
    let EnvOutcome::Hit(doc) = ask(&f.client, Some(&keys), &env) else {
        panic!("expected a hit");
    };
    // V6: IndexMap order survives the wire.
    assert_eq!(
        doc.set.keys().map(String::as_str).collect::<Vec<_>>(),
        ["B", "A"]
    );
    assert_eq!(doc.set["A"].expose(), "1");
    assert_eq!(doc.remove, ["R"]);

    let request: serde_json::Value = serde_json::from_str(&server.join().unwrap()).unwrap();
    assert_eq!(request["type"], "resolve_env");
    assert_eq!(request["protocol"], 6);
    assert_eq!(request["scope"], "exec");
    assert_eq!(request["cwd"], "/p");
    assert_eq!(request["config"], "fnox.toml");
    assert_eq!(request["profile"], serde_json::json!(["default"]));
    assert_eq!(request["keys"], serde_json::json!(["A", "B"]));
    assert_eq!(request["env"], serde_json::json!([["HOME", "/home/u"]]));
}

#[test]
fn no_keys_means_every_key_in_scope() {
    let f = fixture();
    let server = serve(f.listener, reply(DOC));
    assert!(matches!(ask(&f.client, None, &[]), EnvOutcome::Hit(_)));
    let request: serde_json::Value = serde_json::from_str(&server.join().unwrap()).unwrap();
    assert!(request.get("keys").is_none());
}

#[test]
fn an_unrequested_key_is_a_protocol_error() {
    let f = fixture();
    let _server = serve(f.listener, reply(DOC));
    let only_a = vec!["A".to_string()];
    assert!(matches!(
        ask(&f.client, Some(&only_a), &[]),
        EnvOutcome::Unavailable(CallError::Protocol(_))
    ));
}

#[test]
fn a_wrong_schema_or_scope_is_a_protocol_error() {
    for bad in [
        DOC.replace(
            "\"schema\":1,\"fnox_version\"",
            "\"schema\":2,\"fnox_version\"",
        ),
        DOC.replace("\"scope\":\"exec\"", "\"scope\":\"shell\""),
    ] {
        let f = fixture();
        let _server = serve(f.listener, Script::Reply(bad.into_bytes()));
        assert!(matches!(
            ask(&f.client, None, &[]),
            EnvOutcome::Unavailable(CallError::Protocol(_))
        ));
    }
}

#[test]
fn env_miss_is_a_miss() {
    let f = fixture();
    let _server = serve(f.listener, reply(r#"{"status":"env_miss","keys":["B"]}"#));
    let EnvOutcome::Miss { keys } = ask(&f.client, None, &[]) else {
        panic!("expected a miss");
    };
    assert_eq!(keys, ["B"]);
}

#[test]
fn env_rejected_is_rejected() {
    let f = fixture();
    let _server = serve(
        f.listener,
        reply(
            r#"{"status":"env_rejected","unknown":["U"],"suggestions":{},"not_injectable":[{"key":"S","env":false}]}"#,
        ),
    );
    let EnvOutcome::Rejected(rejection) = ask(&f.client, None, &[]) else {
        panic!("expected a rejection");
    };
    assert_eq!(rejection.unknown, ["U"]);
    assert_eq!(rejection.not_injectable[0].key, "S");
}

#[test]
fn disabled_is_disabled() {
    let f = fixture();
    let _server = serve(f.listener, reply(r#"{"status":"disabled"}"#));
    assert!(matches!(ask(&f.client, None, &[]), EnvOutcome::Disabled));
}

#[test]
fn unsupported_protocol_reports_the_daemons_range() {
    let f = fixture();
    let _server = serve(
        f.listener,
        reply(r#"{"status":"unsupported_protocol","min":6,"max":6}"#),
    );
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::VersionMismatch {
            min: Some(6),
            max: Some(6)
        }
    ));
}

#[test]
fn hanging_up_without_a_reply_is_a_version_mismatch() {
    let f = fixture();
    let _server = serve(f.listener, Script::Close);
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::VersionMismatch {
            min: None,
            max: None
        }
    ));
}

#[test]
fn a_daemon_error_is_unavailable() {
    let f = fixture();
    let _server = serve(f.listener, reply(r#"{"status":"error","message":"boom"}"#));
    let EnvOutcome::Unavailable(CallError::Daemon(message)) = ask(&f.client, None, &[]) else {
        panic!("expected a daemon error");
    };
    assert_eq!(message, "boom");
}

#[test]
fn no_socket_is_absent_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("run");
    let rt = RuntimeEnv {
        xdg_runtime_dir: Some(runtime.clone()),
        tmpdir: dir.path().to_path_buf(),
        euid: fnox_client::peer::current_euid(),
    };
    let client = Client::new(SocketKey::new(&[], false, None, None), &rt);
    assert!(matches!(ask(&client, None, &[]), EnvOutcome::Absent));
    assert!(!runtime.exists());
    assert!(!client.socket_path().exists());
}

#[test]
fn a_stale_socket_file_is_absent() {
    let f = fixture();
    let path = f.client.socket_path().to_path_buf();
    drop(f.listener);
    assert!(path.exists(), "the socket file outlives its listener");
    assert!(matches!(ask(&f.client, None, &[]), EnvOutcome::Absent));
}

#[test]
fn a_slow_daemon_times_out() {
    let f = fixture();
    let client = f.client.clone().with_timeout(Duration::from_millis(100));
    let _server = serve(f.listener, Script::Sleep(Duration::from_millis(600)));
    let EnvOutcome::Unavailable(CallError::Io(e)) = ask(&client, None, &[]) else {
        panic!("expected an I/O error");
    };
    assert!(
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{e:?}"
    );
}

#[test]
fn an_oversize_line_is_rejected() {
    let f = fixture();
    let server = serve(f.listener, Script::Big(MAX_LINE_BYTES + 1));
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::Unavailable(CallError::Oversize)
    ));
    let _ = server.join();
}

#[test]
fn a_line_of_exactly_the_limit_is_read() {
    let f = fixture();
    let server = serve(f.listener, Script::Big(MAX_LINE_BYTES));
    // Not JSON, so it fails to decode, which proves it was read whole.
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::Unavailable(CallError::Decode(_))
    ));
    let _ = server.join();
}

#[test]
fn garbage_is_a_decode_error() {
    let f = fixture();
    let _server = serve(f.listener, reply("not json"));
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::Unavailable(CallError::Decode(_))
    ));
}

#[test]
fn an_unexpected_reply_is_a_protocol_error() {
    let f = fixture();
    let _server = serve(f.listener, reply(r#"{"status":"ok"}"#));
    assert!(matches!(
        ask(&f.client, None, &[]),
        EnvOutcome::Unavailable(CallError::Protocol(_))
    ));
}

#[test]
fn fnox_daemon_off_in_the_request_env_is_disabled_without_io() {
    let f = fixture();
    f.listener.set_nonblocking(true).unwrap();
    let env = vec![("FNOX_DAEMON".to_string(), "off".to_string())];
    assert!(matches!(ask(&f.client, None, &env), EnvOutcome::Disabled));
    let accepted = f.listener.accept();
    assert_eq!(
        accepted.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::WouldBlock),
        "the client connected"
    );
}

#[test]
fn hello_reports_the_daemon() {
    let f = fixture();
    let server = serve(
        f.listener,
        reply(
            r#"{"status":"hello","protocol":6,"min_protocol":6,"fnox_version":"1.40.0","pid":123}"#,
        ),
    );
    let info = f.client.hello().unwrap();
    assert_eq!(info.protocol, 6);
    assert_eq!(info.min_protocol, 6);
    assert_eq!(info.fnox_version, "1.40.0");
    assert_eq!(info.pid, 123);
    assert_eq!(
        server.join().unwrap().trim(),
        r#"{"type":"hello","protocol":6}"#
    );
}

#[test]
fn hello_without_a_daemon_says_the_socket_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let rt = RuntimeEnv {
        xdg_runtime_dir: Some(dir.path().to_path_buf()),
        tmpdir: dir.path().to_path_buf(),
        euid: fnox_client::peer::current_euid(),
    };
    let client = Client::new(SocketKey::new(&[], false, None, None), &rt);
    assert!(client.hello().unwrap_err().is_socket_missing());
}
