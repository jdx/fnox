//! One-time local page where the user enters a secret an MCP agent asked for.
//!
//! `fnox mcp` serves the page on `127.0.0.1` and gives the client its URL
//! through URL-mode elicitation, so the value travels from the browser to fnox
//! without passing through the agent or its model.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

use crate::error::{FnoxError, Result};
use crate::local_http::{HttpRequest, constant_time_eq, read_http_request_limited};

/// How long a connection may take to send its request
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest request body the page reads; its form needs a few KiB at most
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Connections handled at once. Further connections wait to be accepted.
const MAX_CONNECTIONS: usize = 8;

/// Keep the confirmation readable after request_secret returns.
const CONFIRMATION_LIFETIME: Duration = Duration::from_secs(60);

/// What the page tells the user about the secret it collects
pub struct PageDetails {
    pub name: String,
    /// Written by the agent, so the page labels it as such
    pub reason: Option<String>,
    pub provider: String,
    pub target: PathBuf,
    pub profile: String,
}

/// What the user did on the page
pub enum Submission {
    /// The user entered a value. Reply with the message to show on success, or
    /// the error that stopped fnox from storing it.
    Value {
        value: String,
        reply: oneshot::Sender<std::result::Result<String, String>>,
    },
    Declined,
}

/// A running page. After a submission, its result stays readable briefly.
pub struct SecretPage {
    url: url::Url,
    submissions: mpsc::Receiver<Submission>,
    server: tokio::task::JoinHandle<()>,
    state: Arc<PageState>,
}

impl Drop for SecretPage {
    fn drop(&mut self) {
        let abort = self.server.abort_handle();
        if matches!(*self.state.outcome.borrow(), PageOutcome::Pending) {
            abort.abort();
        } else {
            // The tool can return before the POST handler has sent its redirect.
            // Keep serving the result, without accepting another value.
            tokio::spawn(async move {
                tokio::time::sleep(CONFIRMATION_LIFETIME).await;
                abort.abort();
            });
        }
    }
}

struct PageState {
    details: PageDetails,
    path: String,
    host: String,
    origin: String,
    outcome: watch::Sender<PageOutcome>,
    submissions: mpsc::Sender<Submission>,
}

#[derive(Clone)]
enum PageOutcome {
    Pending,
    Saving,
    Complete(u16, String),
}

impl PageState {
    fn claim(&self) -> bool {
        self.outcome.send_if_modified(|outcome| {
            if matches!(outcome, PageOutcome::Pending) {
                *outcome = PageOutcome::Saving;
                true
            } else {
                false
            }
        })
    }

    fn complete(&self, response: (u16, String)) {
        self.outcome
            .send_replace(PageOutcome::Complete(response.0, response.1));
    }

    fn response(&self) -> (u16, String) {
        match &*self.outcome.borrow() {
            PageOutcome::Pending => (200, form_page(&self.details, None)),
            PageOutcome::Saving => (
                200,
                page_with_head(
                    "Saving",
                    "<h1>Saving your value…</h1><p>Wait for fnox to confirm that it was stored.</p>",
                    "<meta http-equiv=\"refresh\" content=\"1\">",
                ),
            ),
            PageOutcome::Complete(status, body) => (*status, body.clone()),
        }
    }
}

impl SecretPage {
    /// Listen on a random loopback port behind an unguessable path
    pub async fn start(details: PageDetails) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| FnoxError::Config(format!("failed to start secret page: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| FnoxError::Config(format!("failed to start secret page: {e}")))?
            .port();
        let token = data_encoding::HEXLOWER.encode(&rand::random::<[u8; 32]>());
        let host = format!("127.0.0.1:{port}");
        let origin = format!("http://{host}");
        let path = format!("/secret/{token}");
        let url = url::Url::parse(&format!("{origin}{path}"))
            .map_err(|e| FnoxError::Config(format!("failed to build secret page URL: {e}")))?;
        let (sender, submissions) = mpsc::channel(1);
        let state = Arc::new(PageState {
            details,
            path,
            host,
            origin,
            outcome: watch::channel(PageOutcome::Pending).0,
            submissions: sender,
        });
        let server = tokio::spawn(serve(listener, state.clone()));
        Ok(Self {
            url,
            submissions,
            server,
            state,
        })
    }

    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// Wait for the user to submit or decline
    pub async fn next(&mut self) -> Option<Submission> {
        self.submissions.recv().await
    }
}

async fn serve(listener: TcpListener, state: Arc<PageState>) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        // Never closed, so acquiring only waits
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::debug!("secret page stopped accepting connections: {e}");
                return;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, &state).await {
                tracing::debug!("secret page request failed: {e}");
            }
            drop(slot);
        });
    }
}

async fn handle(mut stream: TcpStream, state: &PageState) -> Result<()> {
    let request = match tokio::time::timeout(
        READ_TIMEOUT,
        read_http_request_limited(&mut stream, MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(e)) => {
            respond(&mut stream, 400, &message_page("Bad request", ""), None).await?;
            return Err(FnoxError::Config(e));
        }
        Err(_) => return Ok(()),
    };
    let (status, body) = route(&request, state).await;
    let redirect = (status == 303).then_some(state.path.as_str());
    respond(&mut stream, status, &body, redirect).await
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

async fn route(request: &HttpRequest, state: &PageState) -> (u16, String) {
    // A page on another site can't reach this one through DNS rebinding: its
    // requests carry that site's name in Host.
    if header(request, "host") != Some(state.host.as_str()) {
        return (403, message_page("Forbidden", ""));
    }
    let path = request.target.split('?').next().unwrap_or_default();
    if !constant_time_eq(path.as_bytes(), state.path.as_bytes()) {
        return (404, message_page("Not found", ""));
    }
    let redirect = || (303, String::new());
    match request.method.as_str() {
        "GET" => state.response(),
        "POST" => {
            if header(request, "origin").is_some_and(|origin| origin != state.origin)
                || header(request, "sec-fetch-site")
                    .is_some_and(|site| site != "same-origin" && site != "none")
            {
                return (403, message_page("Forbidden", ""));
            }
            if !matches!(*state.outcome.borrow(), PageOutcome::Pending) {
                return redirect();
            }
            let mut action = None;
            let mut value = None;
            for (key, field) in url::form_urlencoded::parse(&request.body) {
                match key.as_ref() {
                    "action" => action = Some(field.into_owned()),
                    "value" => value = Some(field.into_owned()),
                    _ => {}
                }
            }
            match action.as_deref() {
                Some("decline") => {
                    if !state.claim() {
                        return redirect();
                    }
                    if state.submissions.send(Submission::Declined).await.is_err() {
                        state.complete(expired());
                        return redirect();
                    }
                    state.complete((
                        200,
                        message_page(
                            "Declined",
                            "fnox told the agent that you declined. You can close this tab.",
                        ),
                    ));
                    redirect()
                }
                Some("save") => {
                    // Spaces can be part of a credential, so only an all-blank
                    // value is refused, and the value is kept as entered
                    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
                        return (400, form_page(&state.details, Some("Enter a value.")));
                    };
                    if !state.claim() {
                        return redirect();
                    }
                    let (reply, outcome) = oneshot::channel();
                    if state
                        .submissions
                        .send(Submission::Value { value, reply })
                        .await
                        .is_err()
                    {
                        state.complete(expired());
                        return redirect();
                    }
                    let response = match outcome.await {
                        Ok(Ok(message)) => (200, message_page("Saved", &message)),
                        Ok(Err(error)) => {
                            (500, message_page("fnox could not store the value", &error))
                        }
                        Err(_) => expired(),
                    };
                    state.complete(response);
                    redirect()
                }
                _ => (400, message_page("Bad request", "")),
            }
        }
        _ => (405, message_page("Method not allowed", "")),
    }
}

fn expired() -> (u16, String) {
    (
        410,
        message_page(
            "This request has expired",
            "The agent stopped waiting. Ask it to request the secret again.",
        ),
    )
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
    redirect: Option<&str>,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        _ => "Internal Server Error",
    };
    let location = redirect
        .map(|path| format!("location: {path}\r\n"))
        .unwrap_or_default();
    // no-referrer makes Chromium submit form navigations with Origin: null,
    // which our CSRF check correctly refuses. same-origin preserves Origin
    // while still keeping the one-time URL out of cross-origin referrers.
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n{location}\
         content-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\n\
         cache-control: no-store\r\n\
         referrer-policy: same-origin\r\n\
         x-content-type-options: nosniff\r\n\
         x-frame-options: DENY\r\n\
         content-security-policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| FnoxError::Config(format!("failed to write secret page response: {e}")))?;
    stream.shutdown().await.ok();
    Ok(())
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

const STYLE: &str = "\
:root{--bg:#f6f6f4;--card:#fff;--text:#1d1d1b;--muted:#5d5d58;--border:#d9d9d4;--accent:#2f5bd3;--accent-text:#fff;--note:#f1efe6}\
@media (prefers-color-scheme: dark){:root{--bg:#161615;--card:#20201f;--text:#ecece8;--muted:#a3a39d;--border:#3a3a37;--accent:#7a9cff;--accent-text:#0d0d0c;--note:#2a2924}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}\
main{max-width:560px;margin:48px auto;padding:0 16px}\
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px}\
h1{font-size:20px;margin:0 0 12px}\
p{margin:0 0 12px}\
code{font:14px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}\
.muted{color:var(--muted);font-size:14px}\
.reason{background:var(--note);border-radius:8px;padding:12px;margin:0 0 16px}\
.reason p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}\
.label{font-size:13px;color:var(--muted);margin:0 0 4px}\
.error{color:#c0392b}\
label{display:block;font-weight:600;margin:0 0 6px}\
input{width:100%;padding:10px 12px;font:15px ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text)}\
.actions{display:flex;gap:12px;justify-content:flex-end;align-items:center;margin-top:16px}\
button{font:inherit;border-radius:8px;padding:8px 16px;cursor:pointer}\
.primary{background:var(--accent);color:var(--accent-text);border:0;font-weight:600}\
.secondary{background:none;border:0;color:var(--muted);order:-1}";

fn page(title: &str, content: &str) -> String {
    page_with_head(title, content, "")
}

fn page_with_head(title: &str, content: &str, head: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style>{head}</head>\
         <body><main><div class=\"card\">{content}</div></main></body></html>",
        escape(title)
    )
}

fn message_page(title: &str, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", escape(message))
    };
    page(title, &format!("<h1>{}</h1>{message}", escape(title)))
}

fn form_page(details: &PageDetails, error: Option<&str>) -> String {
    let name = escape(&details.name);
    let reason = details
        .reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
        .map(|reason| {
            format!(
                "<div class=\"reason\"><div class=\"label\">The agent's reason (written by the agent, not fnox)</div><p>{}</p></div>",
                escape(reason.trim())
            )
        })
        .unwrap_or_default();
    let error = error
        .map(|error| format!("<p class=\"error\">{}</p>", escape(error)))
        .unwrap_or_default();
    let profile = if details.profile == "default" {
        String::new()
    } else {
        format!(" in profile <code>{}</code>", escape(&details.profile))
    };
    // Save is the form's first button so Enter saves; CSS shows Decline first.
    page(
        &format!("fnox: {}", details.name),
        &format!(
            "<h1>Enter a value for <code>{name}</code></h1>\
             <p>An AI agent asked fnox for this secret. fnox stores it with provider <code>{provider}</code> and records it in <code>{target}</code>{profile}. The agent is told only that it was stored.</p>\
             {reason}\
             <p class=\"muted\">Enter only the value meant for <code>{name}</code>. fnox never asks for a password manager's master password here.</p>\
             {error}\
             <form method=\"post\" autocomplete=\"off\">\
             <label for=\"value\">Value</label>\
             <input id=\"value\" name=\"value\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\" required autofocus>\
             <div class=\"actions\">\
             <button class=\"primary\" name=\"action\" value=\"save\">Save to fnox</button>\
             <button class=\"secondary\" name=\"action\" value=\"decline\" formnovalidate>Decline</button>\
             </div></form>",
            provider = escape(&details.provider),
            target = escape(&details.target.display().to_string()),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details() -> PageDetails {
        PageDetails {
            name: "API_TOKEN".into(),
            reason: Some("<script>alert(1)</script> create it at example.com".into()),
            provider: "age".into(),
            target: PathBuf::from("/project/fnox.toml"),
            profile: "default".into(),
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    /// Checks that the page is gone rather than that its port refuses connections:
    /// tests run in parallel, and another can bind a freed port before this looks.
    /// It uses a blocking socket because Tokio's paused clock can't bound real I/O.
    async fn assert_page_not_served(url: &url::Url) {
        let address = url.socket_addrs(|| None).unwrap()[0];
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
            url.path()
        );
        let status = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let wait = Duration::from_secs(2);
            let mut stream = std::net::TcpStream::connect_timeout(&address, wait).ok()?;
            stream.set_read_timeout(Some(wait)).ok()?;
            stream.write_all(request.as_bytes()).ok()?;
            let mut status = [0u8; 12];
            stream.read_exact(&mut status).ok()?;
            Some(status)
        })
        .await
        .unwrap();
        assert_ne!(
            status.as_ref(),
            Some(b"HTTP/1.1 200"),
            "the page must stop being served"
        );
    }

    #[tokio::test]
    async fn serves_the_form_only_at_its_token_path() {
        let page = SecretPage::start(details()).await.unwrap();
        let client = client();

        let response = client.get(page.url().clone()).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "same-origin");
        let body = response.text().await.unwrap();
        assert!(body.contains("API_TOKEN"));
        assert!(body.contains("&lt;script&gt;"), "agent text is escaped");
        assert!(!body.contains("<script>"));

        let mut wrong = page.url().clone();
        wrong.set_path("/secret/0000");
        assert_eq!(client.get(wrong).send().await.unwrap().status(), 404);
    }

    #[tokio::test]
    async fn rejects_another_host_name() {
        let page = SecretPage::start(details()).await.unwrap();
        let mut rebound = page.url().clone();
        rebound.set_host(Some("localhost")).unwrap();
        let response = client().get(rebound).send().await.unwrap();
        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn rejects_a_cross_site_post() {
        let page = SecretPage::start(details()).await.unwrap();
        let response = client()
            .post(page.url().clone())
            .header("origin", "https://evil.example")
            .form(&[("action", "save"), ("value", "x")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn rejects_an_opaque_origin_and_cross_site_fetch_metadata() {
        let page = SecretPage::start(details()).await.unwrap();
        for (origin, site) in [
            ("null", "same-origin"),
            (page.state.origin.as_str(), "cross-site"),
        ] {
            let response = client()
                .post(page.url().clone())
                .header("origin", origin)
                .header("sec-fetch-site", site)
                .form(&[("action", "save"), ("value", "x")])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 403);
        }
        assert!(matches!(*page.state.outcome.borrow(), PageOutcome::Pending));
    }

    #[tokio::test]
    async fn hands_over_the_value_as_entered_once() {
        let mut page = SecretPage::start(details()).await.unwrap();
        let url = page.url().clone();
        let origin = format!("http://{}", url.authority());
        let submit = tokio::spawn({
            let url = url.clone();
            async move {
                client()
                    .post(url)
                    .header("origin", origin)
                    .form(&[("value", " secret value "), ("action", "save")])
                    .send()
                    .await
                    .unwrap()
            }
        });

        let Some(Submission::Value { value, reply }) = page.next().await else {
            panic!("expected a value");
        };
        assert_eq!(value, " secret value ");
        let saving = client()
            .get(url.clone())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(saving.contains("Saving your value"));
        assert!(!saving.contains("type=\"password\""));
        reply.send(Ok("stored it".into())).unwrap();
        // request_secret returns at this point. Its confirmation must outlive
        // that tool call, including the POST-to-GET redirect and later reloads.
        drop(page);
        let response = submit.await.unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(response.headers()["location"], url.path());

        for _ in 0..2 {
            let again = client().get(url.clone()).send().await.unwrap();
            assert_eq!(again.status(), 200);
            let body = again.text().await.unwrap();
            assert!(body.contains("<h1>Saved</h1>"));
            assert!(body.contains("stored it"));
            assert!(!body.contains(" secret value "));
            assert!(!body.contains("type=\"password\""));
        }
        let replay = client()
            .post(url)
            .form(&[("action", "save"), ("value", "replacement")])
            .send()
            .await
            .unwrap();
        assert_eq!(
            replay.status(),
            303,
            "a repeat POST only redirects to the result"
        );
    }

    #[tokio::test]
    async fn an_empty_value_shows_the_form_again() {
        let page = SecretPage::start(details()).await.unwrap();
        let response = client()
            .post(page.url().clone())
            .form(&[("value", "   "), ("action", "save")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(response.text().await.unwrap().contains("Enter a value."));
    }

    #[tokio::test]
    async fn refuses_an_oversized_body() {
        let page = SecretPage::start(details()).await.unwrap();
        let value = "x".repeat(MAX_BODY_BYTES + 1);
        let response = client()
            .post(page.url().clone())
            .form(&[("value", value.as_str()), ("action", "save")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn reports_a_decline() {
        let mut page = SecretPage::start(details()).await.unwrap();
        let response = client()
            .post(page.url().clone())
            .form(&[("action", "decline")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        assert!(matches!(page.next().await, Some(Submission::Declined)));
        let url = page.url().clone();
        drop(page);
        let response = client().get(url).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.text().await.unwrap().contains("<h1>Declined</h1>"));
    }

    #[tokio::test]
    async fn preserves_a_storage_failure_without_accepting_another_value() {
        let mut page = SecretPage::start(details()).await.unwrap();
        let url = page.url().clone();
        let submit = tokio::spawn({
            let url = url.clone();
            async move {
                client()
                    .post(url)
                    .form(&[("action", "save"), ("value", "dummy")])
                    .send()
                    .await
                    .unwrap()
            }
        });
        let Some(Submission::Value { reply, .. }) = page.next().await else {
            panic!("expected submission")
        };
        reply.send(Err("provider unavailable".into())).unwrap();
        assert_eq!(submit.await.unwrap().status(), 303);
        let replay = tokio::time::timeout(
            Duration::from_secs(5),
            client()
                .post(url.clone())
                .form(&[("action", "save"), ("value", "replacement")])
                .send(),
        )
        .await
        .expect("a replay must not wait for another provider reply")
        .unwrap();
        assert_eq!(replay.status(), 303);
        assert!(page.submissions.try_recv().is_err());
        drop(page);
        let response = client().get(url).send().await.unwrap();
        assert_eq!(response.status(), 500);
        let body = response.text().await.unwrap();
        assert!(body.contains("provider unavailable"));
        assert!(!body.contains("<h1>Saved</h1>"));
        assert!(!body.contains("type=\"password\""));
    }

    #[tokio::test]
    async fn reports_expiration_when_the_tool_stops_before_storing() {
        let mut page = SecretPage::start(details()).await.unwrap();
        let url = page.url().clone();
        let submit = tokio::spawn({
            let url = url.clone();
            async move {
                client()
                    .post(url)
                    .form(&[("action", "save"), ("value", "dummy")])
                    .send()
                    .await
                    .unwrap()
            }
        });
        let Some(Submission::Value { reply, .. }) = page.next().await else {
            panic!("expected submission")
        };
        drop(reply);
        drop(page);
        assert_eq!(submit.await.unwrap().status(), 303);
        let response = client().get(url).send().await.unwrap();
        assert_eq!(response.status(), 410);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("This request has expired")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn confirmation_listener_closes_at_the_retention_deadline() {
        // Real loopback I/O must not make Tokio auto-advance the paused clock.
        // This runnable task keeps advancement under the test's control.
        let clock_guard = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let page = SecretPage::start(details()).await.unwrap();
        let url = page.url().clone();
        page.state.complete((200, message_page("Saved", "Stored.")));
        let listener = page.server.abort_handle();
        drop(page);
        // Register the delayed shutdown before advancing time.
        tokio::task::yield_now().await;

        tokio::time::advance(CONFIRMATION_LIFETIME - Duration::from_millis(1)).await;
        let response = client().get(url.clone()).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.text().await.unwrap().contains("<h1>Saved</h1>"));

        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..20 {
            if listener.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            listener.is_finished(),
            "the confirmation listener must stop"
        );
        assert_page_not_served(&url).await;
        clock_guard.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_pending_page_closes_the_listener_without_a_grace_period() {
        let page = SecretPage::start(details()).await.unwrap();
        let url = page.url().clone();
        let listener = page.server.abort_handle();
        let before = tokio::time::Instant::now();
        drop(page);
        for _ in 0..20 {
            if listener.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(listener.is_finished(), "a pending listener must stop");
        assert_page_not_served(&url).await;
        assert_eq!(tokio::time::Instant::now(), before);
    }
}
