use super::plan::*;
use super::server::*;
use super::*;
use crate::config::ProxyRule;
use tokio::io::AsyncReadExt;

fn config() -> ProxyConfig {
    ProxyConfig {
        egress: ProxyEgress::Strict,
        audit: false,
        rules: vec![ProxyRule {
            secret: Some("GITHUB_TOKEN".to_string()),
            lease: None,
            credential: None,
            domain: "api.github.com".to_string(),
            env: None,
            header: Some("authorization".to_string()),
            query: None,
            methods: vec!["GET".to_string()],
            paths: vec!["/repos/example/**".to_string()],
            placeholder: Some("ghp_placeholder".to_string()),
        }],
        ..ProxyConfig::default()
    }
}

fn authorize(
    plan: &ProxyPlan,
    domain: &str,
    method: &str,
    target: &str,
    headers: &mut [(String, String)],
) -> Result<(Vec<String>, String)> {
    let mut url = reqwest::Url::parse(&format!("https://{domain}{target}")).unwrap();
    let injected = plan.policy.authorize(domain, method, &mut url, headers)?;
    Ok((injected, url.to_string()))
}

fn policy() -> ProxyPlan {
    ProxyPlan::new(
        &config(),
        &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn proxy_trust_bundle_includes_native_roots_and_session_ca() {
    let running = RunningProxy::start(policy(), ProxyListener::Loopback)
        .await
        .unwrap();
    let bundle = std::fs::read_to_string(running.ca_path()).unwrap();

    assert!(
        bundle.matches("-----BEGIN CERTIFICATE-----").count() > 1,
        "trust bundle must preserve native roots and append the proxy CA"
    );

    running.shutdown().await;
}

#[tokio::test]
async fn malformed_tls_request_receives_http_error() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let policy = policy().policy;
    let task =
        tokio::spawn(
            async move { proxy_http_request(&mut server, "api.github.com", &policy).await },
        );

    client
        .write_all(b"not an HTTP request\r\n\r\n")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    task.await.unwrap().unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "malformed requests should receive a usable HTTP error"
    );
}

#[test]
fn substitutes_only_on_allowed_route_and_header() {
    let plan = policy();
    let mut headers = vec![(
        "Authorization".to_string(),
        "Bearer ghp_placeholder".to_string(),
    )];
    let (injected, _) = authorize(
        &plan,
        "api.github.com",
        "GET",
        "/repos/example/fnox",
        &mut headers,
    )
    .unwrap();
    assert_eq!(injected, ["GITHUB_TOKEN"]);
    assert_eq!(headers[0].1, "Bearer real-token");
}

#[test]
fn rejects_placeholder_on_wrong_method() {
    let plan = policy();
    let mut headers = vec![(
        "Authorization".to_string(),
        "Bearer ghp_placeholder".to_string(),
    )];
    assert!(
        authorize(
            &plan,
            "api.github.com",
            "DELETE",
            "/repos/example/fnox",
            &mut headers,
        )
        .is_err()
    );
}

#[test]
fn rejects_placeholder_in_another_header() {
    let plan = policy();
    let mut headers = vec![("X-Leak".to_string(), "ghp_placeholder".to_string())];
    assert!(
        authorize(
            &plan,
            "api.github.com",
            "GET",
            "/repos/example/fnox",
            &mut headers
        )
        .is_err()
    );
}

#[test]
fn redacts_reflected_values() {
    let mut body = b"token=real-token".to_vec();
    redact_values(&mut body, &policy().policy.redactions());
    assert_eq!(body, b"token=ghp_placeholder");
}

#[test]
fn redacts_overlapping_values_without_scanning_placeholders() {
    let mut config = config();
    config.rules[0].placeholder = Some("placeholder-with-token".to_string());
    config.rules.push(ProxyRule {
        secret: Some("SHORT_TOKEN".to_string()),
        lease: None,
        credential: None,
        domain: "api.github.com".to_string(),
        env: None,
        header: Some("x-api-key".to_string()),
        query: None,
        methods: vec![],
        paths: vec![],
        placeholder: Some("short-placeholder".to_string()),
    });
    let values = [
        ("GITHUB_TOKEN".to_string(), "real-token".to_string()),
        ("SHORT_TOKEN".to_string(), "token".to_string()),
    ]
    .into_iter()
    .collect();
    let plan = ProxyPlan::new(&config, &values).unwrap();
    let mut body = b"real-token token".to_vec();

    redact_values(&mut body, &plan.policy.redactions());

    assert_eq!(
        body, b"placeholder-with-token short-placeholder",
        "the longer value must match first and replacements must not be rescanned"
    );
}

#[test]
fn rejects_ambiguous_paths() {
    assert!(has_ambiguous_path_encoding(
        "/repos/example/../another/private"
    ));
    assert!(has_ambiguous_path_encoding(
        "/repos/example/%2e%2e/another/private"
    ));
    assert!(has_ambiguous_path_encoding(
        "/repos/example/%252e%252e/another/private"
    ));
    assert!(!has_ambiguous_path_encoding("/repos/example/fnox?dot=.."));
}

#[test]
fn sibling_rules_allow_any_matching_route() {
    let mut config = config();
    config.rules[0].paths = vec!["/repos/example/issues/**".to_string()];
    config.rules.push(ProxyRule {
        secret: Some("GITHUB_TOKEN".to_string()),
        lease: None,
        credential: None,
        domain: "api.github.com".to_string(),
        env: None,
        header: Some("authorization".to_string()),
        query: None,
        methods: vec!["GET".to_string()],
        paths: vec!["/repos/example/pulls/**".to_string()],
        placeholder: Some("ghp_placeholder".to_string()),
    });
    let plan = ProxyPlan::new(
        &config,
        &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let mut headers = vec![(
        "Authorization".to_string(),
        "Bearer ghp_placeholder".to_string(),
    )];

    authorize(
        &plan,
        "api.github.com",
        "GET",
        "/repos/example/pulls/1",
        &mut headers,
    )
    .unwrap();

    assert_eq!(headers[0].1, "Bearer real-token");
}

#[test]
fn single_star_path_does_not_cross_directory_boundaries() {
    let paths = compile_paths(&["/repos/example/*".to_string()])
        .unwrap()
        .unwrap();

    assert!(paths.is_match("/repos/example/fnox"));
    assert!(!paths.is_match("/repos/example/team/fnox"));
}

#[tokio::test]
async fn body_bearing_methods_require_content_length() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    client
        .write_all(b"POST /repos/example/fnox HTTP/1.1\r\nhost: api.github.com\r\n\r\nbody")
        .await
        .unwrap();
    drop(client);

    let error = read_http_request(&mut server).await.err().unwrap();

    assert!(error.to_string().contains("must include content-length"));
}

#[tokio::test]
async fn explicit_empty_request_body_is_allowed() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    client
        .write_all(
            b"POST /repos/example/fnox HTTP/1.1\r\nhost: api.github.com\r\ncontent-length: 0\r\n\r\n",
        )
        .await
        .unwrap();
    drop(client);

    let request = read_http_request(&mut server).await.unwrap();

    assert!(request.body.is_empty());
}

#[test]
fn rejects_overlapping_placeholders() {
    let mut config = config();
    config.rules.push(ProxyRule {
        secret: Some("OTHER_TOKEN".to_string()),
        lease: None,
        credential: None,
        domain: "api.github.com".to_string(),
        env: None,
        header: Some("x-api-key".to_string()),
        query: None,
        methods: vec![],
        paths: vec![],
        placeholder: Some("ghp_placeholder_suffix".to_string()),
    });
    let values = [
        ("GITHUB_TOKEN".to_string(), "real-token".to_string()),
        ("OTHER_TOKEN".to_string(), "other-token".to_string()),
    ]
    .into_iter()
    .collect();
    assert!(ProxyPlan::new(&config, &values).is_err());
}

fn plan_with(rules: Vec<ProxyRule>, value: &str) -> Result<ProxyPlan> {
    let config = ProxyConfig {
        egress: ProxyEgress::Strict,
        audit: false,
        rules,
        ..ProxyConfig::default()
    };
    ProxyPlan::new(
        &config,
        &[("API_KEY".to_string(), value.to_string())]
            .into_iter()
            .collect(),
    )
}

fn query_rule(domain: &str, query: &str) -> ProxyRule {
    ProxyRule {
        secret: Some("API_KEY".to_string()),
        lease: None,
        credential: None,
        domain: domain.to_string(),
        env: None,
        header: None,
        query: Some(query.to_string()),
        methods: vec![],
        paths: vec![],
        placeholder: Some("key_placeholder".to_string()),
    }
}

#[test]
fn substitutes_in_named_query_parameter() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
    let (injected, url) = authorize(
        &plan,
        "maps.example.com",
        "GET",
        "/geocode?q=a%20b&key=key_placeholder&z=1",
        &mut [],
    )
    .unwrap();
    assert_eq!(injected, ["API_KEY"]);
    assert_eq!(
        url,
        "https://maps.example.com/geocode?q=a%20b&key=real-key&z=1"
    );
}

#[test]
fn percent_encodes_substituted_query_value() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a+b/c=d&e").unwrap();
    let (_, url) = authorize(
        &plan,
        "maps.example.com",
        "GET",
        "/?key=key_placeholder",
        &mut [],
    )
    .unwrap();
    assert_eq!(url, "https://maps.example.com/?key=a%2Bb%2Fc%3Dd%26e");
}

#[test]
fn rejects_query_placeholder_in_other_parameter_path_or_header() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
    for target in [
        "/?other=key_placeholder",
        "/?key_placeholder=1",
        "/key_placeholder?key=1",
    ] {
        assert!(
            authorize(&plan, "maps.example.com", "GET", target, &mut []).is_err(),
            "{target} must be refused"
        );
    }
    let mut headers = vec![("Authorization".to_string(), "key_placeholder".to_string())];
    assert!(authorize(&plan, "maps.example.com", "GET", "/", &mut headers).is_err());
}

#[test]
fn rejects_query_placeholder_repeated_or_in_both_places() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
    assert!(
        authorize(
            &plan,
            "maps.example.com",
            "GET",
            "/?key=key_placeholder&key=key_placeholder",
            &mut [],
        )
        .is_err()
    );
    let mut headers = vec![("X-Key".to_string(), "key_placeholder".to_string())];
    assert!(
        authorize(
            &plan,
            "maps.example.com",
            "GET",
            "/?key=key_placeholder",
            &mut headers,
        )
        .is_err()
    );
}

#[test]
fn header_rule_rejects_placeholder_in_query() {
    let plan = policy();
    assert!(
        authorize(
            &plan,
            "api.github.com",
            "GET",
            "/repos/example/fnox?token=ghp_placeholder",
            &mut [],
        )
        .is_err()
    );
}

#[test]
fn query_rule_without_placeholder_leaves_url_untouched() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
    let (injected, url) = authorize(&plan, "maps.example.com", "GET", "/?a=1&&b", &mut []).unwrap();
    assert!(injected.is_empty());
    assert_eq!(url, "https://maps.example.com/?a=1&&b");
}

#[test]
fn redacts_percent_encoded_query_secret() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a b&c").unwrap();
    let mut body = b"Location: /?key=a+b%26c and a b&c".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"Location: /?key=key_placeholder and key_placeholder");
}

#[test]
fn wildcard_domain_matches_exactly_one_label() {
    assert!(domain_matches("*.example.com", "a.example.com"));
    assert!(!domain_matches("*.example.com", "example.com"));
    assert!(!domain_matches("*.example.com", "a.b.example.com"));
    assert!(!domain_matches("*.example.com", "evilexample.com"));
    assert!(!domain_matches("*.example.com", ".example.com"));
    assert!(domain_matches("api.example.com", "api.example.com"));
    assert!(!domain_matches("api.example.com", "a.api.example.com"));
}

#[test]
fn wildcard_rule_authorizes_matching_subdomain_only() {
    let plan = plan_with(vec![query_rule("*.example.com", "key")], "real-key").unwrap();
    assert!(plan.policy.has_domain("maps.example.com"));
    assert!(!plan.policy.has_domain("example.com"));
    assert!(!plan.policy.has_domain("a.b.example.com"));
    let (injected, _) = authorize(
        &plan,
        "maps.example.com",
        "GET",
        "/?key=key_placeholder",
        &mut [],
    )
    .unwrap();
    assert_eq!(injected, ["API_KEY"]);
    assert!(
        authorize(
            &plan,
            "example.com",
            "GET",
            "/?key=key_placeholder",
            &mut []
        )
        .is_err()
    );
}

#[test]
fn validates_wildcard_domains() {
    for good in ["*.example.com", "*.s3.amazonaws.com"] {
        assert!(
            plan_with(vec![query_rule(good, "key")], "v").is_ok(),
            "{good} should be accepted"
        );
    }
    for bad in [
        "*",
        "*.",
        "*.com",
        "**.example.com",
        "a.*.example.com",
        "*example.com",
        "*..example.com",
        "api.*",
        "*.example.com.",
    ] {
        assert!(
            plan_with(vec![query_rule(bad, "key")], "v").is_err(),
            "{bad} should be rejected"
        );
    }
}

#[test]
fn rejects_rule_with_both_header_and_query() {
    let mut rule = query_rule("api.example.com", "key");
    rule.header = Some("x-api-key".to_string());
    assert!(plan_with(vec![rule], "v").is_err());
    assert!(plan_with(vec![query_rule("api.example.com", "")], "v").is_err());
}

#[test]
fn labels_rule_targets() {
    assert_eq!(target_label(&config().rules[0]), "header=authorization");
    assert_eq!(
        target_label(&query_rule("api.example.com", "key")),
        "query=key"
    );
}

#[test]
fn redacts_any_percent_encoding_of_query_secret() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a b&c/d").unwrap();
    let mut body = b"/?k=a%20b%26c%2Fd /?k=a%20b%26c/d /?k=a+b%26c%2fd /?k=%61%20b&c/d".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "/?k=key_placeholder /?k=key_placeholder /?k=key_placeholder /?k=key_placeholder"
    );
}

#[test]
fn header_secret_redaction_stays_exact() {
    let mut body = b"token=real%2Dtoken real-token".to_vec();
    redact_values(&mut body, &policy().policy.redactions());
    assert_eq!(body, b"token=real%2Dtoken ghp_placeholder");
}

#[test]
fn rejects_percent_encoded_placeholder_in_path() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
    for target in [
        "/key%5Fplaceholder?key=key_placeholder",
        "/key_placeholder?key=key_placeholder",
    ] {
        assert!(
            authorize(&plan, "maps.example.com", "GET", target, &mut []).is_err(),
            "{target} must be refused"
        );
    }
}

#[test]
fn redacts_query_secret_containing_percent() {
    let plan = plan_with(vec![query_rule("maps.example.com", "key")], "50%off%41").unwrap();
    let mut body = b"a=50%25off%2541 b=50%off%41 c=50%25off%41 d=50%25off%2541x".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "a=key_placeholder b=key_placeholder c=key_placeholder d=key_placeholderx"
    );
}

#[test]
fn classifies_non_public_addresses() {
    for address in [
        "127.0.0.1",
        "10.1.2.3",
        "172.20.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::1",
        "2001:2::1",
        "3fff::1",
    ] {
        assert!(
            !is_public(address.parse().unwrap()),
            "{address} should not be public"
        );
    }
    for address in [
        "8.8.8.8",
        "140.82.112.6",
        "2606:4700:4700::1111",
        "64:ff9b::808:808",
    ] {
        assert!(
            is_public(address.parse().unwrap()),
            "{address} should be public"
        );
    }
}

#[test]
fn allow_private_permits_listed_networks_only() {
    let destinations = DestinationPolicy {
        allowed: vec![
            parse_network("10.0.0.0/8").unwrap(),
            parse_network("127.0.0.1").unwrap(),
        ],
    };
    assert!(destinations.permits("10.9.8.7".parse().unwrap()));
    assert!(destinations.permits("::ffff:127.0.0.1".parse().unwrap()));
    assert!(!destinations.permits("127.0.0.2".parse().unwrap()));
    assert!(!destinations.permits("169.254.169.254".parse().unwrap()));
    assert!(destinations.permits("8.8.8.8".parse().unwrap()));

    // Entries written in IPv4-mapped form match like their IPv4 form.
    let mapped = DestinationPolicy {
        allowed: vec![
            parse_network("::ffff:127.0.0.1").unwrap(),
            parse_network("::ffff:10.0.0.0/104").unwrap(),
        ],
    };
    assert!(mapped.permits("127.0.0.1".parse().unwrap()));
    assert!(mapped.permits("::ffff:127.0.0.1".parse().unwrap()));
    assert!(mapped.permits("10.200.0.1".parse().unwrap()));
    assert!(!mapped.permits("127.0.0.2".parse().unwrap()));
    assert_eq!(
        parse_network("::ffff:10.0.0.0/104").unwrap(),
        parse_network("10.0.0.0/8").unwrap()
    );
}

#[test]
fn validates_allow_lists() {
    let mut config = config();
    config.allow_domains = vec!["*.com".to_string()];
    assert!(validate_config(&config).is_err());
    config.allow_domains = vec![
        "registry.npmjs.org".to_string(),
        "*.githubusercontent.com".to_string(),
    ];
    assert!(validate_config(&config).is_ok());
    config.allow_private = vec!["10.0.0.0/33".to_string()];
    assert!(validate_config(&config).is_err());
    config.allow_private = vec![
        "10.0.0.0/8".to_string(),
        "fd00::/8".to_string(),
        "192.168.1.5".to_string(),
    ];
    assert!(validate_config(&config).is_ok());
}

fn basic(credentials: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    )
}

#[test]
fn credentials_must_carry_the_session_token() {
    let plan = policy();
    let proxy = &plan.policy;
    let token = &proxy.token;
    assert_eq!(token.len(), 32);
    assert!(proxy.accepts_credentials(&basic(&format!("fnox:{token}"))));
    // The scheme is case-insensitive and the user name is ignored.
    let lowercase = basic(&format!("anyone:{token}")).replacen("Basic", "basic", 1);
    assert!(proxy.accepts_credentials(&lowercase));
    assert!(!proxy.accepts_credentials(&basic("fnox:wrong")));
    assert!(!proxy.accepts_credentials(&basic(token)));
    assert!(!proxy.accepts_credentials(&format!("Bearer {token}")));
    assert!(!proxy.accepts_credentials("Basic not-base64!"));
    assert_ne!(
        token,
        &policy().policy.token,
        "each session gets its own token"
    );
}

async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .map_or(0, |length| length.trim().parse().unwrap());
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    head + &String::from_utf8(body).unwrap()
}

async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &str,
    credentials: Option<&str>,
) -> String {
    let authorization = credentials
        .map(|credentials| format!("Proxy-Authorization: {}\r\n", basic(credentials)))
        .unwrap_or_default();
    let head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    read_response(stream).await
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    address
}

async fn assert_echoes<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

fn tunnel_config(allow_private: &[&str]) -> ProxyConfig {
    let mut config = config();
    config.allow_domains = vec!["localhost".to_string()];
    config.allow_private = allow_private.iter().map(|s| s.to_string()).collect();
    config
}

fn plan_from(config: ProxyConfig) -> ProxyPlan {
    ProxyPlan::new(
        &config,
        &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn loopback_proxy_challenges_then_accepts_credentials_on_one_connection() {
    let echo = echo_server().await;
    let running = RunningProxy::start(
        plan_from(tunnel_config(&["127.0.0.1"])),
        ProxyListener::Loopback,
    )
    .await
    .unwrap();
    let url = running.proxy_url().unwrap();
    assert!(url.starts_with(&format!("http://fnox:{}@127.0.0.1:", running.token)));
    let mut stream = TcpStream::connect(running.address.unwrap()).await.unwrap();
    let target = format!("localhost:{}", echo.port());

    let challenge = connect(&mut stream, &target, None).await;
    assert!(challenge.starts_with("HTTP/1.1 407 "), "{challenge}");
    assert!(
        challenge.contains("proxy-authenticate: Basic"),
        "{challenge}"
    );
    assert!(challenge.contains("connection: keep-alive"), "{challenge}");

    let credentials = format!("fnox:{}", running.token);
    let established = connect(&mut stream, &target, Some(&credentials)).await;
    assert!(established.starts_with("HTTP/1.1 200 "), "{established}");
    assert_echoes(&mut stream).await;
    running.shutdown().await;
}

#[tokio::test]
async fn proxy_refuses_bad_credentials_and_unlisted_or_private_destinations() {
    let echo = echo_server().await;
    let mut config = tunnel_config(&[]);
    config.rules[0].domain = "localhost".to_string();
    config.allow_domains = vec!["127.0.0.1".to_string()];
    let running = RunningProxy::start(plan_from(config), ProxyListener::Loopback)
        .await
        .unwrap();
    let address = running.address.unwrap();
    let credentials = format!("fnox:{}", running.token);
    let attempt = async |target: &str, credentials: Option<&str>| {
        let mut stream = TcpStream::connect(address).await.unwrap();
        connect(&mut stream, target, credentials).await
    };

    let wrong = attempt("example.com:443", Some("fnox:wrong")).await;
    assert!(wrong.starts_with("HTTP/1.1 407 "), "{wrong}");
    assert!(wrong.contains("connection: close"), "{wrong}");

    let unlisted = attempt("example.com:443", Some(&credentials)).await;
    assert!(unlisted.starts_with("HTTP/1.1 403 "), "{unlisted}");
    assert!(
        unlisted.contains("destination is not allowed"),
        "{unlisted}"
    );

    // An allowed tunnel to a loopback address is still refused.
    let tunnel = attempt(&format!("127.0.0.1:{}", echo.port()), Some(&credentials)).await;
    assert!(tunnel.starts_with("HTTP/1.1 403 "), "{tunnel}");
    assert!(tunnel.contains("non-public address"), "{tunnel}");

    // So is a rule's domain that resolves to loopback.
    let injected = attempt("localhost:443", Some(&credentials)).await;
    assert!(injected.starts_with("HTTP/1.1 403 "), "{injected}");
    assert!(injected.contains("non-public address"), "{injected}");
    running.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_listener_is_private_and_removed_on_shutdown() {
    use std::os::unix::fs::PermissionsExt;
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.sock");
    let running = RunningProxy::start(
        plan_from(tunnel_config(&["127.0.0.0/8"])),
        ProxyListener::Unix(path.clone()),
    )
    .await
    .unwrap();
    assert_eq!(running.proxy_url(), None);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let credentials = format!("fnox:{}", running.token);
    let established = connect(
        &mut stream,
        &format!("localhost:{}", echo.port()),
        Some(&credentials),
    )
    .await;
    assert!(established.starts_with("HTTP/1.1 200 "), "{established}");
    assert_echoes(&mut stream).await;

    running.shutdown().await;
    assert!(!path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_is_removed_when_proxy_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.sock");
    let running = RunningProxy::start(policy(), ProxyListener::Unix(path.clone()))
        .await
        .unwrap();
    assert!(path.exists());
    drop(running);
    assert!(!path.exists());
    RunningProxy::start(policy(), ProxyListener::Unix(path.clone()))
        .await
        .expect("the path is free again")
        .shutdown()
        .await;
}

#[test]
fn loggable_targets_drop_credentials_and_queries() {
    for (target, logged) in [
        (
            "http://user:pass@api.example.com/v1?token=SECRET#frag",
            "http://api.example.com/v1",
        ),
        (
            "http://api.example.com:8080/x?key=SECRET",
            "http://api.example.com:8080/x",
        ),
        ("api.example.com:443", "api.example.com:443"),
        ("user:pass@api.example.com:443", "api.example.com:443"),
        ("/path?token=SECRET", "/path"),
    ] {
        assert_eq!(loggable_target(target), logged, "{target}");
    }
}

fn pending_plan() -> ProxyPlan {
    ProxyPlan::new(&config(), &IndexMap::new()).unwrap()
}

#[test]
fn a_rule_without_a_value_is_pending_and_refused() {
    let plan = pending_plan();
    assert_eq!(plan.pending(), vec!["GITHUB_TOKEN".to_string()]);
    assert_eq!(plan.child_env["GITHUB_TOKEN"], "ghp_placeholder");

    let mut headers = vec![(
        "authorization".to_string(),
        "Bearer ghp_placeholder".to_string(),
    )];
    let error = authorize(
        &plan,
        "api.github.com",
        "GET",
        "/repos/example/fnox",
        &mut headers,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("'GITHUB_TOKEN' is not set yet"), "{error}");
    assert_eq!(headers[0].1, "Bearer ghp_placeholder");
}

#[test]
fn a_pending_secret_is_injected_and_redacted_once_set() {
    let plan = pending_plan();
    assert!(plan.policy.redactions().is_empty());
    assert!(
        plan.policy
            .values
            .fill("GITHUB_TOKEN", "real-token".to_string())
            .unwrap()
    );
    // A refresh never replaces a value that is set
    assert!(
        !plan
            .policy
            .values
            .fill("GITHUB_TOKEN", "other-token".to_string())
            .unwrap()
    );
    assert!(plan.pending().is_empty());

    let mut headers = vec![(
        "authorization".to_string(),
        "Bearer ghp_placeholder".to_string(),
    )];
    let (injected, _) = authorize(
        &plan,
        "api.github.com",
        "GET",
        "/repos/example/fnox",
        &mut headers,
    )
    .unwrap();
    assert_eq!(injected, vec!["GITHUB_TOKEN".to_string()]);
    assert_eq!(headers[0].1, "Bearer real-token");

    let mut body = b"echo real-token".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"echo ghp_placeholder");
}

#[test]
fn a_pending_secret_gets_the_startup_checks_when_set() {
    let values = &pending_plan().policy.values;
    assert!(values.fill("GITHUB_TOKEN", String::new()).is_err());
    assert!(
        values
            .fill("GITHUB_TOKEN", "ghp_placeholder".to_string())
            .is_err()
    );
    assert!(
        values
            .fill("GITHUB_TOKEN", "x-ghp_placeholder-x".to_string())
            .is_err()
    );
    assert_eq!(values.pending(), vec!["GITHUB_TOKEN".to_string()]);
}

#[test]
fn a_request_refreshes_only_the_pending_secrets_it_carries() {
    let plan = pending_plan();
    let needed = |method: &str, target: &str, header: &str| {
        let url = reqwest::Url::parse(&format!("https://api.github.com{target}")).unwrap();
        let headers = vec![("authorization".to_string(), header.to_string())];
        plan.policy
            .secrets_needed("api.github.com", method, &url, &headers)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        needed("GET", "/repos/example/fnox", "Bearer ghp_placeholder"),
        vec!["GITHUB_TOKEN".to_string()]
    );
    // No placeholder, another route, or another method: nothing to resolve
    assert!(needed("GET", "/repos/example/fnox", "Bearer other").is_empty());
    assert!(needed("GET", "/user", "Bearer ghp_placeholder").is_empty());
    assert!(needed("POST", "/repos/example/fnox", "Bearer ghp_placeholder").is_empty());
    // authorize refuses a placeholder that appears twice, so no lookup either
    assert!(
        needed(
            "GET",
            "/repos/example/fnox",
            "ghp_placeholder ghp_placeholder"
        )
        .is_empty()
    );
}

#[test]
fn a_misplaced_placeholder_is_reported_before_a_missing_secret() {
    let plan = pending_plan();
    let mut headers = vec![("x-other".to_string(), "ghp_placeholder".to_string())];
    let error = authorize(
        &plan,
        "api.github.com",
        "GET",
        "/repos/example/fnox",
        &mut headers,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("outside its allowed route or target"),
        "{error}"
    );
}

#[test]
fn a_pending_query_secret_is_found_in_its_decoded_parameter_only() {
    let mut config = config();
    config.rules[0].header = None;
    config.rules[0].query = Some("key".to_string());
    config.rules[0].placeholder = Some("<TOKEN>".to_string());
    let plan = ProxyPlan::new(&config, &IndexMap::new()).unwrap();
    let needed = |target: &str, headers: &[(String, String)]| {
        let url = reqwest::Url::parse(&format!("https://api.github.com{target}")).unwrap();
        plan.policy
            .secrets_needed("api.github.com", "GET", &url, headers)
            .len()
    };
    // Percent-encoded in its own parameter: authorize decodes it, so this does too
    assert_eq!(needed("/repos/example/fnox?key=%3CTOKEN%3E", &[]), 1);
    // In another parameter or a header, the rule would refuse it anyway
    assert_eq!(needed("/repos/example/fnox?other=%3CTOKEN%3E", &[]), 0);
    let header = [("authorization".to_string(), "<TOKEN>".to_string())];
    assert_eq!(needed("/repos/example/fnox", &header), 0);
}

#[test]
fn a_replaced_value_stays_redacted() {
    let plan = policy();
    plan.policy
        .values
        .replace("GITHUB_TOKEN", "new-token".to_string())
        .unwrap();
    // A response to a request sent with the old value may still echo it
    let mut body = b"old real-token, new new-token".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"old ghp_placeholder, new ghp_placeholder");
}

#[test]
fn a_forgotten_value_is_pending_and_stays_redacted() {
    let plan = policy();
    plan.policy.values.forget("GITHUB_TOKEN");
    assert_eq!(plan.policy.values.value("GITHUB_TOKEN"), None);
    assert_eq!(
        plan.policy.values.pending(),
        vec!["GITHUB_TOKEN".to_string()]
    );
    let mut body = b"old real-token".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"old ghp_placeholder");
}

fn lease_rule() -> ProxyRule {
    ProxyRule {
        lease: Some("forge".to_string()),
        domain: "forge.example.com".to_string(),
        header: Some("private-token".to_string()),
        methods: vec!["POST".to_string()],
        paths: vec!["/api/v4/projects/42/merge_requests/*/notes".to_string()],
        placeholder: Some("glpat-placeholder".to_string()),
        ..ProxyRule::default()
    }
}

fn lease_config(rules: Vec<ProxyRule>) -> ProxyConfig {
    ProxyConfig {
        egress: ProxyEgress::Strict,
        audit: false,
        rules,
        ..ProxyConfig::default()
    }
}

/// Mints `forge-token-1`, `forge-token-2`, ... and records every call
#[derive(Default)]
struct FakeMinter {
    minted: std::sync::Mutex<Vec<String>>,
    revoked: std::sync::Mutex<Vec<String>>,
    fail: std::sync::atomic::AtomicBool,
    /// Lifetime of each minted lease; `None` never expires
    lifetime: Option<chrono::Duration>,
}

impl LeaseMinter for FakeMinter {
    fn mint<'a>(&'a self, lease: &'a str) -> MintFuture<'a, crate::lease_backends::Lease> {
        Box::pin(async move {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(proxy_error("backend unavailable"));
            }
            // Lets concurrent requests overlap while one is minting
            tokio::task::yield_now().await;
            let mut minted = self.minted.lock().unwrap();
            let id = format!("{lease}-{}", minted.len() + 1);
            minted.push(id.clone());
            Ok(crate::lease_backends::Lease {
                credentials: [(
                    "GITLAB_TOKEN".to_string(),
                    format!("{lease}-token-{}", minted.len()),
                )]
                .into_iter()
                .collect(),
                expires_at: self.lifetime.map(|lifetime| chrono::Utc::now() + lifetime),
                lease_id: id,
            })
        })
    }

    fn revoke<'a>(
        &'a self,
        _lease: &'a str,
        minted: &'a crate::lease_backends::Lease,
    ) -> MintFuture<'a, ()> {
        Box::pin(async move {
            self.revoked.lock().unwrap().push(minted.lease_id.clone());
            Ok(())
        })
    }
}

fn lease_plan(minter: Arc<FakeMinter>) -> ProxyPlan {
    let credentials = [("forge".to_string(), "GITLAB_TOKEN".to_string())]
        .into_iter()
        .collect();
    let plan = ProxyPlan::with_leases(
        &lease_config(vec![lease_rule()]),
        &IndexMap::new(),
        &credentials,
    )
    .unwrap();
    plan.set_lease_minter(minter);
    plan
}

const NOTES: &str = "/api/v4/projects/42/merge_requests/7/notes";

/// Sends one request through the same steps the server takes
async fn send(plan: &ProxyPlan, method: &str, target: &str) -> Result<(Vec<String>, String)> {
    let url = reqwest::Url::parse(&format!("https://forge.example.com{target}")).unwrap();
    let mut headers = vec![("private-token".to_string(), "glpat-placeholder".to_string())];
    plan.policy
        .refresh_pending("forge.example.com", method, &url, &headers)
        .await;
    let (injected, _) = authorize(plan, "forge.example.com", method, target, &mut headers)?;
    Ok((injected, headers[0].1.clone()))
}

#[test]
fn a_rule_names_exactly_one_of_secret_or_lease() {
    let both = ProxyRule {
        secret: Some("GITLAB_TOKEN".to_string()),
        ..lease_rule()
    };
    let error = validate_config(&lease_config(vec![both]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("both secret and lease"), "{error}");

    let neither = ProxyRule {
        lease: None,
        ..lease_rule()
    };
    let error = validate_config(&lease_config(vec![neither]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs a secret or a lease"), "{error}");

    let credential_without_lease = ProxyRule {
        secret: Some("GITLAB_TOKEN".to_string()),
        lease: None,
        credential: Some("GITLAB_TOKEN".to_string()),
        ..lease_rule()
    };
    let error = validate_config(&lease_config(vec![credential_without_lease]))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("credential is only valid with a lease"),
        "{error}"
    );
}

#[test]
fn a_lease_rule_hands_the_child_a_placeholder_under_the_credential_name() {
    let plan = lease_plan(Arc::default());
    assert_eq!(plan.child_env["GITLAB_TOKEN"], "glpat-placeholder");
    // Not a secret: nothing to `fnox set`, and nothing the MCP tools may offer
    assert!(plan.pending().is_empty());
    assert!(plan.handle().rules().is_empty());
}

#[test]
fn rules_for_one_lease_must_pick_the_same_credential() {
    let other = ProxyRule {
        credential: Some("OTHER".to_string()),
        paths: vec![],
        ..lease_rule()
    };
    let credentials = [("forge".to_string(), "GITLAB_TOKEN".to_string())]
        .into_iter()
        .collect();
    let mut first = lease_rule();
    first.credential = Some("GITLAB_TOKEN".to_string());
    let error = ProxyPlan::with_leases(
        &lease_config(vec![first, other]),
        &IndexMap::new(),
        &credentials,
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("different credentials"), "{error}");
}

#[tokio::test]
async fn a_lease_is_minted_on_first_use_and_reused() {
    let minter = Arc::new(FakeMinter::default());
    let plan = lease_plan(minter.clone());
    assert!(minter.minted.lock().unwrap().is_empty(), "minting is lazy");

    let (injected, header) = send(&plan, "POST", NOTES).await.unwrap();
    assert_eq!(injected, vec!["lease:forge".to_string()]);
    assert_eq!(header, "forge-token-1");
    let (_, header) = send(&plan, "POST", NOTES).await.unwrap();
    assert_eq!(header, "forge-token-1");
    assert_eq!(*minter.minted.lock().unwrap(), vec!["forge-1".to_string()]);

    let mut body = b"echo forge-token-1".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"echo glpat-placeholder");
}

#[tokio::test]
async fn a_request_outside_the_rule_mints_nothing() {
    let minter = Arc::new(FakeMinter::default());
    let plan = lease_plan(minter.clone());
    assert!(send(&plan, "GET", NOTES).await.is_err());
    assert!(send(&plan, "POST", "/api/v4/user").await.is_err());
    assert!(minter.minted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_requests_share_one_lease() {
    let minter = Arc::new(FakeMinter::default());
    let plan = Arc::new(lease_plan(minter.clone()));
    let requests = (0..8).map(|_| {
        let plan = plan.clone();
        tokio::spawn(async move { send(&plan, "POST", NOTES).await.unwrap().1 })
    });
    for request in requests {
        assert_eq!(request.await.unwrap(), "forge-token-1");
    }
    assert_eq!(minter.minted.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_expiring_lease_is_minted_again_and_the_old_value_stays_redacted() {
    let minter = Arc::new(FakeMinter {
        // Inside the reuse margin from the start
        lifetime: Some(chrono::Duration::seconds(5)),
        ..FakeMinter::default()
    });
    let plan = lease_plan(minter.clone());
    assert_eq!(send(&plan, "POST", NOTES).await.unwrap().1, "forge-token-1");
    assert_eq!(send(&plan, "POST", NOTES).await.unwrap().1, "forge-token-2");

    let mut body = b"forge-token-1 forge-token-2".to_vec();
    redact_values(&mut body, &plan.policy.redactions());
    assert_eq!(body, b"glpat-placeholder glpat-placeholder");
}

#[tokio::test]
async fn a_failed_mint_refuses_the_request_and_is_retried_later() {
    let minter = Arc::new(FakeMinter::default());
    minter.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let plan = lease_plan(minter.clone());

    let error = send(&plan, "POST", NOTES).await.unwrap_err().to_string();
    assert!(
        error.contains("lease 'forge' could not be created"),
        "{error}"
    );

    minter
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // Within the retry window the failure stands
    assert!(send(&plan, "POST", NOTES).await.is_err());
    plan.policy.leases.retry_now("forge");
    assert_eq!(send(&plan, "POST", NOTES).await.unwrap().1, "forge-token-1");
}

#[tokio::test]
async fn every_lease_minted_in_the_session_is_revoked_at_the_end() {
    let minter = Arc::new(FakeMinter {
        lifetime: Some(chrono::Duration::seconds(5)),
        ..FakeMinter::default()
    });
    let plan = lease_plan(minter.clone());
    let leases = plan.leases();
    send(&plan, "POST", NOTES).await.unwrap();
    send(&plan, "POST", NOTES).await.unwrap();

    leases.revoke_all().await;
    assert_eq!(
        *minter.revoked.lock().unwrap(),
        vec!["forge-1".to_string(), "forge-2".to_string()]
    );
    // Revoking twice does nothing more
    leases.revoke_all().await;
    assert_eq!(minter.revoked.lock().unwrap().len(), 2);
}
