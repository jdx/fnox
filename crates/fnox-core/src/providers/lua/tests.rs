use super::*;
use crate::providers::Provider;

fn plugin(source: &str) -> (tempfile::TempDir, LuaProvider) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider.lua");
    std::fs::write(&path, source).unwrap();
    let options = IndexMap::from([("prefix".to_string(), "p-".to_string())]);
    let provider =
        LuaProvider::new("corp".to_string(), path.display().to_string(), options).unwrap();
    (dir, provider)
}

#[tokio::test]
async fn gets_values_with_options() {
    let (_dir, provider) = plugin(
        r#"
        return {
          get = function(ctx, ref)
            if ref == "missing" then return nil end
            return ctx.options.prefix .. ref .. "@" .. ctx.provider
          end,
        }
        "#,
    );
    assert_eq!(provider.get_secret("db").await.unwrap(), "p-db@corp");
    assert!(matches!(
        provider.get_secret("missing").await,
        Err(FnoxError::ProviderSecretNotFound { .. })
    ));
    assert_eq!(
        provider.capabilities(),
        vec![ProviderCapability::RemoteRead]
    );
    assert!(provider.put_secret("K", "v").await.is_err());
}

#[tokio::test]
async fn batch_falls_back_to_get() {
    let (_dir, provider) = plugin(r#"return { get = function(ctx, ref) return ref:upper() end }"#);
    let results = provider
        .get_secrets_batch(&[
            ("A".to_string(), "one".to_string()),
            ("B".to_string(), "two".to_string()),
        ])
        .await;
    assert_eq!(results["A"].as_ref().unwrap(), "ONE");
    assert_eq!(results["B"].as_ref().unwrap(), "TWO");
}

#[tokio::test]
async fn uses_get_batch_hook_once() {
    let (_dir, provider) = plugin(
        r#"
        local calls = 0
        return {
          get = function() error("get should not be called") end,
          get_batch = function(ctx, refs)
            calls = calls + 1
            assert(calls == 1, "get_batch called more than once")
            local out = {}
            for _, ref in ipairs(refs) do
              if ref ~= "gone" then out[ref] = ref .. "!" end
            end
            return out
          end,
        }
        "#,
    );
    let results = provider
        .get_secrets_batch(&[
            ("A".to_string(), "x".to_string()),
            ("B".to_string(), "x".to_string()),
            ("C".to_string(), "gone".to_string()),
        ])
        .await;
    assert_eq!(results["A"].as_ref().unwrap(), "x!");
    assert_eq!(results["B"].as_ref().unwrap(), "x!");
    assert!(matches!(
        results["C"],
        Err(FnoxError::ProviderSecretNotFound { .. })
    ));
}

#[tokio::test]
async fn encryption_plugins_round_trip() {
    let (_dir, provider) = plugin(
        r#"
        local b64 = require("fnox.base64")
        return {
          encrypt = function(ctx, value) return b64.encode(value) end,
          get = function(ctx, ref) return b64.decode(ref) end,
        }
        "#,
    );
    assert_eq!(
        provider.capabilities(),
        vec![ProviderCapability::Encryption]
    );
    let stored = provider.put_secret("K", "hunter2").await.unwrap();
    assert_eq!(stored, "aHVudGVyMg==");
    assert_eq!(provider.get_secret(&stored).await.unwrap(), "hunter2");
}

#[tokio::test]
async fn encrypt_takes_precedence_over_put() {
    let (_dir, provider) = plugin(
        r#"
        return {
          encrypt = function(ctx, value) return "enc:" .. value end,
          put = function() error("put should not be called") end,
          get = function(ctx, ref) return ref:sub(5) end,
        }
        "#,
    );
    assert_eq!(
        provider.capabilities(),
        vec![ProviderCapability::Encryption]
    );
    assert_eq!(provider.put_secret("K", "v").await.unwrap(), "enc:v");
}

#[tokio::test]
async fn put_returns_reference() {
    let (_dir, provider) = plugin(
        r#"
        local store = {}
        return {
          put = function(ctx, key, value) store["k/" .. key] = value; return "k/" .. key end,
          get = function(ctx, ref) return store[ref] end,
        }
        "#,
    );
    assert_eq!(
        provider.capabilities(),
        vec![ProviderCapability::RemoteStorage]
    );
    let reference = provider.put_secret("TOKEN", "abc").await.unwrap();
    assert_eq!(reference, "k/TOKEN");
    assert_eq!(provider.get_secret(&reference).await.unwrap(), "abc");
}

#[tokio::test]
async fn maps_errors() {
    let (_dir, provider) = plugin(
        r#"
        local fnox = require("fnox")
        return {
          get = function(ctx, ref)
            if ref == "auth" then fnox.auth_error("run corp login") end
            error("backend exploded")
          end,
        }
        "#,
    );
    let err = provider.get_secret("auth").await.unwrap_err();
    assert!(err.is_auth_error(), "{err:?}");
    assert!(err.to_string().contains("run corp login"), "{err}");

    let err = provider.get_secret("other").await.unwrap_err().to_string();
    assert!(err.contains("backend exploded"), "{err}");
    assert!(!err.contains("stack traceback"), "{err}");
}

#[tokio::test]
async fn reports_load_errors() {
    let (_dir, provider) = plugin("return {");
    let err = provider.get_secret("x").await.unwrap_err();
    assert!(matches!(err, FnoxError::Plugin { .. }), "{err:?}");

    let (_dir, provider) = plugin("return 42");
    let err = provider.get_secret("x").await.unwrap_err().to_string();
    assert!(err.contains("must return a table"), "{err}");

    let (_dir, provider) = plugin("return {}");
    let err = provider.get_secret("x").await.unwrap_err().to_string();
    assert!(err.contains("missing required `get` hook"), "{err}");
}

#[tokio::test]
async fn requires_plugin_modules() {
    let (dir, provider) = plugin(
        r#"
        local util = require("util")
        local json = require("fnox.json")
        return {
          get = function(ctx, ref)
            local decoded = json.decode('{"v": "' .. util.shout(ref) .. '"}')
            return json.encode({ value = decoded.v })
          end,
        }
        "#,
    );
    std::fs::write(
        dir.path().join("util.lua"),
        "return { shout = function(s) return s:upper() end }",
    )
    .unwrap();
    assert_eq!(
        provider.get_secret("hi").await.unwrap(),
        r#"{"value":"HI"}"#
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runs_commands() {
    let (_dir, provider) = plugin(
        r#"
        local cmd = require("fnox.cmd")
        return {
          get = function(ctx, ref)
            if ref == "fail" then return cmd.exec({ "sh", "-c", "echo nope >&2; exit 3" }) end
            local r = cmd.run("cat", { stdin = ref, env = { X = "1" } })
            assert(r.ok and r.status == 0)
            return cmd.exec({ "printf", "%s-%s", r.stdout, os.getenv("HOME") and "home" or "nohome" })
          end,
        }
        "#,
    );
    let value = provider.get_secret("abc").await.unwrap();
    assert!(value.starts_with("abc-"), "{value}");
    let err = provider.get_secret("fail").await.unwrap_err().to_string();
    assert!(err.contains("status 3") && err.contains("nope"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn streams_large_stdin_while_reading_output() {
    let (_dir, provider) = plugin(
        r#"
        local cmd = require("fnox.cmd")
        return {
          get = function(ctx, ref)
            -- `cat` echoes input as it reads, so stdout fills before stdin is done
            local input = string.rep(ref, 1024 * 1024)
            local out = cmd.exec({ "cat" }, { stdin = input })
            return tostring(#out)
          end,
        }
        "#,
    );
    let len = tokio::time::timeout(std::time::Duration::from_secs(20), provider.get_secret("x"))
        .await
        .expect("cmd.exec deadlocked")
        .unwrap();
    assert_eq!(len, (1024 * 1024).to_string());
}

#[tokio::test]
async fn load_failures_report_no_capabilities() {
    let (_dir, provider) = plugin("return {");
    assert!(provider.prepare().await.is_err());
    assert!(provider.capabilities().is_empty());
}

#[tokio::test]
async fn http_module_talks_to_servers() {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/secret/{name}",
        get(
            |axum::extract::Path(name): axum::extract::Path<String>| async move {
                format!("value-of-{name}")
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (_dir, provider) = plugin(
        r#"
        local http = require("fnox.http")
        return {
          get = function(ctx, ref)
            local resp = http.get(ctx.options.prefix .. "/secret/" .. ref)
            if not resp.ok then error("status " .. resp.status) end
            return resp.body
          end,
        }
        "#,
    );
    // Reuse the `prefix` option as the base URL
    let provider = LuaProvider {
        options: IndexMap::from([("prefix".to_string(), format!("http://{addr}"))]),
        ..provider
    };
    assert_eq!(provider.get_secret("db").await.unwrap(), "value-of-db");
}

#[test]
fn classifies_plugin_values() {
    assert!(plugin_is_path("./corp.lua"));
    assert!(plugin_is_path("plugins/corp"));
    assert!(plugin_is_path("~/corp"));
    assert!(plugin_is_path("corp.lua"));
    assert!(!plugin_is_path("corp"));
    assert!(LuaProvider::new("p".into(), "bad name".into(), IndexMap::new()).is_err());
}
