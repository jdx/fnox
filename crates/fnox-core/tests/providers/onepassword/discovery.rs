use super::parse_items;
use crate::providers::onepassword::OnePasswordProvider;

#[test]
fn discovery_returns_sorted_metadata_without_secret_fields() {
    let items = parse_items(r#"[
      {"id":"z","title":"Zulu","tags":["project/example/dev"],"vault":{"id":"v","name":"Engineering"},"fields":[{"value":"do-not-return"}],"notesPlain":"private notes"},
      {"id":"a","title":"Alpha","vault":{"id":"v","name":"Engineering"}}
    ]"#).unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.title.as_str())
            .collect::<Vec<_>>(),
        vec!["Alpha", "Zulu"]
    );
    assert!(items[0].tags.is_empty());
    assert_eq!(items[1].tags, vec!["project/example/dev"]);
    let output = serde_json::to_value(items).unwrap();
    assert_eq!(
        output[1],
        serde_json::json!({
            "id":"z", "title":"Zulu", "tags":["project/example/dev"], "vault":{"id":"v","name":"Engineering"}
        })
    );
}

#[test]
fn empty_results_are_successful_and_malformed_results_do_not_echo_values() {
    assert!(parse_items("[]").unwrap().is_empty());
    for input in [
        "null",
        "{}",
        "[{}]",
        r#"[{"id":"x","title":{"secret":"do-not-return"}}]"#,
    ] {
        let error = parse_items(input).unwrap_err().to_string();
        assert!(!error.contains("do-not-return"));
    }
}

#[test]
fn duplicate_titles_remain_distinct_and_sort_by_vault_then_id() {
    let items = parse_items(
        r#"[
      {"id":"b","title":"Token","vault":{"id":"v2","name":"Two"}},
      {"id":"c","title":"Token","vault":{"id":"v1","name":"One"}},
      {"id":"a","title":"Token","vault":{"id":"v1","name":"One"}}
    ]"#,
    )
    .unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "c", "b"]
    );
}

#[tokio::test]
async fn blank_tags_fail_before_launching_op() {
    let provider = OnePasswordProvider::new(None, None, None).unwrap();
    for tag in ["", " ", "\t"] {
        assert!(
            provider
                .discover_items(&[tag.to_string()])
                .await
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
    }
}
