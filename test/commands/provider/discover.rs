use super::format_items;
use fnox_core::providers::discovery::{DiscoveredItem, DiscoveredVault};

#[test]
fn text_output_preserves_unicode_but_escapes_terminal_controls() {
    let items = vec![DiscoveredItem {
        id: "item".into(),
        title: "Clé\n\u{1b}[31m".into(),
        tags: vec!["project\texample".into()],
        vault: Some(DiscoveredVault {
            id: "vault".into(),
            name: "Engineering".into(),
        }),
    }];
    assert_eq!(
        format_items(&items),
        "ID\tVAULT\tVAULT_ID\tTITLE\tTAGS\nitem\tEngineering\tvault\tClé\\n\\u{1b}[31m\tproject\\texample\n"
    );
}

#[test]
fn no_results_prints_only_the_metadata_header() {
    assert_eq!(format_items(&[]), "ID\tVAULT\tVAULT_ID\tTITLE\tTAGS\n");
}
