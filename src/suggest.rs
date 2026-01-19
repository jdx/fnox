//! String similarity suggestions for better error messages.
//!
//! Provides "did you mean?" suggestions when users mistype secret or provider names.

use strsim::jaro_winkler;

/// Minimum similarity threshold for suggestions (0.0 to 1.0).
/// Jaro-Winkler gives higher scores for strings with common prefixes.
const SIMILARITY_THRESHOLD: f64 = 0.7;

/// Maximum number of suggestions to return.
const MAX_SUGGESTIONS: usize = 3;

/// Find similar strings from a list of candidates.
///
/// Returns a list of candidates sorted by similarity (most similar first),
/// filtered to only include those above the similarity threshold.
pub fn find_similar<'a>(
    input: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Vec<&'a str> {
    let input_lower = input.to_lowercase();

    let mut scored: Vec<_> = candidates
        .into_iter()
        .map(|candidate| {
            let score = jaro_winkler(&input_lower, &candidate.to_lowercase());
            (candidate, score)
        })
        .filter(|(_, score)| *score >= SIMILARITY_THRESHOLD)
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scored
        .into_iter()
        .take(MAX_SUGGESTIONS)
        .map(|(s, _)| s)
        .collect()
}

/// Format suggestions as a human-readable string.
///
/// Returns None if there are no suggestions.
pub fn format_suggestions(suggestions: &[&str]) -> Option<String> {
    match suggestions.len() {
        0 => None,
        1 => Some(format!("Did you mean '{}'?", suggestions[0])),
        _ => {
            let quoted: Vec<_> = suggestions.iter().map(|s| format!("'{}'", s)).collect();
            Some(format!("Did you mean one of: {}?", quoted.join(", ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_similar_exact_match() {
        let candidates = vec!["DATABASE_URL", "API_KEY", "SECRET_TOKEN"];
        let result = find_similar("DATABASE_URL", candidates.iter().map(|s| *s));
        assert_eq!(result, vec!["DATABASE_URL"]);
    }

    #[test]
    fn test_find_similar_typo() {
        let candidates = vec!["DATABASE_URL", "API_KEY", "SECRET_TOKEN"];
        let result = find_similar("DATABSE_URL", candidates.iter().map(|s| *s));
        assert_eq!(result, vec!["DATABASE_URL"]);
    }

    #[test]
    fn test_find_similar_case_insensitive() {
        let candidates = vec!["DATABASE_URL", "API_KEY", "SECRET_TOKEN"];
        let result = find_similar("database_url", candidates.iter().map(|s| *s));
        assert_eq!(result, vec!["DATABASE_URL"]);
    }

    #[test]
    fn test_find_similar_no_match() {
        let candidates = vec!["DATABASE_URL", "API_KEY", "SECRET_TOKEN"];
        let result = find_similar("COMPLETELY_DIFFERENT", candidates.iter().map(|s| *s));
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_similar_provider_names() {
        let candidates = vec!["age", "1password", "aws-kms", "aws-sm", "bitwarden"];
        let result = find_similar("1passwrd", candidates.iter().map(|s| *s));
        assert_eq!(result, vec!["1password"]);
    }

    #[test]
    fn test_format_suggestions_none() {
        assert_eq!(format_suggestions(&[]), None);
    }

    #[test]
    fn test_format_suggestions_single() {
        assert_eq!(
            format_suggestions(&["DATABASE_URL"]),
            Some("Did you mean 'DATABASE_URL'?".to_string())
        );
    }

    #[test]
    fn test_format_suggestions_multiple() {
        assert_eq!(
            format_suggestions(&["DATABASE_URL", "DATABASE_URI"]),
            Some("Did you mean one of: 'DATABASE_URL', 'DATABASE_URI'?".to_string())
        );
    }
}
