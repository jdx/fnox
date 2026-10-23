//! Streaming redaction of secret values from a byte stream.
//!
//! Used by `fnox exec` to scrub the child's piped stdout/stderr. Matching is
//! leftmost-longest over raw bytes, so overlapping secrets resolve to the
//! longest one and regex metacharacters in values need no escaping. A value
//! split across read chunks is still caught: bytes that could be the start of a
//! secret are held back until the next chunk (or EOF) decides, so memory stays
//! bounded by the longest secret.

use aho_corasick::{AhoCorasick, MatchKind};
use std::io::{Read, Write};

/// Replacement for every redacted value.
pub const MARKER: &str = "[REDACTED]";

/// Secrets shorter than this are skipped: redacting two-character values
/// corrupts ordinary output.
pub const MIN_REDACT_LENGTH: usize = 3;

/// Trim `value` and return it when it is long enough to redact safely.
pub fn redactable(value: &str) -> Option<&str> {
    let v = value.trim();
    (v.len() >= MIN_REDACT_LENGTH).then_some(v)
}

/// A compiled set of secret values.
pub struct Redactor {
    ac: AhoCorasick,
    patterns: Vec<Vec<u8>>,
    max_len: usize,
}

impl Redactor {
    /// Build from secret values; unusable (empty or too short) values are
    /// dropped. Returns `None` when nothing is left to redact.
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let mut patterns: Vec<Vec<u8>> = values
            .into_iter()
            .filter_map(redactable)
            .map(|v| v.as_bytes().to_vec())
            .collect();
        patterns.sort();
        patterns.dedup();
        if patterns.is_empty() {
            return None;
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .ok()?;
        Some(Self {
            ac,
            patterns,
            max_len,
        })
    }

    /// Redact a complete buffer.
    pub fn redact_all(&self, data: &[u8]) -> Vec<u8> {
        self.ac
            .replace_all_bytes(data, &vec![MARKER.as_bytes(); self.patterns.len()])
    }

    /// Redact `reader` into `writer` in streaming fashion.
    pub fn copy<R: Read, W: Write>(&self, mut reader: R, mut writer: W) -> std::io::Result<()> {
        let mut stream = Stream::new(self);
        let mut chunk = [0u8; 8192];
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let out = stream.push(&chunk[..n]);
            if !out.is_empty() {
                writer.write_all(&out)?;
                writer.flush()?;
            }
        }
        let out = stream.finish();
        writer.write_all(&out)?;
        writer.flush()
    }
}

/// Incremental state: the not-yet-emitted tail of the input.
pub struct Stream<'a> {
    redactor: &'a Redactor,
    pending: Vec<u8>,
}

impl<'a> Stream<'a> {
    pub fn new(redactor: &'a Redactor) -> Self {
        Self {
            redactor,
            pending: Vec::new(),
        }
    }

    /// Feed a chunk; returns the bytes that are now safe to emit.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let len = self.pending.len();

        // Earliest position in the last `max_len - 1` bytes whose suffix could
        // still grow into a secret. Everything before it is decided.
        let hold_from = len.saturating_sub(self.redactor.max_len - 1);
        let safe_end = (hold_from..len)
            .find(|&i| {
                let suffix = &self.pending[i..];
                self.redactor
                    .patterns
                    .iter()
                    .any(|p| p.len() >= suffix.len() && p.starts_with(suffix))
            })
            .unwrap_or(len);

        let mut out = Vec::with_capacity(safe_end);
        let mut pos = 0;
        for m in self.redactor.ac.find_iter(&self.pending) {
            if m.start() >= safe_end {
                break;
            }
            out.extend_from_slice(&self.pending[pos..m.start()]);
            out.extend_from_slice(MARKER.as_bytes());
            pos = m.end();
        }
        if pos < safe_end {
            out.extend_from_slice(&self.pending[pos..safe_end]);
            pos = safe_end;
        }
        self.pending.drain(..pos);
        out
    }

    /// End of input: flush the held-back tail.
    pub fn finish(&mut self) -> Vec<u8> {
        let out = self.redactor.redact_all(&self.pending);
        self.pending.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(values: &[&str], chunks: &[&str]) -> String {
        let r = Redactor::new(values.iter().copied()).unwrap();
        let mut s = Stream::new(&r);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(s.push(c.as_bytes()));
        }
        out.extend(s.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn whole_value() {
        assert_eq!(run(&["hunter22"], &["pw=hunter22\n"]), "pw=[REDACTED]\n");
    }

    #[test]
    fn split_across_every_boundary() {
        let text = "a hunter22 b";
        for i in 1..text.len() {
            assert_eq!(
                run(&["hunter22"], &[&text[..i], &text[i..]]),
                "a [REDACTED] b",
                "split at {i}"
            );
        }
    }

    #[test]
    fn one_byte_chunks() {
        let text = "x=hunter22;y=hunter22";
        let chunks: Vec<String> = text.chars().map(String::from).collect();
        let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
        assert_eq!(run(&["hunter22"], &refs), "x=[REDACTED];y=[REDACTED]");
    }

    #[test]
    fn longest_overlapping_secret_wins() {
        assert_eq!(run(&["abc", "abcdef"], &["v=abcdef"]), "v=[REDACTED]");
        assert_eq!(run(&["abc", "abcdef"], &["v=abc", "def"]), "v=[REDACTED]");
    }

    #[test]
    fn partial_prefix_is_not_swallowed() {
        assert_eq!(run(&["hunter22"], &["hunt", "ing"]), "hunting");
        assert_eq!(run(&["hunter22"], &["hunter2"]), "hunter2");
    }

    #[test]
    fn special_characters_are_literal() {
        assert_eq!(
            run(&["a.b*c(d)[e]+$"], &["k=a.b*c(d)[e]+$ axb"]),
            "k=[REDACTED] axb"
        );
    }

    #[test]
    fn empty_and_short_values_are_skipped() {
        assert!(Redactor::new(["", "  ", "ab"]).is_none());
        assert_eq!(run(&["", "ab", "secret"], &["ab secret"]), "ab [REDACTED]");
    }

    #[test]
    fn values_are_trimmed() {
        assert_eq!(run(&["token123\n"], &["t=token123"]), "t=[REDACTED]");
    }

    #[test]
    fn plain_output_flushes_without_waiting() {
        let r = Redactor::new(["hunter22"]).unwrap();
        let mut s = Stream::new(&r);
        assert_eq!(s.push(b"hello\n"), b"hello\n");
    }

    #[test]
    fn non_utf8_passes_through() {
        let r = Redactor::new(["secret"]).unwrap();
        assert_eq!(r.redact_all(b"\xff secret \xfe"), b"\xff [REDACTED] \xfe");
    }

    #[test]
    fn copy_streams_reader_to_writer() {
        let r = Redactor::new(["hunter22"]).unwrap();
        let mut out = Vec::new();
        r.copy(&b"a hunter22 b"[..], &mut out).unwrap();
        assert_eq!(out, b"a [REDACTED] b");
    }
}
