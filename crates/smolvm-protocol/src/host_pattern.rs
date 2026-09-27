//! Matching for persisted network host entries.
//!
//! Bare entries retain the original exact-or-subdomain behavior. New strict
//! entries use `=host` for exact matching or `*.host` for subdomains only.
//! The `=` prefix is internal; users write `--allow-host-pattern host`.

/// Encode an opt-in host pattern for storage alongside legacy entries.
pub fn encode_strict(pattern: &str) -> Result<String, String> {
    let pattern = pattern.trim_end_matches('.');
    let (host, wildcard) = match pattern.strip_prefix("*.") {
        Some(host) => (host, true),
        None => (pattern, false),
    };
    if host.is_empty()
        || host.len() > 253
        || host.contains('*')
        || (!wildcard && host.parse::<std::net::IpAddr>().is_ok())
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!(
            "invalid host pattern {pattern:?}: use an exact DNS hostname or *.domain"
        ));
    }
    Ok(if wildcard {
        format!("*.{}", host.to_ascii_lowercase())
    } else {
        format!("={}", host.to_ascii_lowercase())
    })
}

/// Match a hostname against a legacy or opt-in network entry.
pub fn matches(host: &str, entry: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let entry = entry.trim_end_matches('.').to_ascii_lowercase();
    if let Some(exact) = entry.strip_prefix('=') {
        return !exact.is_empty() && host == exact;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return !suffix.is_empty()
            && host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    }
    !entry.is_empty()
        && (host == entry
            || host
                .strip_suffix(&entry)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

/// Get the exact hostname to resolve into static CIDRs, if one exists.
/// Wildcard entries learn their addresses as concrete DNS queries succeed.
pub fn static_resolution_host(entry: &str) -> Option<&str> {
    if entry.starts_with("*.") {
        None
    } else {
        Some(entry.strip_prefix('=').unwrap_or(entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_and_new_entries_have_distinct_semantics() {
        assert!(matches("api.example.com", "example.com"));
        assert!(matches("example.com", "example.com"));
        let exact = encode_strict("Example.COM").unwrap();
        assert_eq!(exact, "=example.com");
        assert!(matches("EXAMPLE.COM.", &exact));
        assert!(!matches("api.example.com", &exact));
        let wildcard = encode_strict("*.example.com").unwrap();
        assert!(matches("api.example.com", &wildcard));
        assert!(matches("a.b.example.com", &wildcard));
        assert!(!matches("example.com", &wildcard));
        assert!(!matches("notexample.com", &wildcard));
        assert!(!matches("example.com.evil.test", &wildcard));
    }

    #[test]
    fn rejects_invalid_patterns() {
        for pattern in [
            "",
            "*",
            "*.",
            "*.*.example.com",
            "foo*.example.com",
            "https://example.com",
            "example.com:443",
            "1.2.3.4",
        ] {
            assert!(encode_strict(pattern).is_err(), "{pattern}");
        }
    }
}
