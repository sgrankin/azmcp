//! Validation and canonicalization for caller-supplied relative request targets.

use std::fmt;

use thiserror::Error;
use url::form_urlencoded;

const MAX_TARGET_BYTES: usize = 16 * 1024;
const MAX_QUERY_PAIRS: usize = 64;

/// A relative ARM request target that is safe to join to a reviewed cloud origin.
///
/// This type does not authorize the target. Route matching and subscription-scope checks
/// still run after parsing and before credentials are acquired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeRequestTarget {
    path: String,
    segments: Vec<String>,
    query: Vec<(String, String)>,
}

impl RelativeRequestTarget {
    /// Parse a caller-supplied path without accepting an authority or API-version override.
    pub fn parse(value: &str) -> Result<Self, InvalidRequestTarget> {
        if value.len() > MAX_TARGET_BYTES {
            return Err(InvalidRequestTarget::TooLarge);
        }
        if !value.starts_with('/') || value.starts_with("//") {
            return Err(InvalidRequestTarget::NotRelative);
        }
        if value.contains('#') {
            return Err(InvalidRequestTarget::Fragment);
        }
        if value.contains('\\') {
            return Err(InvalidRequestTarget::Backslash);
        }

        let (path, raw_query) = value
            .split_once('?')
            .map_or((value, None), |(path, query)| (path, Some(query)));

        if path.len() > 1 && path.ends_with('/') {
            return Err(InvalidRequestTarget::TrailingSlash);
        }
        if path.contains("//") {
            return Err(InvalidRequestTarget::DuplicateSlash);
        }

        let mut segments = Vec::new();
        for segment in path.split('/').skip(1) {
            validate_percent_encoding(segment)?;
            let decoded = percent_decode(segment)?;
            if decoded == "." || decoded == ".." {
                return Err(InvalidRequestTarget::DotSegment);
            }
            if decoded.contains('/') || decoded.contains('\\') {
                return Err(InvalidRequestTarget::EncodedSeparator);
            }
            if contains_percent_escape(&decoded) {
                return Err(InvalidRequestTarget::NestedEscape);
            }
            if decoded.chars().any(char::is_control) {
                return Err(InvalidRequestTarget::ControlCharacter);
            }
            segments.push(decoded);
        }

        let query = match raw_query {
            None | Some("") => Vec::new(),
            Some(raw_query) => {
                validate_percent_encoding(raw_query)?;
                let pairs = form_urlencoded::parse(raw_query.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                if pairs.len() > MAX_QUERY_PAIRS {
                    return Err(InvalidRequestTarget::TooManyQueryPairs);
                }
                if pairs.iter().any(|(name, value)| {
                    name.chars().any(char::is_control) || value.chars().any(char::is_control)
                }) {
                    return Err(InvalidRequestTarget::ControlCharacter);
                }
                if pairs
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("api-version"))
                {
                    return Err(InvalidRequestTarget::ApiVersionInQuery);
                }
                pairs
            }
        };

        let path = if path == "/" {
            "/".to_owned()
        } else {
            format!(
                "/{}",
                segments
                    .iter()
                    .map(|segment| form_urlencoded::byte_serialize(segment.as_bytes()).collect())
                    .collect::<Vec<String>>()
                    .join("/")
            )
        };

        Ok(Self {
            path,
            segments,
            query,
        })
    }

    /// The validated encoded path, beginning with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Decoded path segments used for reviewed route-template matching.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Decoded query pairs in caller-supplied order.
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }
}

impl fmt::Display for RelativeRequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.path)?;
        if !self.query.is_empty() {
            formatter.write_str("?")?;
            formatter.write_str(
                &form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(&self.query)
                    .finish(),
            )?;
        }
        Ok(())
    }
}

/// Why a caller-supplied request target was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InvalidRequestTarget {
    /// Targets must start with one slash and cannot contain an authority.
    #[error("request target must be an absolute path without an authority")]
    NotRelative,
    /// URL fragments never reach ARM and can disguise the reviewed target.
    #[error("request target must not contain a fragment")]
    Fragment,
    /// Backslashes have inconsistent path semantics across URL implementations.
    #[error("request target must not contain a backslash")]
    Backslash,
    /// Empty path segments create ambiguous route forms.
    #[error("request target must not contain duplicate slashes")]
    DuplicateSlash,
    /// A trailing slash is a distinct and usually unintended route.
    #[error("request target must not end with a slash")]
    TrailingSlash,
    /// Dot segments must be rejected before a URL library normalizes them.
    #[error("request target must not contain dot segments")]
    DotSegment,
    /// Encoded slash and backslash bytes can bypass route-template matching.
    #[error("request target must not contain encoded path separators")]
    EncodedSeparator,
    /// Percent escapes must be complete hexadecimal bytes.
    #[error("request target contains invalid percent encoding")]
    InvalidPercentEncoding,
    /// Path segments must decode to UTF-8 for deterministic route matching and logging.
    #[error("request target contains a non-UTF-8 path segment")]
    NonUtf8Segment,
    /// A second percent-decoding pass must not change path structure.
    #[error("request target must not contain nested percent escapes")]
    NestedEscape,
    /// Control characters make transport and audit representations ambiguous.
    #[error("request target must not contain control characters")]
    ControlCharacter,
    /// Request targets are bounded before allocation and normalization.
    #[error("request target is too large")]
    TooLarge,
    /// Query cardinality is bounded before policy evaluation.
    #[error("request target has too many query parameters")]
    TooManyQueryPairs,
    /// `api-version` is a separately validated request field.
    #[error("request target query must not contain api-version")]
    ApiVersionInQuery,
}

fn validate_percent_encoding(value: &str) -> Result<(), InvalidRequestTarget> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(InvalidRequestTarget::InvalidPercentEncoding);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn percent_decode(segment: &str) -> Result<String, InvalidRequestTarget> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| InvalidRequestTarget::NonUtf8Segment)
}

fn hex_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("percent encoding was validated before decoding"),
    }
}

fn contains_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_canonicalizes_a_relative_target() {
        let target = RelativeRequestTarget::parse(
            "/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Sql/servers/sql-1?$top=10&name=primary%20db",
        )
        .expect("valid relative target");

        assert_eq!(
            target.path(),
            "/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Sql/servers/sql-1"
        );
        assert_eq!(
            target.segments(),
            [
                "subscriptions",
                "sub",
                "resourceGroups",
                "prod",
                "providers",
                "Microsoft.Sql",
                "servers",
                "sql-1",
            ]
        );
        assert_eq!(
            target.query(),
            &[
                ("$top".to_owned(), "10".to_owned()),
                ("name".to_owned(), "primary db".to_owned()),
            ]
        );
        assert_eq!(
            target.to_string(),
            "/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Sql/servers/sql-1?%24top=10&name=primary+db"
        );
    }

    #[test]
    fn canonicalizes_percent_encoding_once() {
        let target = RelativeRequestTarget::parse("/providers/%4dicr%6fsoft.Sql/caf%C3%A9")
            .expect("valid encoded target");
        assert_eq!(target.path(), "/providers/Microsoft.Sql/caf%C3%A9");
        assert_eq!(target.to_string(), "/providers/Microsoft.Sql/caf%C3%A9");
    }

    #[test]
    fn rejects_authorities_and_absolute_urls() {
        for value in [
            "https://management.azure.com/subscriptions/sub",
            "//management.azure.com/subscriptions/sub",
            "subscriptions/sub",
        ] {
            assert_eq!(
                RelativeRequestTarget::parse(value),
                Err(InvalidRequestTarget::NotRelative),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_path_confusion_before_normalization() {
        let cases = [
            ("/a//b", InvalidRequestTarget::DuplicateSlash),
            ("/a/b/", InvalidRequestTarget::TrailingSlash),
            ("/a/../b", InvalidRequestTarget::DotSegment),
            ("/a/%2e%2E/b", InvalidRequestTarget::DotSegment),
            ("/a/%2fb", InvalidRequestTarget::EncodedSeparator),
            ("/a/%5CB", InvalidRequestTarget::EncodedSeparator),
            ("/a\\b", InvalidRequestTarget::Backslash),
            ("/a#ignored", InvalidRequestTarget::Fragment),
            ("/a/%", InvalidRequestTarget::InvalidPercentEncoding),
            ("/a/%FF", InvalidRequestTarget::NonUtf8Segment),
            ("/a/%252e%252e", InvalidRequestTarget::NestedEscape),
            ("/a/%252f", InvalidRequestTarget::NestedEscape),
            ("/a/%00", InvalidRequestTarget::ControlCharacter),
            ("/a?name=%0a", InvalidRequestTarget::ControlCharacter),
        ];

        for (value, expected) in cases {
            assert_eq!(
                RelativeRequestTarget::parse(value),
                Err(expected),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_any_caller_supplied_api_version() {
        for value in [
            "/subscriptions/sub?api-version=2024-01-01",
            "/subscriptions/sub?API-VERSION=2024-01-01",
            "/subscriptions/sub?api%2Dversion=2024-01-01",
        ] {
            assert_eq!(
                RelativeRequestTarget::parse(value),
                Err(InvalidRequestTarget::ApiVersionInQuery),
                "{value}"
            );
        }
    }
}
