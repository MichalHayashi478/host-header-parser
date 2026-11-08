//! Parses HTTP `Host` header values into a hostname and an optional port.
//!
//! The parser is intentionally strict: it accepts exactly the syntax that
//! RFC 3986 / RFC 7230 allow in a `Host` header, and rejects everything else
//! with a descriptive error. Being strict here matters because a permissive
//! parser is a common source of request-routing bugs (for example, treating
//! `example.com:80:90` as a valid host).
//!
//! Two decisions are worth calling out:
//!
//! * A bracketed IPv6 literal is recognised by its surrounding `[` and `]`.
//!   The brackets are stripped from the returned hostname, so callers always
//!   get the bare address (`::1`, not `[::1]`). This matches what
//!   `std::net::SocketAddr` and `std::net::Ipv6Addr` expect.
//! * A port is only recognised when it is separated from the hostname by a
//!   single `:` and consists of one or more ASCII digits. An empty port
//!   (`example.com:`) is rejected rather than silently defaulted.

use std::fmt;

/// The result of parsing a `Host` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHeader {
    hostname: String,
    port: Option<u16>,
}

impl HostHeader {
    /// Returns the hostname with any IPv6 brackets removed.
    ///
    /// For `[::1]:8080` this returns `::1`; for `example.com` it returns
    /// `example.com`.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Returns the port, if one was present.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns `true` if the hostname is a bracketed IPv6 literal.
    pub fn is_ipv6(&self) -> bool {
        self.hostname.contains(':')
    }
}

impl fmt::Display for HostHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ipv6() {
            write!(f, "[{}]", self.hostname)?;
        } else {
            write!(f, "{}", self.hostname)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

/// Errors returned when a `Host` header value cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input was empty or contained only whitespace.
    Empty,
    /// The input contained characters that are not allowed in a host header.
    InvalidCharacter(char),
    /// A bracketed IPv6 literal was opened but never closed.
    UnclosedBracket,
    /// A `]` appeared without a matching `[`.
    UnmatchedBracket,
    /// The port was present but not a valid `u16`.
    InvalidPort,
    /// The hostname was empty (for example, `:8080` or `[]`).
    EmptyHost,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "host header is empty"),
            ParseError::InvalidCharacter(c) => write!(f, "invalid character in host header: {:?}", c),
            ParseError::UnclosedBracket => write!(f, "unclosed IPv6 bracket"),
            ParseError::UnmatchedBracket => write!(f, "unmatched closing bracket"),
            ParseError::InvalidPort => write!(f, "port is not a valid u16"),
            ParseError::EmptyHost => write!(f, "hostname is empty"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a `Host` header value into a [`HostHeader`].
///
/// The grammar accepted is:
///
/// ```text
/// host-header = host [ ":" port ]
/// host        = reg-name | IPv4address | "[" IPv6address "]"
/// port        = 1*DIGIT
/// ```
///
/// Leading and trailing ASCII whitespace is stripped before parsing, because
/// some clients (and some proxies) emit it and it is harmless to ignore.
///
/// # Errors
///
/// Returns [`ParseError`] if the value does not match the grammar above.
///
/// # Examples
///
/// ```
/// use host_header_parser::parse;
///
/// let host = parse("example.com:8080").unwrap();
/// assert_eq!(host.hostname(), "example.com");
/// assert_eq!(host.port(), Some(8080));
///
/// let v6 = parse("[::1]:443").unwrap();
/// assert_eq!(v6.hostname(), "::1");
/// assert_eq!(v6.port(), Some(443));
/// assert!(v6.is_ipv6());
/// ```
pub fn parse(input: &str) -> Result<HostHeader, ParseError> {
    let trimmed = input.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    // Split off the port. The split point is the first `:` that is not
    // inside a bracketed IPv6 literal. We scan once so that a stray `:`
    // inside brackets is not mistaken for a port separator.
    let bytes = trimmed.as_bytes();
    let mut in_brackets = false;
    let mut split_at: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => {
                if in_brackets {
                    return Err(ParseError::InvalidCharacter('['));
                }
                in_brackets = true;
            }
            b']' => {
                if !in_brackets {
                    return Err(ParseError::UnmatchedBracket);
                }
                in_brackets = false;
            }
            b':' if !in_brackets => {
                split_at = Some(i);
                break;
            }
            _ => {}
        }
    }

    if in_brackets {
        return Err(ParseError::UnclosedBracket);
    }

    let (host_part, port_part) = match split_at {
        Some(i) => (&trimmed[..i], Some(&trimmed[i + 1..])),
        None => (trimmed, None),
    };

    let hostname = parse_host(host_part)?;

    let port = match port_part {
        None => None,
        Some(p) => {
            if p.is_empty() {
                return Err(ParseError::InvalidPort);
            }
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::InvalidPort);
            }
            Some(p.parse::<u16>().map_err(|_| ParseError::InvalidPort)?)
        }
    };

    Ok(HostHeader { hostname, port })
}

/// Parses the host portion (without a port).
fn parse_host(host: &str) -> Result<String, ParseError> {
    if host.is_empty() {
        return Err(ParseError::EmptyHost);
    }

    if let Some(stripped) = host.strip_prefix('[') {
        // IPv6 literal: must end with `]` and contain no other brackets.
        let inner = stripped
            .strip_suffix(']')
            .ok_or(ParseError::UnclosedBracket)?;
        if inner.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        if inner.contains('[') || inner.contains(']') {
            return Err(ParseError::InvalidCharacter(']'));
        }
        // Reject characters that cannot appear in an IPv6 literal. We do not
        // fully validate the address here (that is `std::net::Ipv6Addr`'s
        // job); we only reject characters that would be structurally wrong.
        for c in inner.chars() {
            if !(c.is_ascii_hexdigit() || c == ':' || c == '.') {
                return Err(ParseError::InvalidCharacter(c));
            }
        }
        return Ok(inner.to_string());
    }

    if host.contains(']') {
        return Err(ParseError::UnmatchedBracket);
    }

    // A plain hostname: reject control characters and whitespace, and reject
    // the characters that are structurally reserved in a Host header.
    for c in host.chars() {
        if c.is_ascii_whitespace() || c.is_control() {
            return Err(ParseError::InvalidCharacter(c));
        }
        if matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']') {
            return Err(ParseError::InvalidCharacter(c));
        }
    }

    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_hostname() {
        let h = parse("example.com").unwrap();
        assert_eq!(h.hostname(), "example.com");
        assert_eq!(h.port(), None);
        assert!(!h.is_ipv6());
    }

    #[test]
    fn hostname_with_port() {
        let h = parse("example.com:8080").unwrap();
        assert_eq!(h.hostname(), "example.com");
        assert_eq!(h.port(), Some(8080));
    }

    #[test]
    fn ipv4_literal() {
        let h = parse("127.0.0.1:3000").unwrap();
        assert_eq!(h.hostname(), "127.0.0.1");
        assert_eq!(h.port(), Some(3000));
    }

    #[test]
    fn ipv6_literal_with_port() {
        let h = parse("[2001:db8::1]:8443").unwrap();
        assert_eq!(h.hostname(), "2001:db8::1");
        assert_eq!(h.port(), Some(8443));
        assert!(h.is_ipv6());
    }

    #[test]
    fn ipv6_literal_without_port() {
        let h = parse("[::1]").unwrap();
        assert_eq!(h.hostname(), "::1");
        assert_eq!(h.port(), None);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let h = parse("  example.com:80  ").unwrap();
        assert_eq!(h.hostname(), "example.com");
        assert_eq!(h.port(), Some(80));
    }

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("   "), Err(ParseError::Empty));
    }

    #[test]
    fn empty_port_is_rejected() {
        assert_eq!(parse("example.com:"), Err(ParseError::InvalidPort));
    }

    #[test]
    fn non_numeric_port_is_rejected() {
        assert_eq!(parse("example.com:http"), Err(ParseError::InvalidPort));
    }

    #[test]
    fn out_of_range_port_is_rejected() {
        assert_eq!(parse("example.com:70000"), Err(ParseError::InvalidPort));
    }

    #[test]
    fn unclosed_bracket_is_rejected() {
        assert_eq!(parse("[::1"), Err(ParseError::UnclosedBracket));
    }

    #[test]
    fn unmatched_closing_bracket_is_rejected() {
        assert_eq!(parse("example.com]"), Err(ParseError::UnmatchedBracket));
    }

    #[test]
    fn empty_bracketed_host_is_rejected() {
        assert_eq!(parse("[]"), Err(ParseError::EmptyHost));
    }

    #[test]
    fn empty_host_with_port_is_rejected() {
        assert_eq!(parse(":8080"), Err(ParseError::EmptyHost));
    }

    #[test]
    fn invalid_character_in_hostname_is_rejected() {
        assert_eq!(parse("exa mple.com"), Err(ParseError::InvalidCharacter(' ')));
        assert_eq!(parse("exa/mple.com"), Err(ParseError::InvalidCharacter('/')));
    }

    #[test]
    fn display_round_trips_ipv6() {
        let h = parse("[::1]:443").unwrap();
        assert_eq!(h.to_string(), "[::1]:443");
        let h2 = parse("example.com:80").unwrap();
        assert_eq!(h2.to_string(), "example.com:80");
        let h3 = parse("example.com").unwrap();
        assert_eq!(h3.to_string(), "example.com");
    }
}
