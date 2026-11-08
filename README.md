# host-header-parser

Splits an HTTP `Host` header value into a hostname and an optional port,
handling bracketed IPv6 literals.

## Usage

```rust
use host_header_parser::parse;

let host = parse("example.com:8080").unwrap();
assert_eq!(host.hostname(), "example.com");
assert_eq!(host.port(), Some(8080));

let v6 = parse("[::1]:443").unwrap();
assert_eq!(v6.hostname(), "::1");
assert_eq!(v6.port(), Some(443));
assert!(v6.is_ipv6());
```

The crate exports exactly three public items:

- `parse(&str) -> Result<HostHeader, ParseError>`
- `HostHeader` with methods `hostname() -> &str`, `port() -> Option<u16>`,
  and `is_ipv6() -> bool`
- `ParseError`, an enum implementing `std::error::Error`

## Why this exists

`Host` is the one header a server cannot avoid reading, and the grammar is
smaller than it looks. The tricky part is the IPv6 form: `[::1]:443` has a
colon inside the brackets and another one outside, so a naive
`split(':')` produces the wrong answer. This crate scans once, tracking
bracket depth, and splits only on the colon that is outside any brackets.

The trade-off is strictness. A permissive parser that accepts
`example.com:80:90` or `example.com:` hides routing bugs until production.
This parser rejects both. It also rejects characters that cannot appear in
a host header (`/`, `?`, `#`, `@`, whitespace, control characters) rather
than guessing what the caller meant.

## The awkward edge

A bracketed IPv6 literal is returned **without** its brackets: `parse("[::1]")`
gives `hostname() == "::1"`. That is what `std::net::Ipv6Addr` and
`SocketAddr` want, but it means `HostHeader::hostname()` is not always a
string you can paste back into a URL. `Display` re-adds the brackets, so
`host.to_string()` round-trips.

Ports are parsed as `u16`. A value above 65535 is an error, not a wrapped
number.
