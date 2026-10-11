## 2.0.0

Security release fixing the findings of an external audit of 1.2.2. It
contains **breaking changes**; read the migration guide below.

### Security fixes

- **Redirects are re-checked on every hop** (was: followed by the internal
  `dart:io` delegate, outside the pin policy). An HTTPS → HTTP redirect now
  throws `InsecureConnectionException` instead of sending the request, custom
  headers included, in cleartext; a redirect to a host the policy does not
  allow throws `UnpinnedHostException`.
- **Empty configurations fail closed.** An empty pin list (also through
  `UniversalSecurityClient.create()` without pins, or `perHost({})` without
  `allowUnpinnedHosts: true`) used to disable pinning and the HTTPS check
  silently; it now throws an `ArgumentError`.
- **The scheme is checked on every request.** An `http://` URL to a host that
  already had a pinned connection on the same port was sent in cleartext.
- **`connectionFactory` can no longer bypass pinning.** For direct HTTPS
  connections to pinned hosts a plain socket is secured with the pinned
  context; a `SecureSocket` is refused.
- **`honorBadCertificateCallback` bypasses are per request**, never let the
  callback override a connection whose certificate matched a pin (it is only
  notified), and are
  ignored in release builds (was: permanent per-host bypass list, and a `true`
  answer accepted any certificate on the pinned connection).
- **Host names are normalized** (case, trailing dot, punycode, every
  spelling of an IP address such as `127.1` or `[0:0:0:0:0:0:0:1]`):
  `api.example.com.` no longer escapes a per-host pin, and hosts containing
  characters that are invalid in a host name (for example a percent-encoded
  CR/LF) are refused before any connection.
- **Robustness:** host names longer than DNS allows are rejected before
  punycode encoding (a crafted redirect could block the isolate), a TLS
  failure no longer cancels other requests sharing the connection pool,
  invalid `Location` headers raise `RedirectException` (not `ArgumentError`
  or `FormatException`), unpinned hosts share one delegate client, and the
  Android probe uses at most 16 threads.
- **`abort()` reaches the redirect hop in flight** (also while it is being
  probed).
- **Flutter Web**: new `hsp-sig-v2` response-signature scheme. The signature
  now covers the request method, host, path and query, a random per-request
  nonce sent by the client, the status, the content type and the body digest,
  with labelled components. Responses obtained through a browser redirect are
  refused, since the redirect itself is not signed. The 1.x scheme let an attacker move bytes between
  the nonce and the body, reuse a signed response for another endpoint or
  status, and replay responses for 10 minutes.
- **Flutter Web**: a client without `serverPublicKeys` now throws instead of
  accepting every response unverified.
- **Android**: the probe's trust manager records the chain and **rejects** it
  (was: an accept-all `X509TrustManager`, flagged by Google Play and Android
  Lint). A slow server can no longer block the probe beyond its timeout, a
  timeout under 1 ms is no longer "no timeout", and probes no longer run on a
  serial queue (one slow host stalled pinning for every host).
- **iOS**: the chain is read after `SecTrustEvaluateWithError`, only the
  origin is sent to the native side, and probes run concurrently off the main
  thread.

### Breaking changes and migration guide

| 1.x | 2.0.0 |
| :--- | :--- |
| `HttpSecurityPinningClient([])` disabled pinning | Throws `ArgumentError`. Configure at least one pin (two recommended), or use a plain `HttpClient` deliberately. |
| `UniversalSecurityClient.create()` without `spkiPins` worked on mobile | Throws `ArgumentError` on Android, iOS and desktop. |
| Web: `serverPublicKeyBytes: List<int>` | `serverPublicKeys: List<List<int>>` (several keys allow rotation). Without keys the web client throws unless `allowUnverifiedResponses: true`. |
| Web signature: `X-Server-Signature` over `timestamp + nonce + body`, `X-Signature-Timestamp`, `X-Signature-Nonce` | `hsp-sig-v2`: `X-HSP-Signature`, `X-HSP-Created`, client nonce in the `X-HSP-Nonce` request header. **Update your server** (see README). |
| `PayloadVerifier(pinnedPublicKeyBytes: ...)`, configurable header names | `PayloadVerifier(publicKeys: [...])`, fixed header names, `verify()` also takes `method`, `url`, `statusCode`, `nonce`. |
| `HttpSecurityPinningClient.isSupported` was `true` on the web | `false` on the web (browsers cannot pin TLS). |
| `WebSecurityException` implemented `Exception` | Extends `CertificatePinningException`. |
| Redirects to `http://` were followed | Throw `InsecureConnectionException`. |
| `honorBadCertificateCallback` worked in release builds | Ignored in release builds; applies to one request at a time. |
| `retryCount` on the web counted all attempts | Counts retries after the first attempt, like on other platforms; only idempotent requests are retried, and only after network errors. |
| `serverPublicKeyBytes` on `HttpSecurityPinningClient` (all platforms) and `UniversalSecurityClient.create` | `serverPublicKeys: List<List<int>>` everywhere (a compile error until renamed). |
| `UniversalSecurityClient.create(honorBadCertificateCallback: ...)` | Removed: the returned `http.Client` offers no way to set the callback. |
| `UniversalSecurityClient` was a regular class | `abstract final class` (only the static `create`). |
| `PayloadVerifier.defaultSignatureHeader` / `defaultTimestampHeader` / `defaultNonceHeader` and the instance header fields | `PayloadVerifier.signatureHeader`, `createdHeader`, `nonceHeader` constants. |
| Any `timeout`, negative `retryCount` or `retryDelay` accepted | `timeout <= 0`, `retryCount < 0` and `retryDelay < 0` throw `ArgumentError`. |
| Probed chains were cached forever | Cached for 1 hour (`CertificateChainCache.ttl`): hosts are probed again hourly. |
| URLs with non-canonical IP literals or invalid host characters | Normalized (IP literals) or refused with `ArgumentError` (invalid characters). |
| `connectionFactory` could return a `SecureSocket` | Must return a plain `Socket` for direct HTTPS to pinned hosts. |
| Web: a redirected response was verified against its final URL | Refused with `SignatureVerificationException`. |
| `cryptoSha1` (top-level constant) | Removed (internal). |
| Flutter ≥ 3.27.1, Android minSdk 21, iOS 12 | Flutter ≥ 3.41, Android minSdk 24 (Java 17), iOS 13. |
| The client ignored `http_proxy` / `https_proxy` | Like `dart:io`, `findProxy` defaults to `HttpClient.findProxyFromEnvironment`, and the probe uses the same proxy (first entry of the directive). |

### Added

- `HostNormalizer`, `HostPatternMap`, `ProxyDirective`,
  `ProxyAwareCertificateChainFetcher`.
- `NoValidPinsFoundException.leafOnly`: on desktop the message explains that
  only the leaf certificate can be pinned.
- `CertificateChainCache` entries expire (`ttl`, 1 hour by default) and the
  cache is bounded (`maxEntries`, 256).
- Web: `serverPublicKeysByHost` and `allowUnpinnedHosts` on `perHost`,
  `maxResponseBytes` (`ResponseTooLargeException`), and a deadline covering
  the whole verified response. Non-ASCII (internationalized) host names never
  pass unverified on the web: browsers map look-alikes (fullwidth letters,
  `。`) onto ASCII names, so write such hosts in punycode.
- `SignatureBase` and `ResponseSigner` (server reference implementation, with
  a test vector checked against Node.js `crypto`).
- Debug warning when a host has a single pin (no backup).
- Proxy support for the certificate probe (`CONNECT`) on desktop and Android;
  iOS uses the proxy through `NSURLSession`.
- `open()`/`get()`/... keep the query string of `path`.
- iOS privacy manifest; Swift Package Manager header layout as recommended by
  Flutter.

### Documentation

- README rewritten: accurate platform table (desktop pins only the leaf,
  Android sees the server-sent chain), security model, Flutter Web threat
  model and signature specification, correct pin discovery, best practices
  (backup key not yet deployed, no third-party pins, recovery, testing),
  correct API in every snippet (checked by `tool/check_readme_snippets.dart`).
- Corrections to earlier release notes: 1.2.0 did add dependencies
  (`cryptography`, `flutter_web_plugins`); its web support was response
  signing, not TLS pinning, and its "anti-replay protection" was only a
  clock-skew window; native WebCrypto acceleration needs `cryptography` 2.9.0.
  1.1.0 also started to validate pins at construction, added
  `InsecureConnectionException` and keyed the cache by `host:port`. Releases
  1.0.0 to 1.2.1 were published under the MIT License; 1.2.2 and later are
  BSD 3-Clause.

### Tests

- Regression tests for every audit finding (redirects, empty pins, scheme
  reuse, trailing dots, `connectionFactory`, callback bypass, proxies, web
  signature tampering, replay, retries, limits).
- Native tests with real TCP/TLS connections to local servers: Android JUnit
  (`CertificateProbeTest`, `CertificateProbeRealCasesTest`,
  `HttpSecurityPinningPluginTest`: expired, wrong-host, EC and untrusted-CA
  certificates, TLS 1.2/1.3, client-auth servers, SNI, IPv6, closed, reset
  and silent servers, misbehaving proxies, concurrent load) and iOS XCTest
  (`example/ios/RunnerTests`: CONNECT and SNI through a local proxy, refused
  tunnels, closed servers, deadlines, concurrency).
- Rotation-proof integration tests that discover the pins of public hosts
  before pinning them (manual, on a device; not run in CI).

## 1.2.2 - 2026-10-06

### Licensing & Attribution
- **Adopted BSD 3-Clause License**: Migrated from MIT License to the official BSD 3-Clause License to enforce strict author attribution, protect the author's copyright, and prohibit unauthorized name endorsement in derivative products.
- **Source Code Copyright Headers**: Added standard Flutter/Dart SDK copyright headers across all Dart, Swift, Objective-C, and Java source files.

## 1.2.1 - 2026-10-06

### Platform Support & Score Improvements
- **Swift Package Manager (SPM) on iOS**:
  - Added modern Swift Package Manager support (`ios/http_security_pinning/Package.swift`) conforming to Flutter 3.44+ specifications and pub.dev requirements.
  - Reorganized iOS native sources to `Sources/http_security_pinning/` and configured dual compatibility for both SPM and CocoaPods.
- **Web & WebAssembly (WASM) Compatibility**:
  - Isolated native `dart:io` symbols from the public library entrypoint using clean conditional web stubs (`web_stub.dart`), ensuring 100% compatibility with Flutter Web and WASM runtimes.
- **Documentation Polish**:
  - Completed documentation comments for all public constructors and properties across caching and web security exception classes.

## 1.2.0 - 2026-10-06

### New Features & Cross-Platform Support (Flutter Web)
- **Flutter Web Support (Application-Layer Public Key Pinning)**:
  - Eliminated web stubs; fully implemented `HttpSecurityPinningClient` on Flutter Web using `Ed25519` (RFC 8032) cryptographic response signature verification (`PayloadVerifier`) accelerated by the browser's native WebCrypto engine.
  - Added anti-replay attack protection with configurable timestamp tolerance window (`timestampTolerance`).
  - Added typed web security exceptions: `SignatureVerificationException`, `MissingSecurityHeaderException`, `ReplayAttackException`, `MalformedSecurityHeaderException`.
- **Universal Cross-Platform Client (`UniversalSecurityClient`)**:
  - Provides a unified factory `UniversalSecurityClient.create(...)` that automatically uses native TLS SPKI Pinning on mobile/desktop and Application-Layer Signature Pinning on Flutter Web.
- **Web Plugin Registration**: Registered official Flutter Web plugin in `pubspec.yaml` with zero external dependencies.

### Testing
- Expanded test suite to 97 passing tests (93.2% code coverage), adding comprehensive test coverage for Ed25519 payload verification, replay attack prevention, case-insensitive headers, and universal client dispatch.

## 1.1.0 - 2026-10-06

### Security & Architecture Improvements
- **Infinite Recursion Prevention**: Solved `StackOverflowError` when `HttpOverrides.global` is installed by running internal delegate clients in an isolated context using `HttpOverrides.runWithHttpOverrides(..., _NoHttpOverrides())`.
- **Dynamic Certificate Renewal & Cache Invalidation**:
  - Automatically evicts negative and failed cache entries upon TLS handshake errors.
  - Automatically invalidates cached security context and retries once upon `HandshakeException`, seamlessly supporting server certificate rotation without application restart.
- **Thread-Safe Multi-Host Connection Pooling**: Replaced single shared client instance with an asynchronous client connection pool keyed by `host:port`, preventing premature client disposal, race conditions, and socket leaks across concurrent requests.
- **Robust X.509 ASN.1 Parsing**: Enhanced SPKI DER parser to properly handle the optional `[0]` version tag per RFC 5280, supporting X.509 v1, v2, and v3 certificates without index out-of-bounds errors.
- **Modular Architecture**: Restructured codebase into clean domain modules (`client`, `core`, `crypto`, `fetcher`, `service`) with unidirectional dependencies.

### New Features & Enhancements
- **Certificate Inspection & `badCertificateCallback` Integration**:
  - Surface failed or unpinned certificates directly to `HttpClient.badCertificateCallback` via a new `PresentedCertificate` class that implements `dart:io` `X509Certificate` (providing access to `der`, `sha1`, `pem`, `subject`, `issuer`, and validity dates).
  - Added opt-in `honorBadCertificateCallback` parameter (defaults to `false` for fail-safe security), allowing developers to inspect presented certificates or bypass pinning in local development and proxy debugging environments.
- **Desktop Platforms Support**: Added out-of-the-box support for Windows, macOS, and Linux using a pure-Dart leaf certificate probe (`DartIoCertificateFetcher`).
- **Per-Host & Wildcard Pin Policies**: Introduced `HttpSecurityPinningClient.perHost` and `PinPolicy` supporting distinct pin sets for individual hosts or wildcard subdomains (`*.example.com`).
- **Flexible SPKI Pin Formats**: Supported standard base64, unpadded base64, URL-safe base64, and `sha256/` / `sha256=` prefixes with constant-time cryptographic verification.
- **Native Platform Robustness**:
  - **Android**: Direct `SSLSocket` probe with dedicated background thread queue and configurable connection/read timeouts, without dependency on Android system CA store.
  - **iOS**: Upgraded to bounded timeout semaphore wait, ephemeral session configuration, and `SecTrustCopyCertificateChain` (iOS 15+) with backward-compatible fallback.
- **Zero Third-Party PEM Dependencies**: Replaced external `pem` package with native standard library base64 encoding.

### Testing
- Comprehensive unit and component test suite covering OpenSSL-verified cryptographic fixtures, local loopback HTTPS servers, TLS renewals, multi-host concurrency, and certificate callback diagnostics (81 tests passing with 94.2% code coverage).

## 1.0.1 - 2026-05-20

* Fix android namespace

## 1.0.0 - 2025-10-17

* Initial public release of the `http_security_pinning` package.