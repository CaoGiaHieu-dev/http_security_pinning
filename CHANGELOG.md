## 1.2.1

### Platform Support & Score Improvements
- **Swift Package Manager (SPM) on iOS**:
  - Added modern Swift Package Manager support (`ios/http_security_pinning/Package.swift`) conforming to Flutter 3.44+ specifications and pub.dev requirements.
  - Reorganized iOS native sources to `Sources/http_security_pinning/` and configured dual compatibility for both SPM and CocoaPods.
- **Web & WebAssembly (WASM) Compatibility**:
  - Isolated native `dart:io` symbols from the public library entrypoint using clean conditional web stubs (`web_stub.dart`), ensuring 100% compatibility with Flutter Web and WASM runtimes.
- **Documentation Polish**:
  - Completed documentation comments for all public constructors and properties across caching and web security exception classes.
- **License**:
  - Adopted the BSD 3-Clause License to enforce strict author attribution and protect the author's copyright across all source distributions and derivative works.

## 1.2.0

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

## 1.1.0

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

## 1.0.1

* Fix android namespace

## 1.0.0

* Initial public release of the `http_security_pinning` package.