# HttpSecurityPinning

[![pub version](https://img.shields.io/pub/v/http_security_pinning.svg)](https://pub.dev/packages/http_security_pinning)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

A Flutter plugin providing a secure-by-default, production-ready `HttpClient` implementation with Subject Public Key Info (SPKI) SHA-256 certificate pinning.

This package defends your mobile and desktop applications against Man-In-The-Middle (MITM) attacks, rogue Certificate Authorities (CAs), and DNS spoofing by cryptographically verifying the server's public key before allowing HTTP traffic.

---

## Features

- 🛡️ **SPKI SHA-256 Pinning**: Pins cryptographic public keys rather than full certificates. Survives certificate renewals when the same key pair or intermediate CA is used.
- 🌐 **Cross-Platform Support**: Full certificate chain inspection on Android and iOS; leaf certificate pinning on Windows, macOS, and Linux out-of-the-box.
- 🎯 **Per-Host & Wildcard Policies**: Configure distinct pins per host (e.g., `api.example.com`, `auth.example.com`) or wildcards (`*.example.com`).
- ⚡ **Zero-Leakage Concurrency**: Thread-safe client connection pooling and in-flight request deduplication prevent socket leaks and duplicate handshakes.
- 🔄 **Safe Dynamic Rotation**: Automatic TLS cache invalidation and retry if server certificate rotates during app runtime.
- 🛠️ **Seamless Integration**: Drop-in replacement for `dart:io` `HttpClient`, fully compatible with `package:http`, `package:dio`, and `HttpOverrides.global`.
- 🔍 **Diagnostics & Bad Certificate Callback**: Pin validation failures surface to `badCertificateCallback` with a `PresentedCertificate` object (implementing `dart:io` `X509Certificate`) for detailed logging and diagnostics. Controlled debug bypass via opt-in `honorBadCertificateCallback: true`.
- ⏱️ **Exponential Backoff Retries**: Configurable timeouts and exponential backoff retry policy for flaky networks.

---

## Supported Platforms

| Platform | Support | Mechanism | Chain Depth |
| :--- | :---: | :--- | :--- |
| **Android** | ✅ API 21+ | Native TLS probe (`SSLSocket`) | Full chain (Leaf, Intermediate, Root) |
| **iOS** | ✅ iOS 12.0+ | Native TLS probe (`NSURLSession` + `SecTrust`) | Full chain (Leaf, Intermediate, Root) |
| **macOS** | ✅ macOS 10.15+ | Pure-Dart `DartIoCertificateFetcher` | Leaf certificate |
| **Windows** | ✅ Windows 10+ | Pure-Dart `DartIoCertificateFetcher` | Leaf certificate |
| **Linux** | ✅ Any modern distro | Pure-Dart `DartIoCertificateFetcher` | Leaf certificate |
| **Web** | ✅ Supported | Application-Layer Ed25519 Public Key Pinning & Replay Protection | Payload & Response Signature |

> [!NOTE]
> On mobile and desktop platforms, pinning is enforced at the TLS socket level against SPKI hashes. On Flutter Web, where browser sandboxing abstracts the underlying TLS handshake, pinning is cryptographically enforced at the application layer via **Ed25519 Response Signature Verification** and replay protection.
>
> `HttpSecurityPinningClient.isSupported` returns `true` across all platforms (Android, iOS, Windows, macOS, Linux, and Web).

---

## Getting Started

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
  http_security_pinning: ^1.1.0
```

Then run:

```bash
flutter pub get
```

---

## Quick Start

### 1. Simple Single-Host Pinning

```dart
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() async {
  // Pass one or more SPKI SHA-256 hashes (base64 or sha256/... format)
  final client = HttpSecurityPinningClient([
    'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=', // Primary pin
    'k2v657xBsOVe1PQR/JU7tNm+hmd2h0EtTV0mbJ5De+o=', // Backup / rotation pin
  ]);

  final ioClient = IOClient(client);

  try {
    final response = await ioClient.get(Uri.parse('https://github.com'));
    print('Status: ${response.statusCode}');
  } finally {
    ioClient.close();
  }
}
```

---

### 2. Multi-Host Pinning with Wildcards

Use `HttpSecurityPinningClient.perHost` when your application communicates with multiple backends or third-party APIs:

```dart
final client = HttpSecurityPinningClient.perHost(
  {
    // Exact host match
    'api.example.com': [
      '6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=',
    ],
    // Wildcard match for all subdomains
    '*.cdn.example.com': [
      'eHDSOkYgiJphKpIaKaW52Pn7mp0HFI9Af8AuoVP4op8=',
    ],
  },
  allowUnpinnedHosts: false, // Default is false: blocks unpinned hosts
  timeout: const Duration(seconds: 15),
  retryCount: 2,
);
```

---

### 3. Usage with `Dio`

For `dio` 5.x+, configure `createHttpClient` on `IOHttpClientAdapter`:

```dart
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() async {
  final dio = Dio();

  (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
    return HttpSecurityPinningClient([
      'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=',
    ]);
  };

  final response = await dio.get('https://github.com');
  print('Status code: ${response.statusCode}');
}
```

---

### 4. Global Pinning with `HttpOverrides`

Apply SPKI pinning transparently across all `HttpClient` calls in your app (including image loading and third-party libraries) without modifying individual request call sites:

```dart
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

class SecureHttpOverrides extends HttpOverrides {
  final List<String> pins;
  SecureHttpOverrides(this.pins);

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return HttpSecurityPinningClient(
      pins,
      timeout: const Duration(seconds: 10),
      retryCount: 2,
    );
  }
}

void main() {
  HttpOverrides.global = SecureHttpOverrides([
    'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=',
  ]);

  runApp(const MyApp());
}
```

> [!NOTE]
> `HttpSecurityPinningClient` internally isolates its internal connections from `HttpOverrides.global`, preventing infinite recursion / `StackOverflowError`.

---

## How to Obtain Your SPKI Hash

### Option A: Using OpenSSL (Recommended)

Run the following command in terminal to extract the leaf certificate's SPKI SHA-256 hash:

```bash
openssl s_client -servername example.com -connect example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

### Option B: Automatic Hash Discovery via Debug Logs

Run a test request with an empty pin list or a placeholder pin. In debug mode, `HttpSecurityPinningClient` prints the SPKI SHA-256 hashes of all certificates presented by the server:

```text
HttpSecurityPinning: Certificate chain for example.com:
  [0] 6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY= (Leaf)
  [1] eHDSOkYgiJphKpIaKaW52Pn7mp0HFI9Af8AuoVP4op8= (Intermediate)
  [2] pkxmZ+2TONzz6JwpGl/qh+1XL7DIvPmWO4sa+yE2sY8= (Root)
```

Copy the desired hash into your configuration.

---

## Handling `badCertificateCallback`

When a server certificate fails SPKI verification or OS handshake verification, `HttpSecurityPinningClient` invokes `badCertificateCallback` with a `PresentedCertificate` object implementing `dart:io` `X509Certificate`.

### Inspecting Failed Certificates for Diagnostics

```dart
final client = HttpSecurityPinningClient(['EXPECTED_PIN_HASH']);

client.badCertificateCallback = (cert, host, port) {
  print('Pinning failed for $host:$port');
  print('Subject: ${cert.subject}');
  print('Issuer: ${cert.issuer}');
  print('Valid: ${cert.startValidity} to ${cert.endValidity}');
  print('SHA-1: ${cert.sha1.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':')}');
  print('PEM:\n${cert.pem}');

  // By default, returning true or false here logs information,
  // but connection STILL FAILS with NoValidPinsFoundException (secure-by-default).
  return false;
};
```

### Debug Bypass Mode (`honorBadCertificateCallback: true`)

If you want `badCertificateCallback` return value to actually override pinning failure (e.g. in development environments or test proxies like Charles/Proxyman):

```dart
final client = HttpSecurityPinningClient(
  ['EXPECTED_PIN_HASH'],
  honorBadCertificateCallback: true, // ⚠️ Opt-in override
);

client.badCertificateCallback = (cert, host, port) {
  // Return true ONLY for trusted local debug environments!
  if (kDebugMode && host == 'staging.local') {
    return true; // Connection allowed despite pin mismatch
  }
  return false; // Connection rejected
};
```

> [!CAUTION]
> Setting `honorBadCertificateCallback: true` and returning `true` completely disables MITM protection for that request. Never enable this unconditionally in release builds!

---

## Error Handling

All exceptions inherit from `CertificatePinningException`:

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

try {
  final response = await client.getUrl(Uri.parse('https://example.com'));
} on NoValidPinsFoundException catch (e) {
  // MITM attack detected or pins are out of date!
  print('Pin mismatch on ${e.host}:${e.port}');
  print('Configured pins: ${e.expectedPins}');
  print('Observed pins from server: ${e.observedPins}');
} on CertificateFetchException catch (e) {
  // Network failure or timeout while probing certificates
  print('Failed to probe certificate: ${e.message} (Retryable: ${e.isRetryable})');
} on UnpinnedHostException catch (e) {
  // Host was not defined in perHost policy and allowUnpinnedHosts is false
  print('Host ${e.host} is not allowed');
} on InvalidPinException catch (e) {
  // Malformed pin provided in configuration (e.g. wrong base64 length)
  print('Invalid pin format: ${e.message}');
} catch (e) {
  print('Other error: $e');
}
```

---

## Unified Cross-Platform Usage (`UniversalSecurityClient`)

For applications running across **both Mobile/Desktop and Flutter Web**, `UniversalSecurityClient` provides a drop-in `http.Client` that automatically applies the correct cryptographic protection:

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

final client = UniversalSecurityClient.create(
  // Native (Mobile & Desktop): TLS SPKI Pinning
  spkiPins: [
    '6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=',
  ],
  // Web: Server Ed25519 Public Key bytes (32 bytes)
  serverPublicKeyBytes: [/* 32-byte Ed25519 public key */],
);

// Works transparently on Android, iOS, Windows, macOS, Linux, and Web!
final response = await client.get(Uri.parse('https://api.example.com/data'));
print('Status: ${response.statusCode}');
```

### Backend Setup for Web Support

On Flutter Web, the client expects the server to sign response payloads using an Ed25519 private key:

- `X-Server-Signature`: Base64-encoded 64-byte Ed25519 digital signature of `TimestampBytes + BodyBytes`.
- `X-Signature-Timestamp`: Generation timestamp in milliseconds since epoch (e.g. `1728212400000`).
- Ensure CORS exposes these headers: `Access-Control-Expose-Headers: X-Server-Signature, X-Signature-Timestamp`.

---

## Configuration Reference

### `HttpSecurityPinningClient`

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `pins` | `List<String>` | required | List of SPKI SHA-256 hashes for all hosts. |
| `timeout` | `Duration` | `10s` | Network timeout for probing certificate chains. |
| `retryCount` | `int` | `3` | Max retry attempts upon probe failure. |
| `retryDelay` | `Duration` | `500ms` | Base exponential backoff delay between retries. |
| `honorBadCertificateCallback` | `bool` | `false` | If `true`, returning `true` from `badCertificateCallback` bypasses pin mismatch. |
| `onLog` | `void Function(String)?` | `null` | Optional custom logger callback. |

### `HttpSecurityPinningClient.perHost`

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `pinsByHost` | `Map<String, List<String>>` | required | Map of host patterns (`api.example.com` or `*.example.com`) to pins. |
| `allowUnpinnedHosts` | `bool` | `false` | When `true`, requests to hosts not in `pinsByHost` bypass pinning instead of failing. |
| `timeout` | `Duration` | `10s` | Network timeout for probing certificate chains. |
| `retryCount` | `int` | `3` | Max retry attempts upon probe failure. |
| `retryDelay` | `Duration` | `500ms` | Base exponential backoff delay between retries. |
| `honorBadCertificateCallback` | `bool` | `false` | Debug bypass flag. |

---

## Best Practices for Certificate Pinning

1. **Always Pin Multiple Keys**: Pin at least the current leaf key and a backup intermediate or offline leaf key. This prevents application downtime during emergency certificate re-issuance.
2. **Prefer SPKI Over Leaf Certificate Pinning**: SPKI hashes pin only the public key. When renewing your TLS certificate with the Certificate Signing Request (CSR) created with the same private key, the SPKI hash remains identical.
3. **Use Per-Host Policies**: Separate pins for third-party endpoints (e.g. Payment Gateway, OAuth provider) from your own API endpoints.

---

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.