# http_security_pinning

[![pub version](https://img.shields.io/pub/v/http_security_pinning.svg)](https://pub.dev/packages/http_security_pinning)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

TLS certificate pinning for Flutter. `HttpSecurityPinningClient` is a drop-in
`dart:io` `HttpClient` (usable with `package:http`, `package:dio` and
`HttpOverrides`) that only completes a TLS connection when the server's
public key matches one of your **SPKI SHA-256 pins**.

On **Flutter Web**, where browsers do not allow TLS pinning, the package
instead verifies **Ed25519 signatures on responses** made by your server. This
is a different, weaker guarantee; read [Flutter Web](#flutter-web-response-signatures-not-tls-pinning)
before relying on it.

> [!WARNING]
> Pinning trades flexibility for protection. If the server's keys change and
> none of your pins matches any more, **every pinned request fails until users
> install an app update**. Before you pin, read [Best practices](#best-practices),
> always ship a backup pin, and make sure you control the keys you pin.

---

## Contents

- [Platform support](#platform-support)
- [Installation](#installation)
- [Getting your pins](#getting-your-pins)
- [Usage](#usage)
- [How it works (security model)](#how-it-works-security-model)
- [Flutter Web: response signatures, not TLS pinning](#flutter-web-response-signatures-not-tls-pinning)
- [Debugging and `badCertificateCallback`](#debugging-and-badcertificatecallback)
- [Error handling](#error-handling)
- [Configuration reference](#configuration-reference)
- [Best practices](#best-practices)
- [Testing](#testing)

---

## Platform support

| Platform | Mechanism | Certificates the pins are compared with |
| :--- | :--- | :--- |
| **Android** (API 24+) | Native TLS probe, then the `dart:io` request trusts only the matching certificates | The chain **the server sends**: leaf and intermediates. Servers rarely send their root, so do not rely on root pins. |
| **iOS** (13+) | Native TLS probe (`NSURLSession` + `SecTrust`), then the same as Android | The chain **built by iOS**: leaf, intermediates and usually the root (which may come from the device trust store). |
| **macOS, Windows, Linux** | Pure `dart:io` probe | **Only the leaf certificate.** Intermediate and root pins can never match on desktop. |
| **Web** | No TLS pinning (browsers do not allow it). Ed25519 response-signature check (required unless explicitly disabled) | Not applicable: `HttpSecurityPinningClient.isSupported` is `false` on the web. |

Pins configured for a host are therefore portable across platforms only if
they include the **leaf key** (plus a backup key).

---

## Installation

```yaml
dependencies:
  http_security_pinning: ^2.0.0
```

Requirements: Flutter 3.41 or newer, Android `minSdk` 24, iOS 13.

Upgrading from 1.x? Version 2.0.0 contains breaking security fixes: see the
[migration guide in the changelog](CHANGELOG.md#200).

---

## Getting your pins

A pin is the base64 SHA-256 digest of a certificate's DER encoded
*SubjectPublicKeyInfo* (RFC 7469). `sha256/` prefixes and URL-safe or
unpadded base64 are accepted too.

### From the server, with OpenSSL

```bash
# Every certificate the server sends, leaf first, with its pin.
openssl s_client -servername api.example.com -connect api.example.com:443 -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/{n++} n>0 {print > ("cert" n ".pem")}'
for f in cert*.pem; do
  echo "$f: $(openssl x509 -in "$f" -noout -subject)"
  openssl x509 -in "$f" -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | openssl enc -base64
done
```

On Windows, run these commands in Git Bash (it ships OpenSSL).

### For a backup key that is not deployed yet

Generate the next key pair now, keep it offline, and pin it in the app so that
you can switch to it without an app update:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out next.key
openssl pkey -in next.key -pubout -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

### From the app (any build mode)

Connect once with a pin that cannot match: the error lists what the server
presented (`observedPins`, leaf first). Verify the values out of band (for
example with OpenSSL) before shipping them.

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

Future<List<String>> discoverPins(Uri url) async {
  final client = HttpSecurityPinningClient([
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // matches nothing
  ]);
  try {
    await (await client.getUrl(url)).close();
    return const [];
  } on NoValidPinsFoundException catch (e) {
    return e.observedPins;
  } finally {
    client.close(force: true);
  }
}
```

The example app has a **Discover pins** button doing exactly this.

---

## Usage

All pins and keys in the snippets below are **placeholders that match nothing**: replace them with your own values. Never copy a pin or key from documentation, tests or fixtures into an app: their private keys may be public.

### With `package:http`

```dart
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Future<void> main() async {
  final client = IOClient(HttpSecurityPinningClient([
    'PRIMARY0PIN000000000000000000000000000000AA=', // your current key
    'BACKUP00PIN000000000000000000000000000000AA=', // your backup key
  ]));
  try {
    final response = await client.get(Uri.parse('https://api.example.com/'));
    print(response.statusCode);
  } finally {
    client.close();
  }
}
```

An empty pin list throws an `ArgumentError`: it would disable pinning.

### Several hosts, wildcards

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

final client = HttpSecurityPinningClient.perHost(
  {
    'api.example.com': [
      'PRIMARY0PIN000000000000000000000000000000AA=',
      'BACKUP00PIN000000000000000000000000000000AA=',
    ],
    // Any depth of subdomain (a.cdn.example.com, a.b.cdn.example.com),
    // but NOT cdn.example.com itself: list it separately if needed.
    '*.cdn.example.com': [
      'CDN0PRIMARY0000000000000000000000000000000A=',
      'CDN0BACKUP00000000000000000000000000000000A=',
    ],
  },
  // false (default): other hosts throw UnpinnedHostException.
  // true: other hosts use the normal system trust store, without pinning.
  allowUnpinnedHosts: false,
);
```

Host names are compared case-insensitively, without a trailing dot, and
internationalized names are compared in their punycode form.

### With `package:dio`

```dart
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Future<void> main() async {
  final dio = Dio();
  (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () =>
      HttpSecurityPinningClient([
        'PRIMARY0PIN000000000000000000000000000000AA=',
        'BACKUP00PIN000000000000000000000000000000AA=',
      ]);
  try {
    final response = await dio.get<String>('https://api.example.com/');
    print(response.statusCode);
  } on DioException catch (e) {
    // Dio wraps errors: the pinning exception is in `e.error`.
    if (e.error is NoValidPinsFoundException) print('Pin mismatch');
    rethrow;
  } finally {
    dio.close();
  }
}
```

### App-wide with `HttpOverrides`

`HttpOverrides.global` affects every `dart:io` `HttpClient` of the app
(including `NetworkImage` and packages built on `dart:io`). Use a **per-host**
policy with `allowUnpinnedHosts: true` so that hosts you do not pin (CDNs,
analytics, map tiles) keep working:

```dart
import 'dart:io';

import 'package:http_security_pinning/http_security_pinning.dart';

class PinnedHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    // `context` is ignored: pinned hosts use their own SecurityContext.
    return HttpSecurityPinningClient.perHost(
      {
        'api.example.com': [
          'PRIMARY0PIN000000000000000000000000000000AA=',
          'BACKUP00PIN000000000000000000000000000000AA=',
        ],
      },
      allowUnpinnedHosts: true,
    );
  }
}

void main() {
  HttpOverrides.global = PinnedHttpOverrides();
  // runApp(...);
}
```

`HttpOverrides` does **not** affect native networking: WebViews,
`cupertino_http`, `cronet_http`, Firebase and other native SDKs. Pin those
with the platform's own mechanism (Android Network Security Config `pin-set`,
iOS `NSPinnedDomains`).

### One client for mobile, desktop and web

`UniversalSecurityClient` returns an `http.Client` that pins TLS on Android,
iOS and desktop, and verifies response signatures on the web:

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

final client = UniversalSecurityClient.create(
  // Android, iOS, desktop: required, TLS SPKI pinning.
  spkiPins: [
    'PRIMARY0PIN000000000000000000000000000000AA=',
    'BACKUP00PIN000000000000000000000000000000AA=',
  ],
  // Web: required, the server's Ed25519 public keys (32 bytes each).
  serverPublicKeys: [
    PayloadVerifier.decodeBase64('SERVER0KEY0CURRENT000000000000000000000000A='),
  ],
);
```

Each platform throws an `ArgumentError` when the setting it relies on is
missing, instead of silently sending unprotected requests.

---

## How it works (security model)

For every request, `HttpSecurityPinningClient`:

1. **Checks the policy** for the target host: hosts not allowed by a per-host
   policy throw `UnpinnedHostException`, and a non-HTTPS URL to a pinned host
   throws `InsecureConnectionException`.
2. **Probes the server's certificate chain** once per `host:port` (cached for
   one hour by default, see `CertificateChainCache`). No request is ever sent
   on the probe connection: Android, iOS and the desktop probe through a
   proxy abort the TLS handshake as soon as the chain is known; the direct
   desktop probe completes the handshake and closes the socket. When
   `findProxy` (by default the `http_proxy` / `https_proxy` environment
   variables, like `dart:io`) chooses a proxy, the probe goes through the
   first proxy of the directive, without falling back to further entries.
   Credentials embedded in the directive (`PROXY user:pass@host:port`) are
   used; those set with `addProxyCredentials` are not.
3. **Keeps only the certificates whose SPKI hash matches a pin**. No match:
   `NoValidPinsFoundException` (fail closed).
4. **Sends the request on a connection whose only trust anchors are those
   certificates** (`SecurityContext(withTrustedRoots: false)`). The TLS
   handshake still verifies the host name, the validity period and the
   signatures up to the matched certificate, before any request byte is sent.
   A different certificate presented on this connection, even one carrying a
   pinned key with a forged issuer, is rejected.

Consequences worth knowing:

- **Pinning replaces the system CA check, it does not add to it.** A
  certificate chaining to a pinned key is accepted even if the system does not
  trust its root; revocation and Certificate Transparency are not checked.
  Expired certificates and host name mismatches are still rejected.
- **Redirects are followed by the client itself**, so every hop goes through
  steps 1–4. A redirect from HTTPS to HTTP throws
  `InsecureConnectionException`; a redirect to a host the policy does not
  allow throws `UnpinnedHostException`. `abort()` reaches the hop in flight.
  `Authorization`, `Proxy-Authorization` and cookies are dropped on
  cross-origin redirects, like `dart:io` does, but **custom headers such as
  `X-API-Key` are forwarded** to the next host the policy allows (with
  `allowUnpinnedHosts: true` this can be an unpinned host, checked only by the
  system trust store): set `followRedirects = false` on requests that carry
  such secrets if your API may redirect to another host.
- **A custom `connectionFactory`** must return a plain `Socket` for direct
  HTTPS connections to pinned hosts: the client secures it with the pinned
  context. A `SecureSocket` is refused, since how it was validated is
  unknown. The probe does not use the factory.
- **Host names** are normalized before the policy lookup: case, a trailing
  dot, Unicode vs punycode and every spelling of an IP address
  (`127.1`, `0x7f.0.0.1`, `[0:0:0:0:0:0:0:1]`) are equivalent. URLs whose host
  contains characters that are not valid in a host name are refused with an
  `ArgumentError`.
- **Certificate renewal:** after a TLS failure the chain is probed again once
  and the request retried. This helps only if the new key is already pinned.
- **Failed probes** (network errors, timeouts) are retried `retryCount` times
  with a linear delay (`retryDelay * attempt`). With the defaults, an
  unreachable host fails after about 45 seconds (4 × 10 s plus delays); lower
  `timeout` / `retryCount` for interactive requests.
- Pinning only protects connections made through this client. It can be
  bypassed on a rooted or jailbroken device by an attacker who controls the
  device; treat it as defence in depth, not as protection of the client
  itself.

---

## Flutter Web: response signatures, not TLS pinning

Browsers do not let applications inspect or constrain TLS connections.
On the web, `HttpSecurityPinningClient` therefore **does not pin
certificates** (the SPKI pins are only validated for syntax). Instead your
server signs every response with an Ed25519 key, and the client verifies the
signature with the public keys you configure.

What this protects: the response body, status and content type, for the exact
request that was sent (method, scheme, host, path and query, and a random
per-request nonce), against modification or replay by intermediaries
**between your signing server and the browser** (CDN, reverse proxy,
TLS-inspecting middlebox). Other response headers are not signed. A response
that the browser obtained by following a redirect is **refused**, because the
redirect itself is not signed: call the final URL directly.

What it does not protect: confidentiality (anyone able to intercept TLS can
still read requests and responses, including tokens), the request itself, and
an attacker who can modify the JavaScript bundle of your app.

`timestampTolerance` only bounds how old a signature may be (in both
directions, to tolerate clock skew); replay protection comes from the nonce.

### Client

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

final client = UniversalSecurityClient.create(
  spkiPins: ['PRIMARY0PIN000000000000000000000000000000AA=', 'BACKUP00PIN000000000000000000000000000000AA='],
  serverPublicKeys: [
    // Current key and the next one, so you can rotate without an update.
    PayloadVerifier.decodeBase64('SERVER0KEY0CURRENT000000000000000000000000A='),
    PayloadVerifier.decodeBase64('SERVER0KEY0NEXT000000000000000000000000000A='),
  ],
  // Accepted clock difference; null disables the check for users with a
  // badly set clock (the nonce still prevents replays).
  timestampTolerance: const Duration(minutes: 5),
  maxResponseBytes: 10 * 1024 * 1024, // responses are buffered to be verified
);
```

On the web, `HttpSecurityPinningClient.perHost` also accepts
`serverPublicKeysByHost` (keys per host pattern). A host without keys throws
`UnpinnedHostException`, unless `allowUnpinnedHosts: true`, in which case its
responses pass through unverified (as a stream: neither `timeout` nor
`maxResponseBytes` apply to their body). `allowUnverifiedResponses: true`
lets hosts without keys pass unverified (hosts with keys are still verified);
without any key it turns the check off explicitly. Internationalized host
names must be written in punycode on the web: a non-ASCII host never passes
unverified. These web-only parameters are accepted and ignored on other
platforms, so the same code compiles everywhere.

### The `hsp-sig-v2` signature

1. The client sends a random nonce in the `X-HSP-Nonce` request header.
2. The server builds the **signature base**: UTF-8 text, one line per
   component, separated by `\n`, no trailing newline:

   ```text
   hsp-sig-v2
   @method: GET
   @scheme: https
   @authority: api.example.com
   @request-target: /users/42?expand=true
   @status: 200
   @nonce: AAECAwQFBgcICQoLDA0ODw
   @created: 1760169600000
   content-type: application/json
   @body-sha256: F7TbBk4X9IeOORF35spiO3mJEfNAFLyeeJIJk9fdJ60=
   ```

   - `@method`: request method, upper case.
   - `@scheme`: request scheme, lower case (`https`).
   - `@authority`: lower-case host (punycode, no trailing dot, IPv6 in
     brackets), plus `:port` only for a non-default port. Use the **public**
     host the client called, not an internal one.
   - `@request-target`: path (`/` if empty) and `?query` if the URL has one,
     exactly as received on the wire (Node: `req.url`; Express:
     `req.originalUrl`), not a decoded or rewritten path. Browsers send `'`
     in a query as `%27`, and the client signs it that way.
   - `@status`: response status code.
   - `@nonce`: the `X-HSP-Nonce` request header.
   - `@created`: signing time, milliseconds since the Unix epoch.
   - `content-type`: the response `Content-Type` (trimmed), or empty. Sign
     the exact value that is sent: some frameworks append `; charset=utf-8`
     after your code runs.
   - `@body-sha256`: base64 SHA-256 of the response body **as the browser
     delivers it** (sign the uncompressed body; `HEAD` responses and empty
     bodies hash the empty string).
3. The server signs the base with Ed25519 and sends
   `X-HSP-Signature: <base64 signature>` and `X-HSP-Created: <same time>`.

The server must also:

- answer CORS preflights with `Access-Control-Allow-Headers: X-HSP-Nonce`
  and expose the signature with
  `Access-Control-Expose-Headers: X-HSP-Signature, X-HSP-Created`;
- send `Cache-Control: no-store` on signed responses (a cached response
  carries the nonce of an earlier request and fails verification).

Test vector, for checking a server implementation only (**never deploy
this key**, its seed is public): Ed25519 seed `00 01 02 … 1f`, public key
`A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=`, response body `{"id":42}`.
The base above signs to
`lqUamjCnsQgg1W1/HZmLh9Ew25fyPhoF75EH32Kk/J/Var13xKU7vTTByb//BzsrZlB91P/P1RMy9I+JEMpjDw==`.

#### Node.js server

```js
import crypto from 'node:crypto';

// PKCS#8 Ed25519 private key (keep it out of source control).
const privateKey = crypto.createPrivateKey(process.env.HSP_PRIVATE_KEY_PEM);

export function signResponse({ method, authority, requestTarget, nonce, status, contentType, body }) {
  const created = Date.now();
  const base = [
    'hsp-sig-v2',
    `@method: ${method.toUpperCase()}`,
    '@scheme: https',
    `@authority: ${authority}`,
    `@request-target: ${requestTarget}`,
    `@status: ${status}`,
    `@nonce: ${nonce}`,
    `@created: ${created}`,
    `content-type: ${(contentType ?? '').trim()}`,
    `@body-sha256: ${crypto.createHash('sha256').update(body ?? '').digest('base64')}`,
  ].join('\n');
  return {
    'X-HSP-Signature': crypto.sign(null, Buffer.from(base, 'utf8'), privateKey).toString('base64'),
    'X-HSP-Created': String(created),
    'Cache-Control': 'no-store',
  };
}
```

#### Dart server or tests

`ResponseSigner` is the reference implementation:

```dart
import 'dart:convert';

import 'package:http_security_pinning/http_security_pinning.dart';

Future<Map<String, String>> sign(List<int> seed32, String nonce) async {
  final signer = await ResponseSigner.fromSeed(seed32);
  return signer.sign(
    method: 'GET',
    url: Uri.parse('https://api.example.com/users/42'),
    statusCode: 200,
    nonce: nonce,
    contentType: 'application/json',
    bodyBytes: utf8.encode('{"id":42}'),
  );
}
```

---

## Debugging and `badCertificateCallback`

This section describes Android, iOS and desktop. On the web the callback has
the signature `bool Function(Object error, String host, int port)` and
receives the verification error; the same restrictions apply.

`badCertificateCallback` is **notified** when a server's chain matches no pin
(with a `PresentedCertificate`, which implements `X509Certificate` and also
exposes `pem`) and when a TLS handshake fails. By default its return value is
ignored and the request fails.

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

final client = HttpSecurityPinningClient([
  'PRIMARY0PIN000000000000000000000000000000AA=',
  'BACKUP00PIN000000000000000000000000000000AA=',
])
  ..badCertificateCallback = (cert, host, port) {
    print('Rejected certificate for $host:$port: ${cert.subject}');
    return false;
  };
```

To inspect traffic with a debugging proxy (Charles, Proxyman, mitmproxy) you
can let the callback accept a failed certificate:

```dart
import 'package:flutter/foundation.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

final client = HttpSecurityPinningClient(
  [
    'PRIMARY0PIN000000000000000000000000000000AA=',
    'BACKUP00PIN000000000000000000000000000000AA=',
  ],
  honorBadCertificateCallback: kDebugMode,
)..badCertificateCallback = (cert, host, port) => host == 'staging.example.com';
```

The bypass is deliberately limited:

- it is **ignored in release builds**,
- it applies to **one request** (the callback is asked again next time; for
  unpinned hosts a certificate accepted by the callback stays accepted for
  the keep-alive connection, as in plain `dart:io`),
- it never overrides a connection whose certificate matched a pin.

---

## Error handling

Pinning and verification failures are `CertificatePinningException`s
(table below). Other errors keep their usual types: `ArgumentError` for
invalid configuration or URLs, `StateError` after `close()`,
`RedirectException` when `maxRedirects` is exceeded or a `Location` header is
invalid, and network errors such
as `SocketException`, `HandshakeException`, `TimeoutException` or
`http.ClientException` (including `ResponseTooLargeException` on the web).

| Exception | Meaning |
| :--- | :--- |
| `NoValidPinsFoundException` | The server's chain matches no pin. `host`, `observedPins`, `presentedChain`, `leafOnly`. |
| `CertificateFetchException` | The certificate probe failed (`code`, `isRetryable`). |
| `UnpinnedHostException` | The host has no pins and the policy does not allow unpinned hosts. |
| `InsecureConnectionException` | A non-HTTPS URL (or an HTTPS → HTTP redirect) to a pinned host. |
| `InvalidPinException` | A configured pin is not a valid base64 SHA-256 digest. |
| `CertificateFormatException` | A certificate could not be parsed. |
| `WebSecurityException` (web) | `SignatureVerificationException`, `MissingSecurityHeaderException`, `MalformedSecurityHeaderException`, `ReplayAttackException`. |
| `ResponseTooLargeException` (web, an `http.ClientException`) | The body exceeds `maxResponseBytes`. |

```dart
import 'package:http_security_pinning/http_security_pinning.dart';

Future<void> fetch(HttpSecurityPinningClient client) async {
  try {
    final request = await client.getUrl(Uri.parse('https://api.example.com/'));
    await (await request.close()).drain<void>();
  } on NoValidPinsFoundException catch (e) {
    // Possible interception, or outdated pins.
    print('Pin mismatch for ${e.host}; server presented ${e.observedPins}');
  } on CertificateFetchException catch (e) {
    print('Probe failed: ${e.message} (code ${e.code}, retryable: ${e.isRetryable})');
  } on UnpinnedHostException catch (e) {
    print('Host ${e.host} is not allowed');
  } on InsecureConnectionException catch (e) {
    print('Refused cleartext request to ${e.url}');
  }
}
```

---

## Configuration reference

### `HttpSecurityPinningClient(pins, ...)` and `.perHost(pinsByHost, ...)`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `spkiHashes` / `pinsByHost` | required | Pins for every host, or per host pattern. Must not be empty. |
| `allowUnpinnedHosts` (`perHost`) | `false` | `true`: hosts without pins use normal TLS without pinning. |
| `timeout` | 10 s | Timeout of one certificate probe. Must be positive. |
| `retryCount` | 3 | Extra probe attempts after a failure. |
| `retryDelay` | 200 ms | Base delay; attempt *n* waits `retryDelay * n`. |
| `honorBadCertificateCallback` | `false` | Let `badCertificateCallback` accept one failed request (debug/profile builds only). |
| `pinningService` | new, with the shared cache | Inject a custom fetcher or cache (tests). |
| `serverPublicKeys`, `serverPublicKeysByHost`, `timestampTolerance`, `allowUnverifiedResponses`, `maxResponseBytes` | – | Used on the web only; ignored on other platforms. |

### `UniversalSecurityClient.create(...)`

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `spkiPins` | – | Required on Android, iOS and desktop. |
| `serverPublicKeys` | – | Required on the web unless `allowUnverifiedResponses`. |
| `allowUnverifiedResponses` | `false` | Web: let responses from hosts without keys pass unverified. |
| `timeout` | 10 s | Native: probe timeout. Web: deadline for a verified response, body included. |
| `retryCount` / `retryDelay` | 3 / 200 ms | Native: probe retries. Web: retries of idempotent requests after network errors. |
| `timestampTolerance` | 5 min | Web: accepted clock difference, `null` to disable. |
| `maxResponseBytes` | 10 MiB | Web: largest body buffered for verification. |
| `innerClient` | – | Web only (e.g. a `BrowserClient`). Must be `null` elsewhere. |

---

## Best practices

These follow RFC 7469, the Android Network Security Configuration guide,
Apple's guidance on identity pinning, and OWASP MASVS (MASVS-NETWORK-2).

1. **Ask whether you need pinning.** Platform vendors recommend relying on
   the system trust store unless you have a specific threat (for example
   mis-issued certificates or user-installed CAs). Pinning adds an outage risk.
2. **Always ship at least two pins**, one of them for a key that is **not
   deployed yet** and kept offline (see
   [backup key](#for-a-backup-key-that-is-not-deployed-yet)). The package
   prints a debug warning when a host has a single pin.
3. **Pin keys you control.** Do not pin third-party services (payment
   providers, OAuth, CDNs, analytics): they rotate keys without notice.
4. **Choose what to pin per platform.** An intermediate CA pin survives leaf
   renewals on Android and iOS but never matches on desktop, where only the
   leaf is visible. Pinning the leaf key works everywhere but requires reusing
   the key on renewal (ACME clients generate a new key by default; use for
   example `certbot --reuse-key`). Public certificate lifetimes are getting
   shorter (47 days by 2029), so plan for frequent renewals.
5. **Have a recovery path.** Ship pins with a remote configuration you can
   update (fetched over a channel that does not depend on those pins), or a
   kill switch, and keep the backup key's private half safe. Consider an
   expiry date after which the app stops pinning, as Android's `pin-set
   expiration` does, so that very old app versions cannot be bricked.
6. **Test the failure.** Run the app through mitmproxy or Charles with its CA
   installed on the device and check that pinned requests fail.
7. **Cover other network stacks** (WebView, native SDKs) with Android
   `pin-set` / iOS `NSPinnedDomains` if they talk to the same backend.

---

## Testing

```bash
flutter test                                  # Dart unit tests (VM)
cd example && flutter test integration_test   # on an Android or iOS device, needs Internet
```

Native tests:

```bash
# Android (JUnit), from example/android after `flutter build apk --debug`
./gradlew :http_security_pinning:testDebugUnitTest :http_security_pinning:lintDebug

# iOS (XCTest, macOS), from example after `flutter build ios --config-only --simulator`
xcodebuild test -workspace ios/Runner.xcworkspace -scheme Runner \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

`dart run tool/check_readme_snippets.dart` compiles every Dart snippet of this
README against the package.

---

## License

BSD 3-Clause, see [LICENSE](LICENSE). Versions 1.0.0 to 1.2.1 were published
under the MIT License.
