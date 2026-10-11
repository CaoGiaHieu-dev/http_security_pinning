// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/host_normalizer.dart';
import 'exceptions.dart';

/// The canonical message signed by the server in the `hsp-sig-v2` response
/// signature scheme (modelled on RFC 9421, HTTP Message Signatures).
///
/// The signature base is UTF-8 text, one `name: value` component per line,
/// lines separated by a single `\n` and no trailing newline:
///
/// ```text
/// hsp-sig-v2
/// @method: GET
/// @scheme: https
/// @authority: api.example.com
/// @request-target: /users/42?expand=true
/// @status: 200
/// @nonce: AAECAwQFBgcICQoLDA0ODw
/// @created: 1760169600000
/// content-type: application/json
/// @body-sha256: F7TbBk4X9IeOORF35spiO3mJEfNAFLyeeJIJk9fdJ60=
/// ```
///
/// * `@method` is the request method in upper case.
/// * `@scheme` is the request scheme in lower case (`https`).
/// * `@authority` is the lower-case host (punycode for internationalized
///   names, no trailing dot, IPv6 in brackets), followed by `:port` only when
///   the port is not the default of the scheme.
/// * `@request-target` is the path (`/` if empty) followed by `?query` when
///   the URL has a query, exactly as sent on the wire (browsers send `'` in a
///   query as `%27`).
/// * `@status` is the response status code.
/// * `@nonce` is the random value the client sent in the `X-HSP-Nonce`
///   request header. It binds the response to one request.
/// * `@created` is the signing time in milliseconds since the Unix epoch, as
///   sent in the `X-HSP-Created` response header.
/// * `content-type` is the response `Content-Type` header (trimmed), or empty.
/// * `@body-sha256` is the standard (padded) base64 SHA-256 digest of the
///   response body bytes **after** content decoding (sign the uncompressed
///   body).
///
/// Every component is separated and labelled, so bytes cannot be shifted
/// between components, and a response cannot be reused for another method,
/// URL, status, content type or request. The client refuses redirected
/// responses, since the redirect itself is not signed.
abstract final class SignatureBase {
  /// The scheme label on the first line.
  static const String label = 'hsp-sig-v2';

  /// Builds the signature base bytes.
  ///
  /// Throws a [MalformedSecurityHeaderException] if a component contains a
  /// line break.
  static Uint8List build({
    required String method,
    required Uri url,
    required int statusCode,
    required String nonce,
    required int createdMs,
    required String contentType,
    required List<int> bodyBytes,
  }) {
    final components = <String, String>{
      '@method': method.toUpperCase(),
      '@scheme': url.scheme.toLowerCase(),
      '@authority': authorityOf(url),
      '@request-target': requestTargetOf(url),
      '@status': '$statusCode',
      '@nonce': nonce,
      '@created': '$createdMs',
      'content-type': contentType.trim(),
      '@body-sha256': base64.encode(sha256.convert(bodyBytes).bytes),
    };
    final buffer = StringBuffer(label);
    for (final MapEntry(:key, :value) in components.entries) {
      if (value.contains('\n') || value.contains('\r')) {
        throw MalformedSecurityHeaderException(
          'Signature component $key must not contain a line break.',
        );
      }
      buffer
        ..write('\n')
        ..write(key)
        ..write(': ')
        ..write(value);
    }
    return Uint8List.fromList(utf8.encode(buffer.toString()));
  }

  /// The `@authority` component of [url].
  static String authorityOf(Uri url) {
    var host = HostNormalizer.normalize(url.host);
    if (host.contains(':')) host = '[$host]';
    final defaultPort = switch (url.scheme.toLowerCase()) {
      'https' => 443,
      'http' => 80,
      _ => -1,
    };
    return url.port == defaultPort ? host : '$host:${url.port}';
  }

  /// The `@request-target` component of [url].
  ///
  /// `'` in the query is written `%27`, as browsers send it (the WHATWG URL
  /// standard encodes it in queries of `http(s)` URLs, Dart's [Uri] does
  /// not).
  static String requestTargetOf(Uri url) {
    final path = url.path.isEmpty ? '/' : url.path;
    return url.hasQuery ? '$path?${url.query.replaceAll("'", '%27')}' : path;
  }
}
