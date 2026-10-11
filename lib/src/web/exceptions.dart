// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:http/http.dart' as http;

import '../core/exceptions.dart';

/// Base class of the errors raised by the Flutter Web response-signature
/// check. Like every error of this package, it is a
/// [CertificatePinningException].
abstract class WebSecurityException extends CertificatePinningException {
  /// Creates a web security exception with [message].
  const WebSecurityException(super.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when the Ed25519 signature of a response is missing a valid match
/// for any configured server key: the response was altered, was produced for
/// a different request, or does not come from the genuine server.
class SignatureVerificationException extends WebSecurityException {
  /// Creates a signature verification exception.
  const SignatureVerificationException([
    super.message =
        'Response signature verification failed. The response may have been '
            'tampered with or was not produced for this request.',
  ]);
}

/// Thrown when a required signature header (`X-HSP-Signature` or
/// `X-HSP-Created`) is missing from the server response.
///
/// For cross-origin requests, also check that the server lists these headers
/// in `Access-Control-Expose-Headers`.
class MissingSecurityHeaderException extends WebSecurityException {
  /// The name of the missing security header.
  final String headerName;

  /// Creates a [MissingSecurityHeaderException] for [headerName].
  MissingSecurityHeaderException(this.headerName)
      : super('Missing required security header: $headerName');
}

/// Thrown when a signature header contains an unparseable or invalid value.
class MalformedSecurityHeaderException extends WebSecurityException {
  /// Creates a [MalformedSecurityHeaderException] with the given [message].
  const MalformedSecurityHeaderException(super.message);
}

/// Thrown when the signature's creation time is outside the accepted window
/// around the client clock (too old, or too far in the future).
///
/// The request nonce already binds every response to one request; this check
/// additionally bounds how long a captured response stays usable.
class ReplayAttackException extends WebSecurityException {
  /// The creation time claimed by the server, in milliseconds since epoch.
  final int serverTimestampMs;

  /// The client time used for the check, in milliseconds since epoch.
  final int clientTimestampMs;

  /// The accepted difference between the two clocks.
  final Duration tolerance;

  /// Creates a replay attack exception.
  ReplayAttackException({
    required this.serverTimestampMs,
    required this.clientTimestampMs,
    required this.tolerance,
  }) : super(
          'Response signature time ($serverTimestampMs) differs from client '
          'time ($clientTimestampMs) by more than the allowed tolerance of '
          '${tolerance.inSeconds}s.',
        );
}

/// Thrown when a response that must be buffered for verification is larger
/// than `maxResponseBytes` (Flutter Web client). It is never retried.
class ResponseTooLargeException extends http.ClientException {
  /// The configured limit in bytes.
  final int limit;

  /// Creates the exception for [limit] and [uri].
  ResponseTooLargeException(this.limit, [Uri? uri])
      : super('Response body exceeds maxResponseBytes ($limit bytes).', uri);
}
