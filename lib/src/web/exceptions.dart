// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Exception hierarchy for Application-Layer Web Security Pinning.
abstract class WebSecurityException implements Exception {
  final String message;
  const WebSecurityException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when the cryptographic signature verification of the response payload fails,
/// indicating that the payload was tampered with or does not originate from the genuine server.
class SignatureVerificationException extends WebSecurityException {
  const SignatureVerificationException([
    super.message =
        'Response signature verification failed. The payload may have been tampered with.',
  ]);
}

/// Thrown when required security headers (e.g. X-Server-Signature or X-Signature-Timestamp)
/// are missing from the server response.
class MissingSecurityHeaderException extends WebSecurityException {
  /// The name of the missing security header.
  final String headerName;

  /// Creates a [MissingSecurityHeaderException] indicating [headerName] was not found.
  MissingSecurityHeaderException(this.headerName)
      : super('Missing required security header: $headerName');
}

/// Thrown when a security header contains an unparseable or invalid value format.
class MalformedSecurityHeaderException extends WebSecurityException {
  /// Creates a [MalformedSecurityHeaderException] with the given error [message].
  const MalformedSecurityHeaderException(super.message);
}

/// Thrown when the response timestamp is outside the acceptable tolerance window,
/// preventing replay attacks.
class ReplayAttackException extends WebSecurityException {
  final int serverTimestampMs;
  final int clientTimestampMs;
  final Duration tolerance;

  ReplayAttackException({
    required this.serverTimestampMs,
    required this.clientTimestampMs,
    required this.tolerance,
  }) : super(
          'Response timestamp ($serverTimestampMs) differs from client time ($clientTimestampMs) '
          'by more than the allowed tolerance of ${tolerance.inSeconds}s.',
        );
}
