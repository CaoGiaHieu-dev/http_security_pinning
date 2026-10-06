// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:typed_data';

/// The base class for all exceptions thrown by the http_security_pinning package.
abstract class CertificatePinningException implements Exception {
  /// A descriptive message explaining the error.
  final String message;

  /// Creates a new certificate pinning exception.
  CertificatePinningException(this.message);

  @override
  String toString() => 'CertificatePinningException: $message';
}

/// Thrown when fetching the certificate chain from the native platform fails.
///
/// This can happen due to network errors, timeouts, or if the native
/// code encounters an unexpected issue. The [message] property contains
/// more details from the native layer.
class CertificateFetchException extends CertificatePinningException {
  /// Error codes for which retrying can never succeed.
  static const Set<String> _nonRetryableCodes = {
    'INVALID_URL',
    'INVALID_ARGS',
    'MISSING_PLUGIN',
  };

  /// A machine readable error code reported by the platform layer
  /// (e.g. `CONNECTION_FAILED`, `TIMEOUT`, `NO_CERTIFICATES`), if any.
  final String? code;

  /// Creates a new certificate fetch exception.
  CertificateFetchException(String message, {this.code})
      : super('Failed to fetch certificate chain. Reason: $message');

  /// Whether another attempt could plausibly succeed.
  bool get isRetryable => !_nonRetryableCodes.contains(code);
}

/// Thrown when the server's certificate chain is successfully fetched,
/// but none of the certificates' SPKI hashes match the pins provided to the client.
///
/// This is the primary exception that indicates a pinning validation failure.
class NoValidPinsFoundException extends CertificatePinningException {
  /// The host for which the pinning validation failed.
  final String host;

  /// The base64 SPKI SHA-256 hashes the server actually presented, in chain
  /// order (leaf first). Useful to discover the pin to configure, also in
  /// release builds where debug logging is unavailable.
  final List<String> observedPins;

  /// The DER encoded certificates the server presented, leaf first.
  final List<Uint8List> presentedChain;

  /// Creates a new "no valid pins found" exception.
  NoValidPinsFoundException(
    this.host, {
    this.observedPins = const [],
    this.presentedChain = const [],
  }) : super(
          'No valid SPKI pins found for host: $host'
          '${observedPins.isEmpty ? '' : ' (server presented: ${observedPins.join(', ')})'}',
        );
}

/// Thrown when a configured pin is not a valid base64 encoded SHA-256 digest.
class InvalidPinException extends CertificatePinningException {
  /// The offending pin, exactly as it was provided.
  final String pin;

  /// Creates a new invalid pin exception.
  InvalidPinException(this.pin, String reason)
      : super('Invalid SPKI pin "$pin": $reason');
}

/// Thrown when a request is attempted over a non-HTTPS connection while
/// certificate pinning is active for the target host.
///
/// Pinning only protects TLS connections; silently sending the request in
/// cleartext would defeat the purpose of the client.
class InsecureConnectionException extends CertificatePinningException {
  /// The URL that was requested.
  final Uri url;

  /// Creates a new insecure connection exception.
  InsecureConnectionException(this.url)
      : super(
          'Refusing to open a non-HTTPS connection to ${url.host} while '
          'certificate pinning is enabled: $url',
        );
}

/// Thrown by a per-host client when a request targets a host that has no
/// configured pins and unpinned hosts are not allowed.
class UnpinnedHostException extends CertificatePinningException {
  /// The host that has no pins configured.
  final String host;

  /// Creates a new unpinned host exception.
  UnpinnedHostException(this.host)
      : super('No SPKI pins are configured for host: $host');
}

/// Thrown when a DER encoded certificate cannot be parsed to extract its
/// Subject Public Key Info.
class CertificateFormatException extends CertificatePinningException {
  /// Creates a new certificate format exception.
  CertificateFormatException(String message)
      : super('Malformed X.509 certificate: $message');
}
