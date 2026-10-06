// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../web/exceptions.dart';
import '../web/payload_verifier.dart';

/// An HTTP client for Flutter Web providing Application-Layer Public Key Pinning.
///
/// On Flutter Web, browser sandboxing abstracts the underlying TLS socket.
/// This client provides equivalent cryptographic protection by verifying the server's
/// Ed25519 digital signature ([serverPublicKeyBytes]) on response payloads to ensure
/// authenticity, data integrity, and protection against unauthorized proxies.
class HttpSecurityPinningClient extends http.BaseClient {
  /// Always returns `true` on Flutter Web.
  static bool get isSupported => true;

  /// In-memory cache clearance (no-op on web as browser manages cache).
  static void clearCache() {}

  /// SPKI pin representations or identifiers configured for this client.
  final List<String> pins;

  /// Connection and response read timeout.
  final Duration timeout;

  /// Number of retries on transient network errors.
  final int retryCount;

  /// Delay between retry attempts.
  final Duration retryDelay;

  /// Whether to allow debug bypass when [badCertificateCallback] returns `true`.
  final bool honorBadCertificateCallback;

  /// Acceptable time skew between server timestamp and client time.
  final Duration timestampTolerance;

  final PayloadVerifier? _verifier;
  final http.Client _inner;
  final Set<String> _bypassedHosts = <String>{};

  /// User-defined callback invoked when signature verification or security check fails.
  ///
  /// Can be used for diagnostics and audit logging.
  /// If [honorBadCertificateCallback] is `true` and this callback returns `true`,
  /// the failure is bypassed.
  bool Function(Object error, String host, int port)? badCertificateCallback;

  /// Creates a web pinning client with [pins] and optional [serverPublicKeyBytes].
  HttpSecurityPinningClient(
    this.pins, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    this.timestampTolerance = const Duration(minutes: 5),
    List<int>? serverPublicKeyBytes,
    http.Client? innerClient,
  })  : _inner = innerClient ?? http.Client(),
        _verifier = serverPublicKeyBytes != null
            ? PayloadVerifier(
                pinnedPublicKeyBytes: serverPublicKeyBytes,
                timestampTolerance: timestampTolerance,
              )
            : null;

  /// Creates a client with fine-grained per-host pin configurations.
  factory HttpSecurityPinningClient.perHost(
    Map<String, List<String>> pinsByHost, {
    bool allowUnpinnedHosts = false,
    Duration timeout = const Duration(seconds: 10),
    int retryCount = 3,
    Duration retryDelay = const Duration(milliseconds: 200),
    bool honorBadCertificateCallback = false,
    Duration timestampTolerance = const Duration(minutes: 5),
    List<int>? serverPublicKeyBytes,
    http.Client? innerClient,
  }) {
    return HttpSecurityPinningClient(
      pinsByHost.values.expand((e) => e).toList(),
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
      honorBadCertificateCallback: honorBadCertificateCallback,
      timestampTolerance: timestampTolerance,
      serverPublicKeyBytes: serverPublicKeyBytes,
      innerClient: innerClient,
    );
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final host = request.url.host;
    final port = request.url.port;

    int attempt = 0;
    while (true) {
      attempt++;
      try {
        final streamedResponse = await _inner.send(request).timeout(timeout);

        final verifier = _verifier;
        // If no verifier is configured or host is bypassed, pass through
        if (verifier == null || _bypassedHosts.contains(host)) {
          return streamedResponse;
        }

        final bodyBytes = await streamedResponse.stream.toBytes();

        try {
          await verifier.verify(
            bodyBytes: bodyBytes,
            headers: streamedResponse.headers,
          );
        } catch (e) {
          bool userAccepts = false;
          final cb = badCertificateCallback;
          if (cb != null) {
            try {
              userAccepts = cb(e, host, port);
            } catch (cbErr) {
              debugPrint('Error in badCertificateCallback: $cbErr');
            }
          }

          if (honorBadCertificateCallback && userAccepts) {
            debugPrint(
              'Security verification failed for $host, but bypassed via badCertificateCallback.',
            );
            _bypassedHosts.add(host);
          } else {
            rethrow;
          }
        }

        return http.StreamedResponse(
          Stream.value(bodyBytes),
          streamedResponse.statusCode,
          contentLength: bodyBytes.length,
          request: streamedResponse.request,
          headers: streamedResponse.headers,
          isRedirect: streamedResponse.isRedirect,
          persistentConnection: streamedResponse.persistentConnection,
          reasonPhrase: streamedResponse.reasonPhrase,
        );
      } catch (e) {
        if (e is WebSecurityException) {
          rethrow;
        }
        if (attempt >= retryCount) {
          rethrow;
        }
        await Future<void>.delayed(retryDelay * attempt);
      }
    }
  }

  @override
  void close() {
    _inner.close();
  }
}
