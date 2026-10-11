// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../core/exceptions.dart';
import 'certificate_fetcher.dart';
import 'proxy_directive.dart';

/// A [CertificateChainFetcher] implemented purely with `dart:io`.
///
/// It is used on Windows, Linux and macOS where no native plugin code is
/// needed. It performs a TLS handshake, reads the peer certificate and drops
/// the connection without sending any application data.
///
/// > **Limitation:** `dart:io` only exposes the *leaf* certificate of a
/// > connection, so on these platforms only the leaf's SPKI can be pinned
/// > (not an intermediate or root). Pin a backup key as well to survive key
/// > rotation.
class DartIoCertificateFetcher implements ProxyAwareCertificateChainFetcher {
  /// Creates a fetcher.
  const DartIoCertificateFetcher();

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) async {
    ConnectionTask<SecureSocket>? task;
    SecureSocket? socket;
    try {
      task = await SecureSocket.startConnect(
        url.host,
        url.port,
        // Only observing: the peer certificate is validated against the pins
        // by the caller, and no data is ever sent on this connection.
        onBadCertificate: (_) => true,
      );
      final pending = task;
      socket = await pending.socket.timeout(
        timeout,
        onTimeout: () {
          pending.cancel();
          throw TimeoutException('TLS handshake timed out', timeout);
        },
      );

      final certificate = socket.peerCertificate;
      if (certificate == null) {
        throw CertificateFetchException(
          'Server returned no certificates.',
          code: 'NO_CERTIFICATES',
        );
      }
      return [certificate.der];
    } on CertificateFetchException {
      rethrow;
    } on TimeoutException {
      throw CertificateFetchException(
        'Certificate fetch timed out.',
        code: 'TIMEOUT',
      );
    } on SocketException catch (e) {
      throw CertificateFetchException(
        'Connection failed: ${e.message}',
        code: 'CONNECTION_FAILED',
      );
    } on TlsException catch (e) {
      throw CertificateFetchException(
        'TLS handshake failed: ${e.message}',
        code: 'CONNECTION_FAILED',
      );
    } finally {
      socket?.destroy();
    }
  }

  /// Tunnels the probe through [proxy] with an HTTP `CONNECT`.
  ///
  /// A throw-away [HttpClient] that trusts no certificate at all is used: the
  /// leaf is captured in its `badCertificateCallback`, which then aborts the
  /// handshake, so no request ever reaches the target server.
  @override
  Future<List<Uint8List>> fetchChainThroughProxy(
    Uri url,
    Duration timeout,
    ProxyDirective proxy,
  ) async {
    X509Certificate? captured;
    final client = HttpOverrides.runWithHttpOverrides(
      () => HttpClient(context: SecurityContext(withTrustedRoots: false)),
      _NoHttpOverrides(),
    )
      ..connectionTimeout = timeout
      ..findProxy = ((_) => proxy.toFindProxyString())
      ..badCertificateCallback = (cert, host, port) {
        captured = cert;
        return false;
      };
    try {
      final request = await client
          .openUrl('HEAD', Uri(scheme: 'https', host: url.host, port: url.port))
          .timeout(timeout);
      // Unreachable in practice: no certificate is trusted.
      request.abort();
    } on TimeoutException {
      if (captured == null) {
        throw CertificateFetchException(
          'Certificate fetch through proxy timed out.',
          code: 'TIMEOUT',
        );
      }
    } on HandshakeException {
      // Expected: the handshake was aborted after capturing the leaf.
    } on TlsException catch (e) {
      if (captured == null) {
        throw CertificateFetchException(
          'TLS handshake through proxy failed: ${e.message}',
          code: 'CONNECTION_FAILED',
        );
      }
    } on IOException catch (e) {
      throw CertificateFetchException(
        'Connection through proxy ${proxy.host}:${proxy.port} failed: $e',
        code: 'CONNECTION_FAILED',
      );
    } finally {
      client.close(force: true);
    }
    final certificate = captured;
    if (certificate == null) {
      throw CertificateFetchException(
        'Server returned no certificates.',
        code: 'NO_CERTIFICATES',
      );
    }
    return [certificate.der];
  }
}

class _NoHttpOverrides extends HttpOverrides {}
