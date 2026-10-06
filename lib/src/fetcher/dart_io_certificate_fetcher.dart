// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../core/exceptions.dart';
import 'certificate_fetcher.dart';

/// A [CertificateChainFetcher] implemented purely with `dart:io`.
///
/// It is used on Windows, Linux and macOS where no native plugin code is
/// needed. It performs a TLS handshake, reads the peer certificate and drops
/// the connection without sending any data.
///
/// > **Limitation:** `dart:io` only exposes the *leaf* certificate of a
/// > connection, so on these platforms only the leaf's SPKI can be pinned
/// > (not an intermediate or root). Pin a backup key as well to survive key
/// > rotation.
class DartIoCertificateFetcher implements CertificateChainFetcher {
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
}
