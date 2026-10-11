// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
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

  /// Tunnels the probe through [proxy] with an HTTP `CONNECT`, then performs
  /// the TLS handshake over the tunnel and reads the leaf certificate, like
  /// [fetchChain]. No request is sent to the target server.
  @override
  Future<List<Uint8List>> fetchChainThroughProxy(
    Uri url,
    Duration timeout,
    ProxyDirective proxy,
  ) async {
    RawSocket? socket;
    RawSecureSocket? secure;
    Future<List<Uint8List>> probe() async {
      final raw = socket = await RawSocket.connect(proxy.host, proxy.port);
      final subscription = await _openTunnel(raw, url, proxy);
      final tls = secure = await RawSecureSocket.secure(
        raw,
        subscription: subscription,
        host: url.host,
        // Only observing: the caller validates the certificate against the
        // pins, and no data is ever sent on this connection.
        onBadCertificate: (_) => true,
      );
      final certificate = tls.peerCertificate;
      if (certificate == null) {
        throw CertificateFetchException(
          'Server returned no certificates.',
          code: 'NO_CERTIFICATES',
        );
      }
      return [certificate.der];
    }

    try {
      return await probe().timeout(timeout);
    } on CertificateFetchException {
      rethrow;
    } on TimeoutException {
      throw CertificateFetchException(
        'Certificate fetch through proxy timed out.',
        code: 'TIMEOUT',
      );
    } on SocketException catch (e) {
      throw CertificateFetchException(
        'Connection through proxy ${proxy.host}:${proxy.port} failed: '
        '${e.message}',
        code: 'CONNECTION_FAILED',
      );
    } on TlsException catch (e) {
      throw CertificateFetchException(
        'TLS handshake through proxy failed: ${e.message}',
        code: 'CONNECTION_FAILED',
      );
    } finally {
      secure?.close().ignore();
      socket?.close().ignore();
    }
  }

  static const int _maxProxyResponseBytes = 16 * 1024;
  static const String _crlf = '\r\n';

  /// Sends `CONNECT` and waits for a `200` answer. Returns the socket
  /// subscription, which the TLS layer then takes over.
  static Future<StreamSubscription<RawSocketEvent>> _openTunnel(
    RawSocket socket,
    Uri url,
    ProxyDirective proxy,
  ) {
    final host = url.host.contains(':') ? '[${url.host}]' : url.host;
    final authority = '$host:${url.port}';
    final authorization = proxy.authorization;
    final request = StringBuffer()
      ..write('CONNECT $authority HTTP/1.1$_crlf')
      ..write('Host: $authority$_crlf');
    if (authorization != null) {
      request.write('Proxy-Authorization: $authorization$_crlf');
    }
    request.write(_crlf);
    List<int> pending = latin1.encode(request.toString());

    final head = BytesBuilder(copy: false);
    final done = Completer<StreamSubscription<RawSocketEvent>>();
    late final StreamSubscription<RawSocketEvent> subscription;

    void fail(String message) {
      if (!done.isCompleted) {
        done.completeError(
          CertificateFetchException(message, code: 'CONNECTION_FAILED'),
        );
      }
    }

    void onRead() {
      final data = socket.read();
      if (data == null) return;
      head.add(data);
      final bytes = head.toBytes();
      final end = _endOfHead(bytes);
      if (end == -1) {
        if (bytes.length > _maxProxyResponseBytes) {
          fail('The proxy response is too large.');
        }
        return;
      }
      if (end != bytes.length) {
        // The target only speaks after the ClientHello.
        fail('Unexpected data from the proxy.');
        return;
      }
      final statusLine =
          latin1.decode(bytes.sublist(0, end)).split(_crlf).first;
      final parts = statusLine.split(' ');
      if (parts.length < 2 || parts[1] != '200') {
        fail('The proxy refused the tunnel ($statusLine).');
        return;
      }
      // Stop reading here: the TLS layer takes over the subscription.
      socket.readEventsEnabled = false;
      done.complete(subscription);
    }

    subscription = socket.listen(
      (event) {
        if (done.isCompleted) return;
        switch (event) {
          case RawSocketEvent.write:
            if (pending.isNotEmpty) {
              pending = pending.sublist(socket.write(pending));
              if (pending.isNotEmpty) socket.writeEventsEnabled = true;
            }
          case RawSocketEvent.read:
            onRead();
          case RawSocketEvent.readClosed:
          case RawSocketEvent.closed:
            fail('The proxy closed the connection.');
        }
      },
      onError: (Object e, StackTrace s) {
        if (!done.isCompleted) done.completeError(e, s);
      },
    );
    return done.future;
  }

  /// The index just past the blank line ending the response head, or -1.
  static int _endOfHead(Uint8List bytes) {
    for (var i = 3; i < bytes.length; i++) {
      if (bytes[i - 3] == 13 &&
          bytes[i - 2] == 10 &&
          bytes[i - 1] == 13 &&
          bytes[i] == 10) {
        return i + 1;
      }
    }
    return -1;
  }
}
