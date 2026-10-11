// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';

import 'package:flutter/services.dart';

import '../core/exceptions.dart';
import '../core/host_normalizer.dart';
import 'proxy_directive.dart';

/// Retrieves the certificate chain a server presents during a TLS handshake.
///
/// `dart:io` does not expose the full chain of a connection, so on mobile the
/// chain is read by the native platform ([MethodChannelCertificateFetcher]).
/// Implementations must **only observe** the handshake: they must not send any
/// application data. The result is never trusted by itself; it is only used to
/// find which certificates match the configured pins.
abstract interface class CertificateChainFetcher {
  /// Returns the DER encoded certificates presented by the server at [url],
  /// leaf first.
  ///
  /// Implementations should throw a [CertificateFetchException] on failure.
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout);
}

/// A [CertificateChainFetcher] that can also probe through an HTTP proxy
/// (`CONNECT` tunnel), so that the probe takes the same route as requests
/// sent through a proxy chosen by `HttpClient.findProxy`.
abstract interface class ProxyAwareCertificateChainFetcher
    implements CertificateChainFetcher {
  /// Like [fetchChain], but tunnels the probe through [proxy].
  Future<List<Uint8List>> fetchChainThroughProxy(
    Uri url,
    Duration timeout,
    ProxyDirective proxy,
  );
}

/// A [CertificateChainFetcher] backed by the native Android / iOS plugin code.
///
/// * **Android** returns the certificates the server sent (normally the leaf
///   and its intermediates; servers rarely send the root).
/// * **iOS** returns the chain built by the system trust evaluation, which can
///   include a root from the device trust store.
///
/// Leaf and intermediate pins therefore work on both platforms; a root pin is
/// only reliable on iOS or when the server sends its root.
class MethodChannelCertificateFetcher
    implements ProxyAwareCertificateChainFetcher {
  /// The name of the channel shared with the native implementations.
  static const String channelName = 'http_security_pinning';

  /// Extra time given to the native side before the Dart side gives up.
  static const Duration _gracePeriod = Duration(seconds: 1);

  final MethodChannel _channel;

  /// Creates a fetcher, optionally using a custom [channel] (for testing).
  MethodChannelCertificateFetcher([MethodChannel? channel])
      : _channel = channel ?? const MethodChannel(channelName);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) =>
      _fetch(url, timeout, null);

  /// Tunnels the probe through [proxy].
  ///
  /// Android opens the `CONNECT` tunnel itself. iOS hands the proxy to
  /// `NSURLSession`.
  @override
  Future<List<Uint8List>> fetchChainThroughProxy(
    Uri url,
    Duration timeout,
    ProxyDirective proxy,
  ) =>
      _fetch(url, timeout, proxy);

  Future<List<Uint8List>> _fetch(
    Uri url,
    Duration timeout,
    ProxyDirective? proxy,
  ) async {
    try {
      if (timeout <= Duration.zero) {
        throw ArgumentError.value(timeout, 'timeout', 'must be positive');
      }
      // Only the origin is sent to the platform: path, query and user info
      // are never needed for a TLS probe.
      // Hosts are sent in their ASCII (punycode) form without a trailing dot.
      final host = HostNormalizer.normalize(url.host);
      if (!HostNormalizer.isValid(host)) {
        throw CertificateFetchException(
          'Invalid host name.',
          code: 'INVALID_URL',
        );
      }
      final origin = Uri(scheme: 'https', host: host, port: url.port);
      // Round up so that sub-millisecond timeouts never become 0 ("no
      // timeout") on the native side.
      final timeoutMs = (timeout.inMicroseconds + 999) ~/ 1000;
      final List<Object?>? result =
          await _channel.invokeMethod<List<Object?>>('fetchHostCertificates', {
        'url': '$origin/',
        'host': host,
        'port': url.port,
        'timeout': timeoutMs,
        if (proxy != null) ...{
          'proxyHost': proxy.host,
          'proxyPort': proxy.port,
          if (proxy.authorization != null)
            'proxyAuthorization': proxy.authorization,
        },
      }).timeout(timeout + _gracePeriod);

      final chain = result?.whereType<Uint8List>().toList(growable: false);
      if (chain == null || chain.isEmpty) {
        throw CertificateFetchException(
          'Native method returned no certificates.',
          code: 'NO_CERTIFICATES',
        );
      }
      return chain;
    } on PlatformException catch (e) {
      throw CertificateFetchException(
        e.message ?? 'Unknown platform error',
        code: e.code,
      );
    } on MissingPluginException {
      throw CertificateFetchException(
        'The native part of http_security_pinning is not available on this platform.',
        code: 'MISSING_PLUGIN',
      );
    } on TimeoutException {
      throw CertificateFetchException(
        'Certificate fetch timed out.',
        code: 'TIMEOUT',
      );
    }
  }
}
