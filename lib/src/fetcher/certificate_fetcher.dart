import 'dart:async';

import 'package:flutter/services.dart';

import '../core/exceptions.dart';

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

/// A [CertificateChainFetcher] backed by the native Android / iOS plugin code.
///
/// Returns the **complete** chain, so leaf, intermediate and root certificates
/// can all be pinned.
class MethodChannelCertificateFetcher implements CertificateChainFetcher {
  /// The name of the channel shared with the native implementations.
  static const String channelName = 'http_security_pinning';

  /// Extra time given to the native side before the Dart side gives up.
  static const Duration _gracePeriod = Duration(seconds: 1);

  final MethodChannel _channel;

  /// Creates a fetcher, optionally using a custom [channel] (for testing).
  MethodChannelCertificateFetcher([MethodChannel? channel])
      : _channel = channel ?? const MethodChannel(channelName);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) async {
    try {
      final List<Object?>? result =
          await _channel.invokeMethod<List<Object?>>('fetchHostCertificates', {
        'url': url.toString(),
        'host': url.host,
        'port': url.port,
        'timeout': timeout.inMilliseconds,
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
