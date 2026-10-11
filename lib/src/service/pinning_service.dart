// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../core/exceptions.dart';
import '../core/presented_certificate.dart';
import '../core/spki_pin.dart';
import '../crypto/spki_hasher.dart';
import '../fetcher/certificate_fetcher.dart';
import '../fetcher/dart_io_certificate_fetcher.dart';
import '../fetcher/proxy_directive.dart';
import 'certificate_cache.dart';

/// Orchestrates certificate chain probing, pin evaluation and the pinned
/// [SecurityContext] used by `HttpSecurityPinningClient`.
///
/// Pass a custom instance to the client to inject a [fetcher] (for tests) or
/// an isolated [cache].
class PinningService {
  static const String _tag = 'HttpSecurityPinning';

  /// Reads the chain a server presents (native probe on Android and iOS,
  /// `dart:io` elsewhere).
  final CertificateChainFetcher fetcher;

  /// Caches probed chains per `host:port`.
  final CertificateChainCache cache;

  /// Creates a [PinningService].
  PinningService({
    CertificateChainFetcher? fetcher,
    CertificateChainCache? cache,
  })  : fetcher = fetcher ?? _createDefaultFetcher(),
        cache = cache ?? CertificateChainCache.shared;

  static CertificateChainFetcher _createDefaultFetcher() {
    // On mobile platforms (Android, iOS), use the native MethodChannel fetcher
    // which extracts the full certificate chain during TLS handshake.
    // On other platforms (Windows, macOS, Linux), fallback to DartIoCertificateFetcher.
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      return MethodChannelCertificateFetcher();
    }
    return const DartIoCertificateFetcher();
  }

  /// Fetches the certificate chain for [url] with retry logic and caching.
  ///
  /// [findProxy] (in dart:io `HttpClient.findProxy` syntax) selects the route
  /// of the probe so that it matches the route of the real request. When the
  /// first directive is `PROXY host:port` and the [fetcher] is a
  /// [ProxyAwareCertificateChainFetcher], the probe is tunnelled through that
  /// proxy; otherwise it connects directly. Retries back off linearly
  /// (`retryDelay * attempt`).
  Future<List<Uint8List>> getCertificateChain(
    Uri url, {
    required Duration timeout,
    required int retryCount,
    Duration retryDelay = const Duration(milliseconds: 200),
    String Function(Uri url)? findProxy,
  }) {
    final cacheKey = CertificateChainCache.keyFor(url);
    return cache.getOrFetch(cacheKey, () async {
      final proxy = _proxyFor(url, findProxy);
      final fetcher = this.fetcher;
      int attempts = 0;
      while (true) {
        attempts++;
        try {
          if (proxy != null && fetcher is ProxyAwareCertificateChainFetcher) {
            return await fetcher.fetchChainThroughProxy(url, timeout, proxy);
          }
          return await fetcher.fetchChain(url, timeout);
        } on CertificateFetchException catch (e) {
          if (!e.isRetryable || attempts > retryCount) {
            rethrow;
          }
          if (kDebugMode) {
            debugPrint(
              '$_tag: Failed to fetch certificate chain for ${url.host} '
              '(attempt $attempts/${retryCount + 1}): ${e.message}. Retrying...',
            );
          }
        } catch (e) {
          if (attempts > retryCount) {
            throw CertificateFetchException(
              e.toString(),
              code: 'UNEXPECTED_ERROR',
            );
          }
          if (kDebugMode) {
            debugPrint(
              '$_tag: Unexpected error fetching certificates for ${url.host} '
              '(attempt $attempts/${retryCount + 1}): $e. Retrying...',
            );
          }
        }
        if (retryDelay > Duration.zero) {
          await Future<void>.delayed(retryDelay * attempts);
        }
      }
    });
  }

  static ProxyDirective? _proxyFor(
    Uri url,
    String Function(Uri url)? findProxy,
  ) {
    if (findProxy == null) return null;
    try {
      return ProxyDirective.parse(findProxy(url));
    } catch (e) {
      if (kDebugMode) {
        debugPrint('$_tag: findProxy threw for ${url.host}: $e');
      }
      return null;
    }
  }

  /// Evaluates the server's certificate chain against [validPins].
  ///
  /// Returns a record containing the matched certificates, the full presented
  /// chain, and the list of observed SPKI base64 hashes.
  Future<
      ({
        List<Uint8List> matchedCerts,
        List<Uint8List> presentedChain,
        List<String> observedPins,
      })> evaluatePins(
    Uri url,
    Set<SpkiPin> validPins, {
    required Duration timeout,
    required int retryCount,
    Duration retryDelay = const Duration(milliseconds: 200),
    String Function(Uri url)? findProxy,
  }) async {
    final chain = await getCertificateChain(
      url,
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
      findProxy: findProxy,
    );

    final observedPins = <String>[];
    final matchedCerts = <Uint8List>[];

    for (final cert in chain) {
      try {
        final spkiDigest = SpkiHasher.sha256Digest(cert);
        final base64Pin = base64.encode(spkiDigest);
        observedPins.add(base64Pin);

        for (final pin in validPins) {
          if (pin.matches(spkiDigest)) {
            matchedCerts.add(cert);
            break;
          }
        }
      } on CertificateFormatException catch (e) {
        if (kDebugMode) {
          debugPrint('$_tag: Skipping malformed certificate in chain: $e');
        }
      }
    }

    if (kDebugMode) {
      debugPrint(
        '$_tag: Certificate chain for ${url.host}: ${observedPins.join(', ')}'
        '${matchedCerts.isNotEmpty ? ' [${matchedCerts.length} PINNED]' : ' [NO MATCH]'}',
      );
    }

    return (
      matchedCerts: matchedCerts,
      presentedChain: chain,
      observedPins: observedPins,
    );
  }

  /// Builds a [SecurityContext] trusting only the matched pinned certificates.
  SecurityContext createPinnedSecurityContext(List<Uint8List> matchedCerts) {
    final securityContext = SecurityContext(withTrustedRoots: false);
    final pemBuffer = StringBuffer();
    for (final cert in matchedCerts) {
      pemBuffer.write(PresentedCertificate.derToPem(cert));
    }
    final pemBytes = Uint8List.fromList(ascii.encode(pemBuffer.toString()));
    securityContext.setTrustedCertificatesBytes(pemBytes);
    return securityContext;
  }
}
