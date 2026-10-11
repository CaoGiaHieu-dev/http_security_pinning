// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../core/exceptions.dart';
import '../core/host_pattern_map.dart';
import '../core/spki_pin.dart';
import '../web/exceptions.dart';
import '../web/payload_verifier.dart';
import '../web/signature_base.dart';

/// The Flutter Web client: verifies Ed25519 response signatures.
///
/// **This is not TLS certificate pinning.** Browsers do not let applications
/// inspect or constrain the TLS handshake, so [isSupported] is `false` and the
/// SPKI `pins` are only validated for syntax. Instead, every response must
/// carry an `hsp-sig-v2` signature (see `SignatureBase`) made with one of the
/// pinned server keys over the request method, URL, a per-request nonce, the
/// status, the content type and the body.
///
/// This detects responses that were altered or replayed by an intermediary
/// (CDN, proxy, TLS-inspecting middlebox) between the signing server and the
/// browser. It does not hide requests or responses from such an
/// intermediary, and it does not protect the request itself.
///
/// The server must:
/// * sign every response for the configured hosts (see `ResponseSigner`),
/// * allow the `X-HSP-Nonce` request header and expose `X-HSP-Signature` and
///   `X-HSP-Created` via CORS, and
/// * send `Cache-Control: no-store`, because a cached response carries the
///   nonce of an earlier request.
class HttpSecurityPinningClient extends http.BaseClient {
  /// Whether TLS certificate pinning is supported: always `false` in
  /// browsers. Response signatures are verified instead.
  static bool get isSupported => false;

  /// No-op on the web: there is no certificate cache.
  static void clearCache() {}

  /// The SPKI pins passed for API parity with the native client. They are
  /// validated but not used, since browsers do not expose certificates.
  final List<String> pins;

  /// Deadline for a whole attempt: sending the request and reading the body.
  final Duration timeout;

  /// How many times a failed request is retried after a network error or
  /// timeout (in addition to the first attempt). Only idempotent methods
  /// sent as an `http.Request` (whose body can be replayed) are retried;
  /// streamed and multipart requests and verification failures never are.
  /// The delay grows linearly: `retryDelay * attempt`.
  final int retryCount;

  /// The base delay between retry attempts.
  final Duration retryDelay;

  /// Whether a `true` result of [badCertificateCallback] may accept a single
  /// response that failed verification. Ignored in release builds.
  final bool honorBadCertificateCallback;

  /// Accepted clock difference for the signature time, or `null` to skip it.
  final Duration? timestampTolerance;

  /// Upper bound of a response body that is buffered for verification, or
  /// `null` for no limit.
  final int? maxResponseBytes;

  /// Whether responses from hosts without keys pass through unverified.
  /// Non-ASCII (internationalized) hosts never do: write them in punycode.
  final bool allowUnverifiedResponses;

  final PayloadVerifier? _defaultVerifier;
  final HostPatternMap<PayloadVerifier>? _verifiersByHost;
  final http.Client _inner;
  final Random _random;

  /// Notified when a response fails verification, for diagnostics. With
  /// [honorBadCertificateCallback] enabled in a debug or profile build, a
  /// `true` result accepts that one response anyway.
  bool Function(Object error, String host, int port)? badCertificateCallback;

  /// Creates a client verifying every response with [serverPublicKeys]
  /// (32-byte Ed25519 keys; list the next key too to allow rotation).
  ///
  /// Throws an [ArgumentError] if no key is given, unless
  /// [allowUnverifiedResponses] is `true` (then nothing is verified, except
  /// that non-ASCII hosts are refused with [UnpinnedHostException]).
  /// [pins] are only validated ([InvalidPinException]).
  HttpSecurityPinningClient(
    this.pins, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    this.timestampTolerance = const Duration(minutes: 5),
    List<List<int>>? serverPublicKeys,
    this.allowUnverifiedResponses = false,
    this.maxResponseBytes = 10 * 1024 * 1024,
    http.Client? innerClient,
    @visibleForTesting Random? random,
  })  : _inner = innerClient ?? http.Client(),
        _random = random ?? Random.secure(),
        _verifiersByHost = null,
        _defaultVerifier = serverPublicKeys == null || serverPublicKeys.isEmpty
            ? null
            : PayloadVerifier(
                publicKeys: serverPublicKeys,
                timestampTolerance: timestampTolerance,
              ) {
    _validate();
  }

  /// Creates a client with keys per host.
  ///
  /// [serverPublicKeysByHost] maps host patterns (exact names or wildcards
  /// such as `*.example.com`) to Ed25519 keys; [serverPublicKeys] applies to
  /// every other host. A host without keys throws [UnpinnedHostException]
  /// unless [allowUnpinnedHosts] is `true`, in which case its responses pass
  /// through unverified (non-ASCII hosts excepted: they always throw).
  /// [pinsByHost] is only validated.
  HttpSecurityPinningClient.perHost(
    Map<String, List<String>> pinsByHost, {
    bool allowUnpinnedHosts = false,
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    this.timestampTolerance = const Duration(minutes: 5),
    List<List<int>>? serverPublicKeys,
    Map<String, List<List<int>>>? serverPublicKeysByHost,
    bool allowUnverifiedResponses = false,
    this.maxResponseBytes = 10 * 1024 * 1024,
    http.Client? innerClient,
    @visibleForTesting Random? random,
  })  : pins = [for (final list in pinsByHost.values) ...list],
        allowUnverifiedResponses =
            allowUnverifiedResponses || allowUnpinnedHosts,
        _inner = innerClient ?? http.Client(),
        _random = random ?? Random.secure(),
        _defaultVerifier = serverPublicKeys == null || serverPublicKeys.isEmpty
            ? null
            : PayloadVerifier(
                publicKeys: serverPublicKeys,
                timestampTolerance: timestampTolerance,
              ),
        _verifiersByHost = HostPatternMap(serverPublicKeysByHost?.map(
              (host, keys) => MapEntry(
                host,
                PayloadVerifier(
                  publicKeys: keys,
                  timestampTolerance: timestampTolerance,
                ),
              ),
            ) ??
            const {}) {
    // Host patterns of the pins are validated like the native client does.
    HostPatternMap(pinsByHost);
    if (_defaultVerifier == null &&
        _verifiersByHost!.isEmpty &&
        !allowUnverifiedResponses) {
      throw ArgumentError(
        'No serverPublicKeys or serverPublicKeysByHost given: nothing would '
        'be verified. Pass allowUnverifiedResponses: true to opt out '
        'explicitly.',
      );
    }
    _validate(requireKey: false);
  }

  void _validate({bool requireKey = true}) {
    for (final pin in pins) {
      SpkiPin.parse(pin);
    }
    if (requireKey && _defaultVerifier == null && !allowUnverifiedResponses) {
      throw ArgumentError(
        'serverPublicKeys is required on Flutter Web: browsers cannot pin TLS '
        'certificates, so responses are verified with Ed25519 signatures. '
        'Pass allowUnverifiedResponses: true to opt out explicitly.',
      );
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(timeout, 'timeout', 'must be positive');
    }
    if (retryCount < 0) {
      throw ArgumentError.value(
          retryCount, 'retryCount', 'must not be negative');
    }
    if (retryDelay < Duration.zero) {
      throw ArgumentError.value(
          retryDelay, 'retryDelay', 'must not be negative');
    }
    if (maxResponseBytes != null && maxResponseBytes! <= 0) {
      throw ArgumentError.value(
          maxResponseBytes, 'maxResponseBytes', 'must be positive');
    }
    if (allowUnverifiedResponses && kDebugMode) {
      debugPrint('HttpSecurityPinningClient: allowUnverifiedResponses is '
          'enabled; some responses will not be verified.');
    }
  }

  bool get _bypassAllowed => honorBadCertificateCallback && !kReleaseMode;

  /// Returns the verifier for [url], `null` if the host may pass unverified,
  /// or throws [UnpinnedHostException].
  PayloadVerifier? _verifierFor(Uri url) {
    final verifier = _verifiersByHost?.lookup(url.host) ?? _defaultVerifier;
    if (verifier != null) return verifier;
    // Browsers map Unicode look-alikes (fullwidth letters, U+3002 dots, soft
    // hyphens, ...) onto ASCII host names before connecting, which this
    // lookup cannot reproduce: such hosts never pass unverified.
    final asciiHost =
        url.host.codeUnits.every((c) => c < 0x80) && !url.host.contains('%');
    if (allowUnverifiedResponses && asciiHost) return null;
    throw UnpinnedHostException(url.host, what: 'response-signing keys');
  }

  String _newNonce() {
    final bytes = Uint8List(16);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static const Set<String> _idempotentMethods = {
    'GET',
    'HEAD',
    'OPTIONS',
    'PUT',
    'DELETE',
    'TRACE',
  };

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final verifier = _verifierFor(request.url);
    final retryable = request is http.Request &&
        _idempotentMethods.contains(request.method.toUpperCase());

    var attempt = 0;
    var current = request;
    while (true) {
      attempt++;
      try {
        return await _sendOnce(current, verifier);
      } on CertificatePinningException {
        // Includes every WebSecurityException: never retried.
        rethrow;
      } catch (e) {
        final transient =
            (e is http.ClientException || e is TimeoutException) &&
                e is! ResponseTooLargeException;
        if (!retryable || !transient || attempt > retryCount) rethrow;
        if (kDebugMode) {
          debugPrint('HttpSecurityPinningClient: attempt $attempt for '
              '${request.url.host} failed ($e); retrying.');
        }
        await Future<void>.delayed(retryDelay * attempt);
        current = _copy(request);
      }
    }
  }

  static http.Request _copy(http.Request original) {
    return http.Request(original.method, original.url)
      ..headers.addAll(original.headers)
      ..bodyBytes = original.bodyBytes
      ..followRedirects = original.followRedirects
      ..maxRedirects = original.maxRedirects
      ..persistentConnection = original.persistentConnection;
  }

  Future<http.StreamedResponse> _sendOnce(
    http.BaseRequest request,
    PayloadVerifier? verifier,
  ) async {
    final stopwatch = Stopwatch()..start();
    Duration remaining() {
      final left = timeout - stopwatch.elapsed;
      return left > Duration.zero ? left : Duration.zero;
    }

    final nonce = verifier == null ? null : _newNonce();
    if (nonce != null) request.headers[PayloadVerifier.nonceHeader] = nonce;

    final response = await _inner.send(request).timeout(remaining());
    if (verifier == null) {
      // This host was explicitly allowed to pass unverified. The response is
      // returned as a stream: neither the body deadline nor maxResponseBytes
      // apply.
      return response;
    }

    final finalUrl = switch (response) {
      http.BaseResponseWithUrl(:final url) => url,
      _ => request.url,
    };

    Uint8List bodyBytes = Uint8List(0);
    try {
      if (!_sameResource(finalUrl, request.url)) {
        // The redirect itself is not signed: verifying the final response
        // would let an intermediary substitute another endpoint or host.
        await response.stream.listen(null).cancel();
        throw SignatureVerificationException(
          'The response was redirected to $finalUrl. Redirects cannot be '
          'verified; request the final URL directly.',
        );
      }
      bodyBytes = await _readBody(response, remaining());
      await verifier.verify(
        method: request.method,
        url: request.url,
        statusCode: response.statusCode,
        nonce: nonce ?? '',
        headers: response.headers,
        bodyBytes: bodyBytes,
      );
    } on WebSecurityException catch (e) {
      if (!_askBypass(e, request.url)) rethrow;
      if (kDebugMode) {
        debugPrint('HttpSecurityPinningClient: verification failed for '
            '${request.url.host}; accepted for this response only via '
            'badCertificateCallback (debug build).');
      }
    }

    return _VerifiedStreamedResponse(
      Stream.value(bodyBytes),
      response.statusCode,
      url: finalUrl,
      contentLength: bodyBytes.length,
      request: response.request,
      headers: response.headers,
      isRedirect: response.isRedirect,
      persistentConnection: response.persistentConnection,
      reasonPhrase: response.reasonPhrase,
    );
  }

  static bool _sameResource(Uri a, Uri b) =>
      a.scheme.toLowerCase() == b.scheme.toLowerCase() &&
      SignatureBase.authorityOf(a) == SignatureBase.authorityOf(b) &&
      SignatureBase.requestTargetOf(a) == SignatureBase.requestTargetOf(b);

  bool _askBypass(Object error, Uri url) {
    final cb = badCertificateCallback;
    if (cb == null) return false;
    var accepts = false;
    try {
      accepts = cb(error, url.host, url.port);
    } catch (e) {
      if (kDebugMode) {
        debugPrint(
            'HttpSecurityPinningClient: badCertificateCallback threw: $e');
      }
    }
    return accepts && _bypassAllowed;
  }

  Future<Uint8List> _readBody(
    http.StreamedResponse response,
    Duration timeLeft,
  ) async {
    final limit = maxResponseBytes;
    final declared = response.contentLength;
    if (limit != null && declared != null && declared > limit) {
      throw ResponseTooLargeException(limit, response.request?.url);
    }
    final builder = BytesBuilder(copy: false);
    final done = Completer<Uint8List>();
    late final StreamSubscription<List<int>> subscription;
    subscription = response.stream.listen(
      (chunk) {
        builder.add(chunk);
        if (limit != null && builder.length > limit) {
          subscription.cancel();
          done.completeError(
              ResponseTooLargeException(limit, response.request?.url));
        }
      },
      onError: (Object e, StackTrace s) {
        if (!done.isCompleted) done.completeError(e, s);
      },
      onDone: () {
        if (!done.isCompleted) done.complete(builder.takeBytes());
      },
      cancelOnError: true,
    );
    return done.future.timeout(timeLeft, onTimeout: () {
      subscription.cancel();
      throw TimeoutException('Reading the response body timed out', timeout);
    });
  }

  @override
  void close() {
    _inner.close();
  }
}

/// A buffered, verified response that also reports its final URL.
class _VerifiedStreamedResponse extends http.StreamedResponse
    implements http.BaseResponseWithUrl {
  @override
  final Uri url;

  _VerifiedStreamedResponse(
    super.stream,
    super.statusCode, {
    required this.url,
    super.contentLength,
    super.request,
    super.headers,
    super.isRedirect,
    super.persistentConnection,
    super.reasonPhrase,
  });
}
