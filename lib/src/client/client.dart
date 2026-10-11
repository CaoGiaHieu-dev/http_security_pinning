// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../core/exceptions.dart';
import '../core/host_normalizer.dart';
import '../core/pin_policy.dart';
import '../core/presented_certificate.dart';
import '../core/spki_pin.dart';
import '../fetcher/dart_io_certificate_fetcher.dart';
import '../service/certificate_cache.dart';
import '../service/pinning_service.dart';

/// An implementation of Dart's [HttpClient] that enforces certificate pinning
/// against Subject Public Key Info (SPKI) SHA-256 hashes.
///
/// For every request the client:
///
/// 1. looks up the pins for the target host (throwing
///    [UnpinnedHostException] for hosts the policy does not allow),
/// 2. refuses non-HTTPS URLs to pinned hosts ([InsecureConnectionException]),
/// 3. probes the server's certificate chain once per host and keeps only the
///    certificates whose SPKI hash matches a pin, and
/// 4. sends the request over a connection whose **only** trust anchors are
///    those matched certificates (system roots are disabled). The TLS
///    handshake, including host name and validity checks, happens before any
///    request data is sent.
///
/// Redirects are followed by this client itself, so every hop goes through
/// the same checks (a redirect to `http://` or to a forbidden host fails).
///
/// Example usage with `package:http`:
/// ```dart
/// final client = IOClient(HttpSecurityPinningClient([
///   'PRIMARY_PIN_BASE64=',
///   'BACKUP_PIN_BASE64=',
/// ]));
/// final response = await client.get(Uri.parse('https://api.example.com'));
/// ```
class HttpSecurityPinningClient implements HttpClient {
  static const String _tag = 'HttpSecurityPinningClient';

  /// Whether TLS certificate pinning is supported on the current platform.
  ///
  /// `true` on Android, iOS, Windows, macOS and Linux. On Flutter Web, where
  /// browsers do not expose the TLS handshake, this is `false` (the Web client
  /// verifies response signatures instead).
  static bool get isSupported => true;

  /// Clears the global cache of fetched certificate chains.
  static void clearCache() {
    CertificateChainCache.shared.clear();
  }

  /// The policy determining which pins apply to which host.
  final PinPolicy _policy;

  /// The timeout for fetching the certificate chain during the TLS probe.
  final Duration timeout;

  /// How many times a failed certificate-chain probe is retried (in addition
  /// to the first attempt). The delay grows linearly: `retryDelay * attempt`.
  final int retryCount;

  /// The base delay between probe retry attempts.
  final Duration retryDelay;

  /// Whether a `true` result of [badCertificateCallback] may bypass pinning
  /// for a single request, for example to inspect traffic with a debugging
  /// proxy.
  ///
  /// Defaults to `false`. It is **ignored in release builds**
  /// ([kReleaseMode]), and it is never consulted for a connection whose
  /// certificate already matched a pin.
  final bool honorBadCertificateCallback;

  final PinningService _pinningService;

  // Delegate clients per "scheme://host:port".
  final Map<String, Future<_Delegate>> _delegates = {};

  // Delegates removed after a TLS failure, closed once their in-flight
  // requests had time to finish (or by close()).
  final Map<_Delegate, Timer> _retired = {};

  // Trust anchors (pin-matching certificates) seen per "host:port", merged
  // across probes so that load-balanced servers presenting different pinned
  // chains keep working.
  final Map<String, Map<String, Uint8List>> _anchors = {};
  static const int _maxAnchorsPerHost = 16;
  static const int _maxAnchorHosts = 256;

  bool _isClosed = false;

  Duration _idleTimeout = const Duration(seconds: 15);
  Duration? _connectionTimeout;
  int? _maxConnectionsPerHost;
  bool _autoUncompress = true;
  String? _userAgent;

  bool Function(X509Certificate cert, String host, int port)?
      _badCertificateCallback;
  Future<bool> Function(Uri url, String scheme, String? realm)? _authenticate;
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? _connectionFactory;
  void Function(String line)? _keyLog;
  // Same default as dart:io's HttpClient: honour http(s)_proxy variables.
  String Function(Uri url)? _findProxy = HttpClient.findProxyFromEnvironment;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;

  final List<_Credential> _credentials = [];
  final List<_ProxyCredential> _proxyCredentials = [];

  /// Creates a client that applies [spkiHashes] to every host.
  ///
  /// [spkiHashes] accepts standard base64 SPKI SHA-256 digests, hashes with a
  /// `sha256/` prefix, and URL-safe or unpadded base64. It must not be empty
  /// ([ArgumentError]); configure at least two pins (a primary and a backup).
  ///
  /// [serverPublicKeys], [timestampTolerance], [allowUnverifiedResponses]
  /// and [maxResponseBytes] are only used by the Flutter Web implementation
  /// and are ignored here; they exist so that the same code compiles on every
  /// platform.
  HttpSecurityPinningClient(
    List<String> spkiHashes, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    Duration? timestampTolerance = const Duration(minutes: 5),
    List<List<int>>? serverPublicKeys,
    bool allowUnverifiedResponses = false,
    int? maxResponseBytes = 10 * 1024 * 1024,
    PinningService? pinningService,
  })  : _policy = PinPolicy.uniform(spkiHashes.map(SpkiPin.parse)),
        _pinningService = pinningService ?? PinningService() {
    _validateArguments();
  }

  /// Creates a client with fine-grained per-host pin policies.
  ///
  /// [pinsByHost] maps host names to lists of pins. A wildcard such as
  /// `*.example.com` matches subdomains at any depth but not `example.com`
  /// itself.
  ///
  /// If [allowUnpinnedHosts] is `false` (default), requests to unpinned hosts
  /// throw [UnpinnedHostException]. If `true`, unpinned hosts use the normal
  /// system trust store **without pinning**.
  ///
  /// [serverPublicKeys], [serverPublicKeysByHost], [timestampTolerance],
  /// [allowUnverifiedResponses] and [maxResponseBytes] are only used on
  /// Flutter Web and are ignored here.
  HttpSecurityPinningClient.perHost(
    Map<String, List<String>> pinsByHost, {
    bool allowUnpinnedHosts = false,
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    Duration? timestampTolerance = const Duration(minutes: 5),
    List<List<int>>? serverPublicKeys,
    Map<String, List<List<int>>>? serverPublicKeysByHost,
    bool allowUnverifiedResponses = false,
    int? maxResponseBytes = 10 * 1024 * 1024,
    PinningService? pinningService,
  })  : _policy = PinPolicy.perHost(
          pinsByHost.map((k, v) => MapEntry(k, v.map(SpkiPin.parse))),
          allowUnpinnedHosts: allowUnpinnedHosts,
        ),
        _pinningService = pinningService ?? PinningService() {
    _validateArguments();
  }

  void _validateArguments() {
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
    if (honorBadCertificateCallback && kReleaseMode) {
      debugPrint(
        '$_tag: honorBadCertificateCallback is ignored in release builds.',
      );
    }
  }

  bool get _bypassAllowed => honorBadCertificateCallback && !kReleaseMode;

  /// Creates an underlying native [HttpClient] without triggering infinite
  /// recursion when [HttpOverrides.global] is installed.
  static HttpClient _createRawHttpClient([SecurityContext? context]) {
    return HttpOverrides.runWithHttpOverrides(
      () => HttpClient(context: context),
      _NoHttpOverrides(),
    );
  }

  /// Asks the user callback about [cert] and returns whether a bypass is
  /// allowed. The callback is always invoked (for diagnostics), but its
  /// answer only counts when [_bypassAllowed].
  bool _askBadCertificateCallback(X509Certificate cert, String host, int port) {
    final cb = _badCertificateCallback;
    if (cb == null) return false;
    var userAccepts = false;
    try {
      userAccepts = cb(cert, host, port);
    } catch (e) {
      if (kDebugMode) {
        debugPrint('$_tag: Error in user badCertificateCallback: $e');
      }
    }
    return userAccepts && _bypassAllowed;
  }

  void _applyStateTo(_Delegate delegate) {
    final client = delegate.client;
    client.idleTimeout = _idleTimeout;
    client.connectionTimeout = _connectionTimeout;
    client.maxConnectionsPerHost = _maxConnectionsPerHost;
    client.autoUncompress = _autoUncompress;
    client.userAgent = _userAgent;

    client.authenticate = _authenticate;
    client.keyLog = _keyLog;
    client.findProxy = _findProxy;
    client.authenticateProxy = _authenticateProxy;
    _installConnectionFactory(delegate);

    for (final c in _credentials) {
      client.addCredentials(c.url, c.realm, c.credentials);
    }
    for (final pc in _proxyCredentials) {
      client.addProxyCredentials(pc.host, pc.port, pc.realm, pc.credentials);
    }

    if (delegate.pins != null) {
      // A pinned connection is never bypassed: the callback is only notified.
      client.badCertificateCallback = (cert, h, p) {
        if (kDebugMode) {
          debugPrint('$_tag: Pinned TLS handshake rejected for $h:$p.');
        }
        _pinningService.cache
            .invalidate(CertificateChainCache.keyFor(Uri(host: h, port: p)));
        _askBadCertificateCallback(cert, h, p);
        return false;
      };
    } else {
      client.badCertificateCallback = (cert, h, p) {
        final accepted = _askBadCertificateCallback(cert, h, p);
        if (accepted) {
          debugPrint(
            '$_tag: Certificate for $h:$p accepted via badCertificateCallback '
            '(honorBadCertificateCallback=true, debug build only).',
          );
        }
        return accepted;
      };
    }
  }

  /// Wraps a user supplied [connectionFactory] so that it cannot bypass
  /// pinning: for direct HTTPS connections to a pinned host, the factory must
  /// return a plain socket, which is secured with the pinned
  /// [SecurityContext] (host name, validity and chain included). An already
  /// secured socket is refused, since its validation cannot be checked.
  void _installConnectionFactory(_Delegate delegate) {
    final userFactory = _connectionFactory;
    final pins = delegate.pins;
    final context = delegate.context;
    if (userFactory == null || pins == null || context == null) {
      delegate.client.connectionFactory = userFactory;
      return;
    }
    delegate.client.connectionFactory = (uri, proxyHost, proxyPort) async {
      final task = await userFactory(uri, proxyHost, proxyPort);
      if (proxyHost != null || !uri.isScheme('https')) {
        // Through a proxy dart:io itself secures the tunnel with the pinned
        // context.
        return task;
      }
      final secured = task.socket.then<Socket>((socket) async {
        if (socket is SecureSocket) {
          socket.destroy();
          throw HandshakeException(
            'connectionFactory returned a SecureSocket for the pinned host '
            '${uri.host}. Return a plain Socket instead; the client secures '
            'it with the pinned SecurityContext.',
          );
        }
        return SecureSocket.secure(
          socket,
          host: uri.host,
          context: context,
          keyLog: _keyLog,
        );
      });
      return ConnectionTask.fromSocket(secured, task.cancel);
    };
  }

  /// Validates [url] against the policy and returns its pins (`null` for an
  /// allowed unpinned host). Runs for every request and every redirect hop.
  Set<SpkiPin>? _pinsForRequest(Uri url) {
    if (!HostNormalizer.isValid(HostNormalizer.normalize(url.host))) {
      throw ArgumentError.value(url, 'url', 'contains an invalid host name');
    }
    final pins = _policy.pinsFor(url.host);
    if (pins != null && !url.isScheme('https')) {
      throw InsecureConnectionException(url);
    }
    return pins;
  }

  /// Pinned hosts get a delegate each (its trust anchors are per host);
  /// unpinned hosts share one plain delegate per scheme.
  static String _delegateKeyFor(Uri url, Set<SpkiPin>? pins) => pins == null
      ? '${url.scheme.toLowerCase()}://*'
      : '${url.scheme.toLowerCase()}://${CertificateChainCache.keyFor(url)}';

  Future<_Delegate> _delegateFor(Uri url, Set<SpkiPin>? pins) {
    final key = _delegateKeyFor(url, pins);
    final existing = _delegates[key];
    if (existing != null) return existing;

    final future = _createDelegate(url, pins);
    _delegates[key] = future;
    future.then<void>((_) {}, onError: (Object _) {
      if (identical(_delegates[key], future)) _delegates.remove(key);
    });
    return future;
  }

  Future<_Delegate> _createDelegate(Uri url, Set<SpkiPin>? pins) async {
    if (pins == null) {
      final delegate = _Delegate(_createRawHttpClient());
      _applyStateTo(delegate);
      return delegate;
    }

    final cacheKey = CertificateChainCache.keyFor(url);
    final evalResult = await _pinningService.evaluatePins(
      url,
      pins,
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
      findProxy: _findProxy,
    );

    if (evalResult.matchedCerts.isEmpty) {
      _pinningService.cache.invalidate(cacheKey);
      final leafOnly = _pinningService.fetcher is DartIoCertificateFetcher;

      if (evalResult.presentedChain.isNotEmpty) {
        final presentedLeaf =
            PresentedCertificate.fromDer(evalResult.presentedChain.first);
        if (_askBadCertificateCallback(presentedLeaf, url.host, url.port)) {
          // One-shot bypass: this delegate is not cached, so the next request
          // probes and asks the callback again.
          debugPrint(
            '$_tag: Pinning failed for ${url.host}, bypassed for one request '
            'via badCertificateCallback (debug build only).',
          );
          final delegate = _Delegate(_createRawHttpClient(), oneShot: true);
          _applyStateTo(delegate);
          return delegate;
        }
      }

      throw NoValidPinsFoundException(
        url.host,
        observedPins: evalResult.observedPins,
        presentedChain: evalResult.presentedChain,
        leafOnly: leafOnly,
      );
    }

    // Most recently used host last; the number of hosts is bounded.
    final anchors = _anchors.remove(cacheKey) ?? {};
    _anchors[cacheKey] = anchors;
    while (_anchors.length > _maxAnchorHosts) {
      _anchors.remove(_anchors.keys.first);
    }
    for (final cert in evalResult.matchedCerts) {
      anchors[base64.encode(cert)] = cert;
    }
    while (anchors.length > _maxAnchorsPerHost) {
      anchors.remove(anchors.keys.first);
    }

    final context =
        _pinningService.createPinnedSecurityContext(anchors.values.toList());
    final delegate = _Delegate(
      _createRawHttpClient(context),
      pins: pins,
      context: context,
    );
    _applyStateTo(delegate);
    return delegate;
  }

  /// Opens [method] [url] on the right delegate, retrying once with a fresh
  /// probe if the TLS handshake fails (e.g. after a certificate renewal).
  Future<HttpClientRequest> _openOnDelegate(String method, Uri url) async {
    _checkOpen();
    final pins = _pinsForRequest(url);
    final key = _delegateKeyFor(url, pins);

    var retryable = false;
    Future<HttpClientRequest> attempt() async {
      final future = _delegateFor(url, pins);
      final delegate = await future;
      // Only a pinned delegate is re-probed after a TLS failure; an unpinned
      // or one-shot (bypass) delegate fails as is.
      retryable = delegate.pins != null;
      if (_isClosed) {
        delegate.client.close(force: true);
        throw StateError('Cannot use HttpSecurityPinningClient after close()');
      }
      if (delegate.oneShot) {
        if (delegate.claimed) {
          // Another request already used this bypass decision: probe and ask
          // the callback again for this one.
          return attempt();
        }
        delegate.claimed = true;
        if (identical(_delegates[key], future)) _delegates.remove(key);
      }
      try {
        final request = await delegate.client.openUrl(method, url);
        request.followRedirects = false;
        return request;
      } on HandshakeException {
        // Only pinned delegates are replaced: an unpinned host failing its
        // handshake says nothing about the shared unpinned delegate.
        if (delegate.pins != null && identical(_delegates[key], future)) {
          _delegates.remove(key);
          // Retire the delegate without cancelling other requests that are
          // still using or waiting for its connections; its idle
          // connections are released afterwards.
          _retired[delegate] =
              Timer(_idleTimeout + const Duration(seconds: 1), () {
            _retired.remove(delegate);
            delegate.client.close();
          });
        }
        rethrow;
      } finally {
        // Let the in-flight request finish, then release the one-shot client.
        if (delegate.oneShot) delegate.client.close();
      }
    }

    try {
      return await attempt();
    } on HandshakeException catch (e) {
      if (!retryable) rethrow;
      if (kDebugMode) {
        debugPrint(
          '$_tag: HandshakeException on ${url.host}: $e. '
          'Re-probing the certificate chain and retrying once...',
        );
      }
      _checkOpen();
      _pinningService.cache.invalidate(CertificateChainCache.keyFor(url));
      return attempt();
    }
  }

  void _checkOpen() {
    if (_isClosed) {
      throw StateError('Cannot use HttpSecurityPinningClient after close()');
    }
  }

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) {
    // Same splitting of query and fragment as dart:io's HttpClient.open, but
    // with an https scheme.
    var fragmentStart = path.length;
    var queryStart = path.length;
    for (var i = path.length - 1; i >= 0; i--) {
      final char = path.codeUnitAt(i);
      if (char == 0x23 /* # */) {
        fragmentStart = i;
        queryStart = i;
      } else if (char == 0x3F /* ? */) {
        queryStart = i;
      }
    }
    String? query;
    if (queryStart < fragmentStart) {
      query = path.substring(queryStart + 1, fragmentStart);
      path = path.substring(0, queryStart);
    }
    final url =
        Uri(scheme: 'https', host: host, port: port, path: path, query: query);
    return openUrl(method, url);
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    final inner = await _openOnDelegate(method, url);
    return _PinnedClientRequest(this, inner, const [], _RedirectChain());
  }

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open('get', host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl('get', url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open('post', host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl('post', url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open('put', host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl('put', url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open('delete', host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl('delete', url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open('head', host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl('head', url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open('patch', host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl('patch', url);

  void _forEachDelegate(void Function(_Delegate delegate) action) {
    for (final future in _delegates.values) {
      future.then<void>(action, onError: (_) {});
    }
  }

  @override
  Duration get idleTimeout => _idleTimeout;

  @override
  set idleTimeout(Duration timeout) {
    _idleTimeout = timeout;
    _forEachDelegate((d) => d.client.idleTimeout = timeout);
  }

  @override
  Duration? get connectionTimeout => _connectionTimeout;

  @override
  set connectionTimeout(Duration? timeout) {
    _connectionTimeout = timeout;
    _forEachDelegate((d) => d.client.connectionTimeout = timeout);
  }

  @override
  int? get maxConnectionsPerHost => _maxConnectionsPerHost;

  @override
  set maxConnectionsPerHost(int? max) {
    _maxConnectionsPerHost = max;
    _forEachDelegate((d) => d.client.maxConnectionsPerHost = max);
  }

  @override
  bool get autoUncompress => _autoUncompress;

  @override
  set autoUncompress(bool auto) {
    _autoUncompress = auto;
    _forEachDelegate((d) => d.client.autoUncompress = auto);
  }

  @override
  String? get userAgent => _userAgent;

  @override
  set userAgent(String? agent) {
    _userAgent = agent;
    _forEachDelegate((d) => d.client.userAgent = agent);
  }

  @override
  set authenticate(
      Future<bool> Function(Uri url, String scheme, String? realm)? f) {
    _authenticate = f;
    _forEachDelegate((d) => d.client.authenticate = f);
  }

  /// Sets a custom connection factory.
  ///
  /// For direct HTTPS connections to pinned hosts the factory must return a
  /// plain (TCP) [Socket]: the client secures it with the pinned
  /// [SecurityContext]. A [SecureSocket] is always refused there (with a
  /// [HandshakeException]), since how it was validated is unknown.
  /// Connections through a proxy and to unpinned hosts are used as returned.
  /// The certificate probe does not use the factory.
  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> Function(
              Uri url, String? proxyHost, int? proxyPort)?
          f) {
    _connectionFactory = f;
    _forEachDelegate(_installConnectionFactory);
  }

  @override
  set keyLog(void Function(String line)? callback) {
    _keyLog = callback;
    _forEachDelegate((d) => d.client.keyLog = callback);
  }

  @override
  set findProxy(String Function(Uri url)? f) {
    _findProxy = f;
    _forEachDelegate((d) => d.client.findProxy = f);
  }

  @override
  set authenticateProxy(
      Future<bool> Function(
              String host, int port, String scheme, String? realm)?
          f) {
    _authenticateProxy = f;
    _forEachDelegate((d) => d.client.authenticateProxy = f);
  }

  /// Sets a callback that is notified about rejected certificates.
  ///
  /// It is invoked with a [PresentedCertificate] when a server's chain matches
  /// no pin, and with the platform certificate when a TLS handshake fails.
  /// Its return value is ignored unless [honorBadCertificateCallback] is
  /// `true` **and** the app runs in a debug or profile build; even then it can
  /// only bypass pinning for a single request and never for a connection
  /// whose certificate matched a pin.
  @override
  set badCertificateCallback(
      bool Function(X509Certificate cert, String host, int port)? callback) {
    _badCertificateCallback = callback;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add(_Credential(url, realm, credentials));
    _forEachDelegate((d) => d.client.addCredentials(url, realm, credentials));
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add(_ProxyCredential(host, port, realm, credentials));
    _forEachDelegate(
        (d) => d.client.addProxyCredentials(host, port, realm, credentials));
  }

  @override
  void close({bool force = false}) {
    _isClosed = true;
    _forEachDelegate((d) => d.client.close(force: force));
    _delegates.clear();
    for (final MapEntry(key: delegate, value: timer) in _retired.entries) {
      timer.cancel();
      delegate.client.close(force: force);
    }
    _retired.clear();
  }
}

/// A delegate [HttpClient] plus what it was configured with.
class _Delegate {
  final HttpClient client;

  /// The pins of the host, or `null` for an unpinned / bypassed delegate.
  final Set<SpkiPin>? pins;

  /// The pinned [SecurityContext], or `null` for an unpinned delegate.
  final SecurityContext? context;

  /// Whether the delegate serves a single request (debug bypass).
  final bool oneShot;

  /// Whether the single request of a [oneShot] delegate has been opened.
  bool claimed = false;

  _Delegate(this.client, {this.pins, this.context, this.oneShot = false});
}

/// State shared by every hop of one logical request, so that [abort] reaches
/// the hop that is currently in flight.
class _RedirectChain {
  HttpClientRequest? current;
  Object? abortError;
  StackTrace? abortStackTrace;

  /// Completes when the request is aborted.
  final Completer<void> aborted = Completer();
}

/// Wraps a delegate request so that redirects are followed by the pinning
/// client (re-checking pins, scheme and host policy on every hop) instead of
/// by the delegate.
class _PinnedClientRequest implements HttpClientRequest {
  final HttpSecurityPinningClient _client;
  final HttpClientRequest _inner;
  final List<RedirectInfo> _previousRedirects;
  final _RedirectChain _chain;
  final Completer<HttpClientResponse> _done = Completer();
  Future<HttpClientResponse>? _closeFuture;

  bool _followRedirects = true;
  int _maxRedirects = 5;

  _PinnedClientRequest(
    this._client,
    this._inner,
    this._previousRedirects,
    this._chain,
  ) {
    _chain.current = _inner;
    _inner.followRedirects = false;
    // Avoid unhandled errors if nobody listens to [done].
    _done.future.ignore();
  }

  @override
  bool get followRedirects => _followRedirects;

  @override
  set followRedirects(bool value) => _followRedirects = value;

  @override
  int get maxRedirects => _maxRedirects;

  @override
  set maxRedirects(int value) => _maxRedirects = value;

  @override
  Future<HttpClientResponse> close() {
    final existing = _closeFuture;
    if (existing != null) return existing;
    final future = _closeAndFollow();
    _closeFuture = future;
    future.then(_done.complete, onError: _done.completeError);
    return future;
  }

  Future<HttpClientResponse> _closeAndFollow() async {
    final response = _PinnedClientResponse(
      _client,
      this,
      await _inner.close(),
      _previousRedirects,
    );
    if (!_followRedirects || !response.isRedirect) return response;
    if (response.redirects.length >= _maxRedirects) {
      await response.drain<void>();
      throw RedirectException('Redirect limit exceeded', response.redirects);
    }
    await response.drain<void>();
    return response.redirect();
  }

  @override
  Future<HttpClientResponse> get done => _done.future;

  @override
  bool get persistentConnection => _inner.persistentConnection;

  @override
  set persistentConnection(bool value) => _inner.persistentConnection = value;

  @override
  int get contentLength => _inner.contentLength;

  @override
  set contentLength(int value) => _inner.contentLength = value;

  @override
  bool get bufferOutput => _inner.bufferOutput;

  @override
  set bufferOutput(bool value) => _inner.bufferOutput = value;

  @override
  String get method => _inner.method;

  @override
  Uri get uri => _inner.uri;

  @override
  HttpHeaders get headers => _inner.headers;

  @override
  List<Cookie> get cookies => _inner.cookies;

  @override
  HttpConnectionInfo? get connectionInfo => _inner.connectionInfo;

  @override
  void abort([Object? exception, StackTrace? stackTrace]) {
    _chain
      ..abortError ??=
          exception ?? HttpException('Request has been aborted', uri: uri)
      ..abortStackTrace ??= stackTrace;
    if (!_chain.aborted.isCompleted) _chain.aborted.complete();
    (_chain.current ?? _inner).abort(exception, stackTrace);
  }

  @override
  Encoding get encoding => _inner.encoding;

  @override
  set encoding(Encoding value) => _inner.encoding = value;

  @override
  void add(List<int> data) => _inner.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      _inner.addError(error, stackTrace);

  @override
  Future<void> addStream(Stream<List<int>> stream) => _inner.addStream(stream);

  @override
  Future<void> flush() => _inner.flush();

  @override
  void write(Object? object) => _inner.write(object);

  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) =>
      _inner.writeAll(objects, separator);

  @override
  void writeCharCode(int charCode) => _inner.writeCharCode(charCode);

  @override
  void writeln([Object? object = '']) => _inner.writeln(object);
}

/// Wraps a delegate response so that [redirect] goes through the pinning
/// client and [redirects] reports the hops followed by it.
class _PinnedClientResponse extends Stream<List<int>>
    implements HttpClientResponse {
  final HttpSecurityPinningClient _client;
  final _PinnedClientRequest _request;
  final HttpClientResponse _inner;

  @override
  final List<RedirectInfo> redirects;

  _PinnedClientResponse(
    this._client,
    this._request,
    this._inner,
    List<RedirectInfo> previousRedirects,
  ) : redirects = List.unmodifiable(previousRedirects);

  static const Set<String> _sensitiveHeaders = {
    'authorization',
    'www-authenticate',
    'proxy-authorization',
    'proxy-authenticate',
    'cookie',
    'cookie2',
  };

  static bool _isSameOrigin(Uri a, Uri b) =>
      a.isScheme(b.scheme) &&
      HostNormalizer.normalize(a.host) == HostNormalizer.normalize(b.host) &&
      a.port == b.port;

  @override
  Future<HttpClientResponse> redirect([
    String? method,
    Uri? url,
    bool? followLoops,
  ]) async {
    final previous = _request;
    method ??= statusCode == HttpStatus.seeOther && previous.method == 'POST'
        ? 'GET'
        : previous.method;
    if (url == null) {
      final location = headers.value(HttpHeaders.locationHeader);
      if (location == null) {
        throw RedirectException(
          'Server response has no Location header for redirect',
          redirects,
        );
      }
      try {
        url = Uri.parse(location);
      } on FormatException catch (e) {
        throw RedirectException(
            'Invalid Location header: ${e.message}', redirects);
      }
    }
    final resolved = previous.uri.resolveUri(url);
    if (previous.uri.isScheme('https') && !resolved.isScheme('https')) {
      // Never downgrade a TLS request, even to a host that may be unpinned.
      throw InsecureConnectionException(resolved);
    }
    if (followLoops != true) {
      for (final hop in redirects) {
        if (hop.location == resolved) {
          throw RedirectException('Redirect loop detected', redirects);
        }
      }
    }

    final chain = previous._chain;
    void throwIfAborted() {
      final error = chain.abortError;
      if (error != null) {
        Error.throwWithStackTrace(
            error, chain.abortStackTrace ?? StackTrace.current);
      }
    }

    throwIfAborted();
    // Goes through the full policy, scheme and pin checks again. An abort()
    // while the next hop is still being probed or connected wins the race;
    // the hop is then aborted as soon as it is open.
    final opening = _client._openOnDelegate(method, resolved);
    opening.then((request) {
      if (chain.abortError != null) {
        request.abort(chain.abortError, chain.abortStackTrace);
      }
    }, onError: (Object _) {});
    final HttpClientRequest inner;
    try {
      inner = await Future.any([
        opening,
        chain.aborted.future.then<HttpClientRequest>((_) {
          throwIfAborted();
          throw StateError('unreachable');
        }),
      ]);
    } on ArgumentError catch (e) {
      // A Location the server controls must not surface as an Error.
      throw RedirectException(
          'Invalid redirect target $resolved: ${e.message}', redirects);
    } on FormatException catch (e) {
      throw RedirectException(
          'Invalid redirect target $resolved: ${e.message}', redirects);
    }
    throwIfAborted();
    final request = _PinnedClientRequest(
      _client,
      inner,
      [...redirects, _RedirectInfo(statusCode, method, resolved)],
      chain,
    )
      ..followRedirects = previous.followRedirects
      ..maxRedirects = previous.maxRedirects;

    final sameOrigin = _isSameOrigin(previous.uri, resolved);
    previous.headers.forEach((name, values) {
      if (request.headers[name] != null) return;
      if (!sameOrigin && _sensitiveHeaders.contains(name.toLowerCase())) {
        return;
      }
      request.headers.set(name, values);
    });
    request.headers.chunkedTransferEncoding = false;
    request.contentLength = 0;
    return request.close();
  }

  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int> event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _inner.listen(
        onData,
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );

  @override
  int get statusCode => _inner.statusCode;

  @override
  String get reasonPhrase => _inner.reasonPhrase;

  @override
  int get contentLength => _inner.contentLength;

  @override
  HttpClientResponseCompressionState get compressionState =>
      _inner.compressionState;

  @override
  bool get persistentConnection => _inner.persistentConnection;

  @override
  bool get isRedirect => _inner.isRedirect;

  @override
  HttpHeaders get headers => _inner.headers;

  @override
  Future<Socket> detachSocket() => _inner.detachSocket();

  @override
  List<Cookie> get cookies => _inner.cookies;

  @override
  X509Certificate? get certificate => _inner.certificate;

  @override
  HttpConnectionInfo? get connectionInfo => _inner.connectionInfo;
}

class _RedirectInfo implements RedirectInfo {
  @override
  final int statusCode;
  @override
  final String method;
  @override
  final Uri location;

  const _RedirectInfo(this.statusCode, this.method, this.location);
}

class _Credential {
  final Uri url;
  final String realm;
  final HttpClientCredentials credentials;
  _Credential(this.url, this.realm, this.credentials);
}

class _ProxyCredential {
  final String host;
  final int port;
  final String realm;
  final HttpClientCredentials credentials;
  _ProxyCredential(this.host, this.port, this.realm, this.credentials);
}

/// Fallback [HttpOverrides] that avoids recursion when creating raw delegates.
class _NoHttpOverrides extends HttpOverrides {}
