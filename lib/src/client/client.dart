import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../core/exceptions.dart';
import '../core/pin_policy.dart';
import '../core/presented_certificate.dart';
import '../core/spki_pin.dart';
import '../service/certificate_cache.dart';
import '../service/pinning_service.dart';

/// An implementation of Dart's [HttpClient] that enforces certificate pinning
/// against Subject Public Key Info (SPKI) SHA-256 hashes.
///
/// Example usage with `package:http`:
/// ```dart
/// final client = IOClient(HttpSecurityPinningClient([
///   'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=',
/// ]));
/// final response = await client.get(Uri.parse('https://github.com'));
/// ```
class HttpSecurityPinningClient implements HttpClient {
  static const String _tag = 'HttpSecurityPinningClient';

  /// Whether certificate pinning is supported on the current platform.
  ///
  /// Returns `true` on Android, iOS, Windows, macOS, and Linux.
  /// Returns `false` on Flutter Web.
  static bool get isSupported => true;

  /// Clears the global cache of fetched certificate chains.
  static void clearCache() {
    CertificateChainCache.shared.clear();
  }

  /// The policy determining which pins apply to which host.
  final PinPolicy _policy;

  /// The timeout for fetching the certificate chain during the TLS probe.
  final Duration timeout;

  /// The number of times to retry fetching the certificate chain on failure.
  final int retryCount;

  /// The delay between retry attempts.
  final Duration retryDelay;

  /// Whether to honor [badCertificateCallback] returning `true` to bypass
  /// pinning validation when inspecting or debugging certificates.
  ///
  /// Defaults to `false` for security. **Never enable this in production.**
  final bool honorBadCertificateCallback;

  final PinningService _pinningService;

  // Active delegate clients managed per "host:port".
  final Map<String, Future<HttpClient>> _clients = {};
  final Set<String> _bypassedHosts = {};

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
  String Function(Uri url)? _findProxy;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;

  final List<_Credential> _credentials = [];
  final List<_ProxyCredential> _proxyCredentials = [];

  /// Creates a client that applies [spkiHashes] to all HTTPS requests.
  ///
  /// [spkiHashes] accepts:
  /// * standard base64 SPKI SHA-256 digests
  /// * hashes with `sha256/` prefix
  /// * URL-safe and unpadded base64
  HttpSecurityPinningClient(
    List<String> spkiHashes, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    PinningService? pinningService,
  })  : _policy = PinPolicy.uniform(spkiHashes.map(SpkiPin.parse)),
        _pinningService = pinningService ?? PinningService();

  /// Creates a client with fine-grained per-host pin policies.
  ///
  /// [pinsByHost] maps hostnames to lists of pins. Wildcards like `*.example.com`
  /// match any subdomain (e.g., `api.example.com`).
  ///
  /// If [allowUnpinnedHosts] is `false` (default), requests to unpinned hosts throw
  /// [UnpinnedHostException]. If `true`, unpinned hosts use standard system TLS.
  HttpSecurityPinningClient.perHost(
    Map<String, List<String>> pinsByHost, {
    bool allowUnpinnedHosts = false,
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
    this.retryDelay = const Duration(milliseconds: 200),
    this.honorBadCertificateCallback = false,
    PinningService? pinningService,
  })  : _policy = PinPolicy.perHost(
          pinsByHost.map((k, v) => MapEntry(k, v.map(SpkiPin.parse))),
          allowUnpinnedHosts: allowUnpinnedHosts,
        ),
        _pinningService = pinningService ?? PinningService();

  /// Creates an underlying native [HttpClient] without triggering infinite
  /// recursion when [HttpOverrides.global] is installed.
  static HttpClient _createRawHttpClient([SecurityContext? context]) {
    return HttpOverrides.runWithHttpOverrides(
      () => HttpClient(context: context),
      _NoHttpOverrides(),
    );
  }

  void _applyStateTo(HttpClient client, String host, int port) {
    client.idleTimeout = _idleTimeout;
    client.connectionTimeout = _connectionTimeout;
    client.maxConnectionsPerHost = _maxConnectionsPerHost;
    client.autoUncompress = _autoUncompress;
    client.userAgent = _userAgent;

    client.authenticate = _authenticate;
    client.connectionFactory = _connectionFactory;
    client.keyLog = _keyLog;
    client.findProxy = _findProxy;
    client.authenticateProxy = _authenticateProxy;

    for (final c in _credentials) {
      client.addCredentials(c.url, c.realm, c.credentials);
    }
    for (final pc in _proxyCredentials) {
      client.addProxyCredentials(pc.host, pc.port, pc.realm, pc.credentials);
    }

    client.badCertificateCallback = (cert, h, p) {
      debugPrint('$_tag: Bad certificate callback triggered for $h:$p.');
      // Invalidate cache for this host on certificate error (supports cert renewal)
      final cacheKey = '$h:$p'.toLowerCase();
      _pinningService.cache.invalidate(cacheKey);

      bool userAccepts = false;
      final cb = _badCertificateCallback;
      if (cb != null) {
        try {
          userAccepts = cb(cert, h, p);
        } catch (e) {
          debugPrint('$_tag: Error in user badCertificateCallback: $e');
        }
      }

      if (honorBadCertificateCallback && userAccepts) {
        debugPrint(
            '$_tag: Certificate accepted via badCertificateCallback (honorBadCertificateCallback=true)');
        return true;
      }
      return false;
    };
  }

  Future<HttpClient> _getClientFor(Uri url) async {
    if (_isClosed) {
      throw StateError('Cannot use HttpSecurityPinningClient after close()');
    }

    final key = CertificateChainCache.keyFor(url);
    final existing = _clients[key];
    if (existing != null) {
      return existing;
    }

    final future = _createPinnedClient(url);
    _clients[key] = future;
    future.then<void>((_) {}, onError: (Object _) {
      if (identical(_clients[key], future)) {
        _clients.remove(key);
      }
    });
    return future;
  }

  Future<HttpClient> _createPinnedClient(Uri url) async {
    final pins = _policy.pinsFor(url.host);

    // If target is unpinned, return standard raw client
    if (pins == null || pins.isEmpty) {
      final client = _createRawHttpClient();
      _applyStateTo(client, url.host, url.port);
      return client;
    }

    // Enforce HTTPS when pinning is required
    if (url.scheme != 'https') {
      throw InsecureConnectionException(url);
    }

    // Check if host was previously bypassed via badCertificateCallback
    final key = CertificateChainCache.keyFor(url);
    if (_bypassedHosts.contains(key)) {
      debugPrint(
          '$_tag: Host ${url.host} is in bypass list; using default SecurityContext.');
      final client = _createRawHttpClient();
      _applyStateTo(client, url.host, url.port);
      return client;
    }

    // Evaluate certificate chain against pins
    final evalResult = await _pinningService.evaluatePins(
      url,
      pins,
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
    );

    if (evalResult.matchedCerts.isEmpty) {
      // Invalidate cache immediately on pin failure
      _pinningService.cache.invalidate(key);

      // Call badCertificateCallback if present so caller can inspect
      final cb = _badCertificateCallback;
      if (cb != null && evalResult.presentedChain.isNotEmpty) {
        final presentedLeaf =
            PresentedCertificate.fromDer(evalResult.presentedChain.first);
        bool userAccepts = false;
        try {
          userAccepts = cb(presentedLeaf, url.host, url.port);
        } catch (e) {
          debugPrint('$_tag: Error in user badCertificateCallback: $e');
        }

        if (honorBadCertificateCallback && userAccepts) {
          debugPrint(
              '$_tag: Pinning failed for ${url.host}, but bypassed via badCertificateCallback '
              '(honorBadCertificateCallback is enabled).');
          _bypassedHosts.add(key);
          final client = _createRawHttpClient();
          _applyStateTo(client, url.host, url.port);
          return client;
        }
      }

      throw NoValidPinsFoundException(
        url.host,
        observedPins: evalResult.observedPins,
        presentedChain: evalResult.presentedChain,
      );
    }

    final securityContext =
        _pinningService.createPinnedSecurityContext(evalResult.matchedCerts);
    final client = _createRawHttpClient(securityContext);
    _applyStateTo(client, url.host, url.port);
    return client;
  }

  Future<HttpClientRequest> _executeWithRetryOnTlsError(
    Uri url,
    Future<HttpClientRequest> Function(HttpClient client) action,
  ) async {
    final client = await _getClientFor(url);
    try {
      return await action(client);
    } on HandshakeException catch (e) {
      // Supports certificate renewal: if handshake fails on cached context,
      // invalidate cache & pooled client, and retry once.
      debugPrint(
        '$_tag: HandshakeException on ${url.host}: $e. '
        'Invalidating cache and retrying once...',
      );
      final key = CertificateChainCache.keyFor(url);
      _pinningService.cache.invalidate(key);
      _clients.remove(key);

      final freshClient = await _getClientFor(url);
      return await action(freshClient);
    }
  }

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) {
    final url = Uri(scheme: 'https', host: host, port: port, path: path);
    return openUrl(method, url);
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) {
    return _executeWithRetryOnTlsError(url, (c) => c.openUrl(method, url));
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

  @override
  Duration get idleTimeout => _idleTimeout;

  @override
  set idleTimeout(Duration timeout) {
    _idleTimeout = timeout;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.idleTimeout = timeout;
      }, onError: (_) {});
    }
  }

  @override
  Duration? get connectionTimeout => _connectionTimeout;

  @override
  set connectionTimeout(Duration? timeout) {
    _connectionTimeout = timeout;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.connectionTimeout = timeout;
      }, onError: (_) {});
    }
  }

  @override
  int? get maxConnectionsPerHost => _maxConnectionsPerHost;

  @override
  set maxConnectionsPerHost(int? max) {
    _maxConnectionsPerHost = max;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.maxConnectionsPerHost = max;
      }, onError: (_) {});
    }
  }

  @override
  bool get autoUncompress => _autoUncompress;

  @override
  set autoUncompress(bool auto) {
    _autoUncompress = auto;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.autoUncompress = auto;
      }, onError: (_) {});
    }
  }

  @override
  String? get userAgent => _userAgent;

  @override
  set userAgent(String? agent) {
    _userAgent = agent;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.userAgent = agent;
      }, onError: (_) {});
    }
  }

  @override
  set authenticate(
      Future<bool> Function(Uri url, String scheme, String? realm)? f) {
    _authenticate = f;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.authenticate = f;
      }, onError: (_) {});
    }
  }

  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> Function(
              Uri url, String? proxyHost, int? proxyPort)?
          f) {
    _connectionFactory = f;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.connectionFactory = f;
      }, onError: (_) {});
    }
  }

  @override
  set keyLog(void Function(String line)? callback) {
    _keyLog = callback;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.keyLog = callback;
      }, onError: (_) {});
    }
  }

  @override
  set findProxy(String Function(Uri url)? f) {
    _findProxy = f;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.findProxy = f;
      }, onError: (_) {});
    }
  }

  @override
  set authenticateProxy(
      Future<bool> Function(
              String host, int port, String scheme, String? realm)?
          f) {
    _authenticateProxy = f;
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.authenticateProxy = f;
      }, onError: (_) {});
    }
  }

  @override
  set badCertificateCallback(
      bool Function(X509Certificate cert, String host, int port)? callback) {
    _badCertificateCallback = callback;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add(_Credential(url, realm, credentials));
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.addCredentials(url, realm, credentials);
      }, onError: (_) {});
    }
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add(_ProxyCredential(host, port, realm, credentials));
    for (final cf in _clients.values) {
      cf.then<void>((c) {
        c.addProxyCredentials(host, port, realm, credentials);
      }, onError: (_) {});
    }
  }

  @override
  void close({bool force = false}) {
    _isClosed = true;
    for (final cf in _clients.values) {
      cf.then((c) => c.close(force: force)).catchError((_) {});
    }
    _clients.clear();
  }
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
