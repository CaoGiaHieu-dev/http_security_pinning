import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:pem/pem.dart';

// --- Exception Classes ---

/// The base class for all exceptions thrown by the http_security_pinning package.
abstract class CertificatePinningException implements Exception {
  /// A descriptive message explaining the error.
  final String message;

  /// Creates a new certificate pinning exception.
  CertificatePinningException(this.message);

  @override
  String toString() => 'CertificatePinningException: $message';
}

/// Thrown when fetching the certificate chain from the native platform fails.
///
/// This can happen due to network errors, timeouts, or if the native
/// code encounters an unexpected issue. The [message] property contains
/// more details from the native layer.
class CertificateFetchException extends CertificatePinningException {
  /// Creates a new certificate fetch exception.
  CertificateFetchException(String message)
      : super('Failed to fetch certificate chain. Reason: $message');
}

/// Thrown when the server's certificate chain is successfully fetched,
/// but none of the certificates' SPKI hashes match the pins provided to the client.
///
/// This is the primary exception that indicates a pinning validation failure.
class NoValidPinsFoundException extends CertificatePinningException {
  /// The host for which the pinning validation failed.
  final String host;

  /// Creates a new "no valid pins found" exception.
  NoValidPinsFoundException(this.host)
      : super('No valid SPKI pins found for host: $host');
}

// --- Internal Service Class ---

/// A private service class that handles the core logic of certificate pinning.
///
/// This includes fetching certificates from the native layer, validating them
/// against the provided pins, and creating a [SecurityContext].
class _HttpSecurityPinningService {
  static const String _tag = "HttpSecurityPinningClient";
  static const MethodChannel _channel = MethodChannel('http_security_pinning');

  /// A cache of host certificates to avoid re-fetching on every request.
  static final Map<String, List<Uint8List>> _hostCertificates =
      <String, List<Uint8List>>{};

  /// Fetches the certificate chain for a given [url] from the native platform.
  ///
  /// Implements a retry mechanism based on [retryCount]. Each attempt respects
  /// the given [timeout].
  ///
  /// Throws a [CertificateFetchException] if all retry attempts fail.
  static Future<List<Uint8List>> _getHostCertificates(
    Uri url,
    Duration timeout,
    int retryCount,
  ) async {
    if (_hostCertificates[url.host] == null) {
      int attempts = 0;
      while (attempts <= retryCount) {
        try {
          final arguments = <String, dynamic>{
            'url': url.toString(),
            'timeout': timeout.inMilliseconds,
          };
          final List<Object?>? fetchedHostCertificates = await _channel
              .invokeMethod('fetchHostCertificates', arguments)
              .timeout(timeout +
                  const Duration(
                      seconds: 1)); // Add a grace period to the Dart timeout

          if (fetchedHostCertificates == null ||
              fetchedHostCertificates.isEmpty) {
            throw CertificateFetchException(
                'Native method returned no certificates.');
          }

          _hostCertificates[url.host] = fetchedHostCertificates
              .whereType<Uint8List>()
              .toList(growable: false);
          break; // Success, exit loop
        } on PlatformException catch (e) {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): ${e.message}");
          if (attempts > retryCount) {
            throw CertificateFetchException(
                e.message ?? 'Unknown platform error');
          }
        } on TimeoutException {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): Timeout");
          if (attempts > retryCount) {
            throw CertificateFetchException('Certificate fetch timed out.');
          }
        } catch (e) {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): $e");
          if (attempts > retryCount) {
            throw CertificateFetchException(e.toString());
          }
        }
      }
    }
    return _hostCertificates[url.host]!;
  }

  /// Filters the fetched certificate chain for a [url] against a set of [validPins].
  ///
  /// Throws a [NoValidPinsFoundException] if no certificates in the chain
  /// match the provided pins.
  static Future<List<Uint8List>> _hostPinCertificates(
    Uri url,
    Set<String> validPins,
    Duration timeout,
    int retryCount,
  ) async {
    final hostCertificates =
        await _HttpSecurityPinningService._getHostCertificates(
            url, timeout, retryCount);

    final info = StringBuffer("Certificate chain for $url: ");
    bool isFirst = true;
    final List<Uint8List> hostPinCerts = [];
    for (final cert in hostCertificates) {
      final Uint8List serverSpkiSha256Digest =
          Uint8List.fromList(_spkiSha256Digest(cert).bytes);
      if (!isFirst) info.write(", ");
      isFirst = false;
      info.write(base64.encode(serverSpkiSha256Digest));
      for (final pin in validPins) {
        if (_listEquals(base64.decode(pin), serverSpkiSha256Digest)) {
          hostPinCerts.add(cert);
          info.write(" pinned");
        }
      }
    }
    debugPrint("$_tag: $info");

    if (hostPinCerts.isEmpty) {
      throw NoValidPinsFoundException(url.host);
    }

    return hostPinCerts;
  }

  /// Creates a [SecurityContext] containing the trusted certificates that match
  /// the pinned hashes for the given [url].
  static Future<SecurityContext> _pinnedSecurityContext(
    Uri url,
    Set<String> validPins,
    Duration timeout,
    int retryCount,
  ) async {
    final List<Uint8List> pinCerts =
        await _HttpSecurityPinningService._hostPinCertificates(
            url, validPins, timeout, retryCount);

    final securityContext = SecurityContext();
    for (final pinCert in pinCerts) {
      final pemCertificate = PemCodec(PemLabel.certificate).encode(pinCert);
      final Uint8List pemCertificatesBytes =
          const AsciiEncoder().convert(pemCertificate);
      securityContext.setTrustedCertificatesBytes(pemCertificatesBytes);
    }
    debugPrint(
        "$_tag: Pinned security context with ${pinCerts.length} trusted certs, from ${validPins.length} possible pins");
    return securityContext;
  }

  /// Removes a [host] from the certificate cache.
  static Future<void> _removeCertificates(String host) async {
    _hostCertificates[host]?.clear();
  }

  /// Computes the SHA-256 digest of the Subject Public Key Info (SPKI)
  /// from a DER-encoded [certificate].
  static Digest _spkiSha256Digest(Uint8List certificate) {
    final asn1Parser = ASN1Parser(certificate);
    final signedCert = asn1Parser.nextObject() as ASN1Sequence;
    final cert = signedCert.elements[0] as ASN1Sequence;
    final spki = cert.elements[6] as ASN1Sequence;
    final spkiDigest = sha256.convert(spki.encodedBytes);
    return spkiDigest;
  }

  /// A utility function to compare two lists of bytes.
  static bool _listEquals<E>(List<E>? list1, List<E>? list2) {
    if (identical(list1, list2)) return true;
    if (list1 == null || list2 == null) return false;
    final length = list1.length;
    if (length != list2.length) return false;
    for (var i = 0; i < length; i++) {
      if (list1[i] != list2[i]) return false;
    }
    return true;
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

/// An implementation of Dart's [HttpClient] that enforces certificate pinning.
///
/// This client ensures that connections are only made to servers presenting
/// certificates with a Subject Public Key Info (SPKI) that matches one of the
/// provided [spkiHashes].
///
/// It works as a wrapper around a standard [HttpClient], intercepting connection
/// creation to inject a custom [SecurityContext] with the pinned certificates.
///
/// If the server's certificate chain does not match any of the provided pins,
/// the connection will fail, throwing a [NoValidPinsFoundException] before the
/// request is sent.
///
/// Example usage with `package:http`:
/// ```dart
/// final secureClient = IOClient(HttpSecurityPinningClient(
///   ["YOUR_SPKI_HASH_HERE"],
/// ));
/// final response = await secureClient.get(Uri.parse('https://example.com'));
/// ```
class HttpSecurityPinningClient implements HttpClient {
  /// Clears the static cache of fetched certificates.
  ///
  /// This is useful for testing purposes, for example to test timeout and retry logic.
  static void clearCache() {
    _HttpSecurityPinningService._hostCertificates.clear();
  }

  static const String _tag = "HttpSecurityPinningClient";

  /// A set of trusted SHA-256 hashes of Subject Public Key Info (SPKI).
  final Set<String> _validPins;

  /// The timeout for fetching the certificate chain from the native platform.
  final Duration timeout;

  /// The number of times to retry fetching the certificate chain upon failure.
  final int retryCount;

  HttpClient _delegatePinnedHttpClient = HttpClient();

  String? _connectedHost;

  bool _isClosed = false;

  Future<bool> Function(Uri url, String scheme, String? realm)? _authenticate;
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? _connectionFactory;
  void Function(String line)? _keyLog;
  final List<_Credential> _credentials = [];
  String Function(Uri url)? _findProxy;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;
  final List<_ProxyCredential> _proxyCredentials = [];
  bool Function(X509Certificate cert, String host, int port)?
      _badCertificateCallback;

  bool _pinningFailureCallback(X509Certificate cert, String host, int port) {
    final badCertificateCallback = _badCertificateCallback;
    if (badCertificateCallback != null) {
      badCertificateCallback(cert, host, port);
    }

    debugPrint(
        "$_tag: Pinning failure callback for $host. Invalidating cache.");
    _HttpSecurityPinningService._removeCertificates(host);
    _connectedHost = null;
    return false;
  }

  void _copyHttpClientState(HttpClient from, HttpClient to) {
    to.idleTimeout = from.idleTimeout;
    to.userAgent = from.userAgent;
    to.connectionTimeout = from.connectionTimeout;
    to.maxConnectionsPerHost = from.maxConnectionsPerHost;
    to.autoUncompress = from.autoUncompress;

    to.authenticate = _authenticate;
    to.connectionFactory = _connectionFactory;
    to.keyLog = _keyLog;
    to.findProxy = _findProxy;
    to.authenticateProxy = _authenticateProxy;

    for (final credential in _credentials) {
      to.addCredentials(
          credential.url, credential.realm, credential.credentials);
    }
    for (final proxyCredential in _proxyCredentials) {
      to.addProxyCredentials(proxyCredential.host, proxyCredential.port,
          proxyCredential.realm, proxyCredential.credentials);
    }

    to.badCertificateCallback = _pinningFailureCallback;
  }

  Future<HttpClient> _createPinnedHttpClient(Uri url) async {
    final securityContext = _validPins.isEmpty
        ? SecurityContext.defaultContext
        : await _HttpSecurityPinningService._pinnedSecurityContext(
            url, _validPins, timeout, retryCount);

    final newHttpClient = HttpClient(context: securityContext);
    _copyHttpClientState(_delegatePinnedHttpClient, newHttpClient);

    _connectedHost = url.host;
    return newHttpClient;
  }

  Future<HttpClient> _getOrCreatePinnedHttpClient(Uri url) async {
    if (_isClosed) {
      return _delegatePinnedHttpClient;
    }

    if (_connectedHost != url.host) {
      final newHttpClient = await _createPinnedHttpClient(url);
      _delegatePinnedHttpClient.close();
      _delegatePinnedHttpClient = newHttpClient;
    }
    return _delegatePinnedHttpClient;
  }

  /// Creates a new [HttpClient] that enforces certificate pinning.
  ///
  /// [spkiHashes] is a list of trusted SHA-256 hashes of a certificate's
  /// Subject Public Key Info (SPKI) in Base64 encoding.
  ///
  /// [timeout] specifies the duration to wait for the native platform to fetch
  /// the certificate chain for a host. Defaults to 10 seconds.
  ///
  /// [retryCount] specifies the number of times to retry fetching the certificate
  /// chain upon failure. Defaults to 3 times.
  HttpSecurityPinningClient(
    List<String> spkiHashes, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
  })  : _validPins = spkiHashes.toSet(),
        super();

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) async {
    final url = Uri(scheme: "https", host: host, port: port, path: path);
    final client = await _getOrCreatePinnedHttpClient(url);
    return client.open(method, host, port, path);
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    final client = await _getOrCreatePinnedHttpClient(url);
    return client.openUrl(method, url);
  }

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open("get", host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl("get", url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open("post", host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl("post", url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open("put", host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl("put", url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open("delete", host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl("delete", url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open("head", host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl("head", url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open("patch", host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl("patch", url);

  @override
  set idleTimeout(Duration timeout) =>
      _delegatePinnedHttpClient.idleTimeout = timeout;

  @override
  Duration get idleTimeout => _delegatePinnedHttpClient.idleTimeout;

  @override
  set connectionTimeout(Duration? timeout) =>
      _delegatePinnedHttpClient.connectionTimeout = timeout;

  @override
  Duration? get connectionTimeout =>
      _delegatePinnedHttpClient.connectionTimeout;

  @override
  set maxConnectionsPerHost(int? maxConnections) =>
      _delegatePinnedHttpClient.maxConnectionsPerHost = maxConnections;

  @override
  int? get maxConnectionsPerHost =>
      _delegatePinnedHttpClient.maxConnectionsPerHost;

  @override
  set autoUncompress(bool autoUncompress) =>
      _delegatePinnedHttpClient.autoUncompress = autoUncompress;

  @override
  bool get autoUncompress => _delegatePinnedHttpClient.autoUncompress;

  @override
  set userAgent(String? userAgent) =>
      _delegatePinnedHttpClient.userAgent = userAgent;

  @override
  String? get userAgent => _delegatePinnedHttpClient.userAgent;

  @override
  set authenticate(
      Future<bool> Function(Uri url, String scheme, String? realm)? f) {
    _authenticate = f;
    _delegatePinnedHttpClient.authenticate = f;
  }

  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> Function(
              Uri url, String? proxyHost, int? proxyPort)?
          f) {
    _connectionFactory = f;
    _delegatePinnedHttpClient.connectionFactory = f;
  }

  @override
  set keyLog(void Function(String line)? f) {
    _keyLog = f;
    _delegatePinnedHttpClient.keyLog = f;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add(_Credential(url, realm, credentials));
    _delegatePinnedHttpClient.addCredentials(url, realm, credentials);
  }

  @override
  set findProxy(String Function(Uri url)? f) {
    _findProxy = f;
    _delegatePinnedHttpClient.findProxy = f;
  }

  @override
  set authenticateProxy(
      Future<bool> Function(
              String host, int port, String scheme, String? realm)?
          f) {
    _authenticateProxy = f;
    _delegatePinnedHttpClient.authenticateProxy = f;
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add(_ProxyCredential(host, port, realm, credentials));
    _delegatePinnedHttpClient.addProxyCredentials(
        host, port, realm, credentials);
  }

  @override
  set badCertificateCallback(
      bool Function(X509Certificate cert, String host, int port)? callback) {
    _badCertificateCallback = callback;
  }

  @override
  void close({bool force = false}) {
    _delegatePinnedHttpClient.close(force: force);
    _isClosed = true;
  }
}
