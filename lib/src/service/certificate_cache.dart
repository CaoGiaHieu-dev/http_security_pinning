import 'dart:async';
import 'dart:typed_data';

/// An in-memory cache of the certificate chains presented by hosts.
///
/// * Concurrent requests for the same host share one in-flight fetch.
/// * Failed fetches are never cached.
/// * Entries are removed with [invalidate] when a chain turns out to be
///   unusable (pin mismatch, or a TLS failure after a certificate renewal).
class CertificateChainCache {
  /// The cache shared by every client that uses the default fetcher.
  static final CertificateChainCache shared = CertificateChainCache();

  final Map<String, Future<List<Uint8List>>> _entries = {};

  /// Builds the cache key for [url]: `host:port`, host in lower case.
  static String keyFor(Uri url) => '${url.host.toLowerCase()}:${url.port}';

  /// Returns the cached chain for [key], or runs [fetch] and caches its result.
  Future<List<Uint8List>> getOrFetch(
    String key,
    Future<List<Uint8List>> Function() fetch,
  ) {
    final existing = _entries[key];
    if (existing != null) return existing;

    final future = fetch();
    _entries[key] = future;
    // Forget failures so that the next call retries. This derived future
    // handles the error itself; callers still receive it through [future].
    future.then<void>((_) {}, onError: (Object _) {
      if (identical(_entries[key], future)) _entries.remove(key);
    });
    return future;
  }

  /// Removes the chain cached for [key], if any.
  void invalidate(String key) => _entries.remove(key);

  /// Removes every cached chain.
  void clear() => _entries.clear();

  /// Whether a chain is cached (or being fetched) for [key].
  bool contains(String key) => _entries.containsKey(key);
}
