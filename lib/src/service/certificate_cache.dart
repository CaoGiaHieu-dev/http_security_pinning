// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import '../core/host_normalizer.dart';

/// An in-memory cache of the certificate chains presented by hosts.
///
/// The cached chain is never trusted by itself: it is only used to choose
/// which certificates become trust anchors for the real, fully validated TLS
/// connection. A stale entry can therefore cause a failed connection (which
/// invalidates the entry and re-probes), but never the acceptance of an
/// unpinned key.
///
/// * Concurrent requests for the same host share one in-flight fetch.
/// * Failed fetches are never cached.
/// * Entries expire after [ttl] and at most [maxEntries] entries are kept
///   (the oldest entry is evicted first).
/// * Entries are removed with [invalidate] when a chain turns out to be
///   unusable (pin mismatch, or a TLS failure after a certificate renewal).
class CertificateChainCache {
  /// Creates a new in-memory [CertificateChainCache].
  ///
  /// [clock] can be overridden in tests.
  CertificateChainCache({
    this.ttl = const Duration(hours: 1),
    this.maxEntries = 256,
    DateTime Function()? clock,
  })  : assert(maxEntries > 0),
        _clock = clock ?? DateTime.now;

  /// The cache used by every [PinningService] created without an explicit
  /// `cache` (and so by every client created without a `pinningService`).
  static final CertificateChainCache shared = CertificateChainCache();

  /// How long a fetched chain is reused before the host is probed again.
  final Duration ttl;

  /// The maximum number of hosts kept in the cache.
  final int maxEntries;

  final DateTime Function() _clock;

  final LinkedHashMap<String, ({Future<List<Uint8List>> chain, DateTime at})>
      _entries = LinkedHashMap();

  /// Builds the cache key for [url]: `host:port`, with the host normalized by
  /// [HostNormalizer.normalize].
  static String keyFor(Uri url) =>
      '${HostNormalizer.normalize(url.host)}:${url.port}';

  /// Returns the cached chain for [key], or runs [fetch] and caches its result.
  Future<List<Uint8List>> getOrFetch(
    String key,
    Future<List<Uint8List>> Function() fetch,
  ) {
    final existing = _entries[key];
    if (existing != null) {
      if (_clock().difference(existing.at) < ttl) return existing.chain;
      _entries.remove(key);
    }

    final future = fetch();
    _entries[key] = (chain: future, at: _clock());
    while (_entries.length > maxEntries) {
      _entries.remove(_entries.keys.first);
    }
    // Forget failures so that the next call retries. This derived future
    // handles the error itself; callers still receive it through [future].
    future.then<void>((_) {}, onError: (Object _) {
      if (identical(_entries[key]?.chain, future)) _entries.remove(key);
    });
    return future;
  }

  /// Removes the chain cached for [key], if any.
  void invalidate(String key) => _entries.remove(key);

  /// Removes every cached chain.
  void clear() => _entries.clear();

  /// Whether a non-expired chain is cached (or being fetched) for [key].
  bool contains(String key) {
    final entry = _entries[key];
    return entry != null && _clock().difference(entry.at) < ttl;
  }
}
