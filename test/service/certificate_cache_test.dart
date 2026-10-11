// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('CertificateChainCache', () {
    late CertificateChainCache cache;

    setUp(() {
      cache = CertificateChainCache();
    });

    test('builds consistent keyFor uri', () {
      final uri1 = Uri.parse('https://api.Example.COM:443/v1');
      final uri2 = Uri.parse('https://api.example.com:443/v2');
      expect(CertificateChainCache.keyFor(uri1), 'api.example.com:443');
      expect(CertificateChainCache.keyFor(uri1),
          equals(CertificateChainCache.keyFor(uri2)));
    });

    test('keyFor normalizes trailing dots and IDN hosts', () {
      expect(CertificateChainCache.keyFor(Uri.parse('https://localhost.:8443')),
          'localhost:8443');
      expect(CertificateChainCache.keyFor(Uri.parse('https://bücher.de/')),
          'xn--bcher-kva.de:443');
    });

    test('entries expire after ttl', () async {
      var now = DateTime(2026);
      final ttlCache = CertificateChainCache(
        ttl: const Duration(minutes: 10),
        clock: () => now,
      );
      var fetchCount = 0;
      Future<List<Uint8List>> fetch() async {
        fetchCount++;
        return [Uint8List(1)];
      }

      await ttlCache.getOrFetch('h:443', fetch);
      now = now.add(const Duration(minutes: 9));
      await ttlCache.getOrFetch('h:443', fetch);
      expect(fetchCount, 1);
      now = now.add(const Duration(minutes: 2));
      expect(ttlCache.contains('h:443'), isFalse);
      await ttlCache.getOrFetch('h:443', fetch);
      expect(fetchCount, 2);
    });

    test('keeps at most maxEntries entries, evicting the oldest', () async {
      final small = CertificateChainCache(maxEntries: 2);
      Future<List<Uint8List>> fetch() async => [Uint8List(1)];
      await small.getOrFetch('a:443', fetch);
      await small.getOrFetch('b:443', fetch);
      await small.getOrFetch('c:443', fetch);
      expect(small.contains('a:443'), isFalse);
      expect(small.contains('b:443'), isTrue);
      expect(small.contains('c:443'), isTrue);
    });

    test('caches successful fetch result', () async {
      int fetchCount = 0;
      Future<List<Uint8List>> fakeFetch() async {
        fetchCount++;
        return [
          Uint8List.fromList([1, 2, 3])
        ];
      }

      final res1 = await cache.getOrFetch('host:443', fakeFetch);
      final res2 = await cache.getOrFetch('host:443', fakeFetch);

      expect(fetchCount, 1);
      expect(res1, equals(res2));
      expect(cache.contains('host:443'), isTrue);
    });

    test('shares single in-flight fetch between concurrent callers', () async {
      final completer = Completer<List<Uint8List>>();
      int fetchCount = 0;

      Future<List<Uint8List>> fakeFetch() {
        fetchCount++;
        return completer.future;
      }

      final future1 = cache.getOrFetch('host:443', fakeFetch);
      final future2 = cache.getOrFetch('host:443', fakeFetch);

      expect(fetchCount, 1);

      final expected = [
        Uint8List.fromList([9, 9, 9])
      ];
      completer.complete(expected);

      final results = await Future.wait([future1, future2]);
      expect(results[0], equals(expected));
      expect(results[1], equals(expected));
    });

    test('does not cache failed fetches (auto-eviction)', () async {
      int attempts = 0;
      Future<List<Uint8List>> failingFetch() async {
        attempts++;
        throw StateError('Network failure $attempts');
      }

      await expectLater(
        () => cache.getOrFetch('host:443', failingFetch),
        throwsStateError,
      );

      // Verify entry was evicted and not retained as a permanent error
      expect(cache.contains('host:443'), isFalse);

      // Subsequent call retries the fetch
      await expectLater(
        () => cache.getOrFetch('host:443', failingFetch),
        throwsStateError,
      );
      expect(attempts, 2);
    });

    test('invalidate removes specific entry', () async {
      await cache.getOrFetch('host1:443', () async => [Uint8List(1)]);
      await cache.getOrFetch('host2:443', () async => [Uint8List(2)]);

      expect(cache.contains('host1:443'), isTrue);
      expect(cache.contains('host2:443'), isTrue);

      cache.invalidate('host1:443');

      expect(cache.contains('host1:443'), isFalse);
      expect(cache.contains('host2:443'), isTrue);
    });

    test('clear removes all entries', () async {
      await cache.getOrFetch('host1:443', () async => [Uint8List(1)]);
      await cache.getOrFetch('host2:443', () async => [Uint8List(2)]);

      cache.clear();

      expect(cache.contains('host1:443'), isFalse);
      expect(cache.contains('host2:443'), isFalse);
    });
  });
}
