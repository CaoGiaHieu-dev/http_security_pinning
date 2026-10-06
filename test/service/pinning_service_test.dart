import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Uint8List _pemToDer(String pemContent) {
  final clean = pemContent
      .replaceAll('\r', '')
      .split('\n')
      .map((l) => l.trim())
      .where((line) =>
          line.isNotEmpty &&
          !line.startsWith('-----BEGIN') &&
          !line.startsWith('-----END'))
      .join();
  return base64.decode(clean);
}

class FakeFetcher implements CertificateChainFetcher {
  int attempts = 0;
  final Future<List<Uint8List>> Function(int attempt) onFetch;

  FakeFetcher(this.onFetch);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) {
    attempts++;
    return onFetch(attempts);
  }
}

void main() {
  group('PinningService', () {
    late Uint8List certA1Der;
    late Uint8List certBDer;
    late SpkiPin pinA1;

    setUpAll(() {
      certA1Der =
          _pemToDer(File('test/fixtures/server_a1.pem').readAsStringSync());
      certBDer =
          _pemToDer(File('test/fixtures/server_b.pem').readAsStringSync());
      pinA1 = SpkiPin.parse(SpkiHasher.pinOf(certA1Der));
    });

    test('retries retryable errors up to retryCount', () async {
      final fakeFetcher = FakeFetcher((attempt) async {
        if (attempt < 3) {
          throw CertificateFetchException('Timeout', code: 'TIMEOUT');
        }
        return [certA1Der];
      });

      final service = PinningService(
        fetcher: fakeFetcher,
        cache: CertificateChainCache(),
      );

      final chain = await service.getCertificateChain(
        Uri.parse('https://example.com'),
        timeout: const Duration(seconds: 1),
        retryCount: 3,
        retryDelay: Duration.zero,
      );

      expect(chain.length, 1);
      expect(fakeFetcher.attempts, 3);
    });

    test('does not retry non-retryable errors', () async {
      final fakeFetcher = FakeFetcher((attempt) async {
        throw CertificateFetchException('Invalid URL', code: 'INVALID_URL');
      });

      final service = PinningService(
        fetcher: fakeFetcher,
        cache: CertificateChainCache(),
      );

      await expectLater(
        () => service.getCertificateChain(
          Uri.parse('https://example.com'),
          timeout: const Duration(seconds: 1),
          retryCount: 3,
          retryDelay: Duration.zero,
        ),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'INVALID_URL')),
      );

      expect(fakeFetcher.attempts, 1);
    });

    test('evaluatePins identifies matching and observed pins', () async {
      final fakeFetcher = FakeFetcher((_) async => [certA1Der, certBDer]);
      final service = PinningService(
        fetcher: fakeFetcher,
        cache: CertificateChainCache(),
      );

      final result = await service.evaluatePins(
        Uri.parse('https://example.com'),
        {pinA1},
        timeout: const Duration(seconds: 1),
        retryCount: 1,
      );

      expect(result.matchedCerts.length, 1);
      expect(result.matchedCerts.first, equals(certA1Der));
      expect(result.presentedChain.length, 2);
      expect(result.observedPins.length, 2);
      expect(result.observedPins.first, equals(pinA1.base64Value));
    });

    test('createPinnedSecurityContext constructs valid SecurityContext', () {
      final service = PinningService();
      final ctx = service.createPinnedSecurityContext([certA1Der]);
      expect(ctx, isA<SecurityContext>());
    });

    test(
        'retries unexpected exceptions and throws UNEXPECTED_ERROR when exhausted',
        () async {
      final fakeFetcher = FakeFetcher((attempt) async {
        throw const FormatException('Unexpected format error');
      });

      final service = PinningService(
        fetcher: fakeFetcher,
        cache: CertificateChainCache(),
      );

      await expectLater(
        () => service.getCertificateChain(
          Uri.parse('https://example.com'),
          timeout: const Duration(seconds: 1),
          retryCount: 2,
          retryDelay: Duration.zero,
        ),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'UNEXPECTED_ERROR')),
      );

      expect(fakeFetcher.attempts, 3);
    });

    test('evaluatePins skips malformed certificates in chain gracefully',
        () async {
      final malformedDer = Uint8List.fromList([1, 2, 3]);
      final fakeFetcher = FakeFetcher((_) async => [malformedDer, certA1Der]);
      final service = PinningService(
        fetcher: fakeFetcher,
        cache: CertificateChainCache(),
      );

      final result = await service.evaluatePins(
        Uri.parse('https://example.com'),
        {pinA1},
        timeout: const Duration(seconds: 1),
        retryCount: 0,
      );

      expect(result.matchedCerts.length, 1);
      expect(result.observedPins.length, 1); // malformed was skipped
      expect(result.presentedChain.length, 2);
    });
  });
}
