import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('MethodChannelCertificateFetcher', () {
    const channel = MethodChannel(MethodChannelCertificateFetcher.channelName);
    final targetUrl = Uri.parse('https://example.com:443');

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    test('successfully returns certificate chain from channel', () async {
      final fakeCert1 = Uint8List.fromList([1, 2, 3]);
      final fakeCert2 = Uint8List.fromList([4, 5, 6]);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'fetchHostCertificates') {
          expect(call.arguments['url'], targetUrl.toString());
          expect(call.arguments['host'], 'example.com');
          expect(call.arguments['port'], 443);
          expect(call.arguments['timeout'], 5000);
          return [fakeCert1, fakeCert2];
        }
        return null;
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      final chain = await fetcher.fetchChain(
        targetUrl,
        const Duration(seconds: 5),
      );

      expect(chain.length, 2);
      expect(chain[0], fakeCert1);
      expect(chain[1], fakeCert2);
    });

    test(
        'throws CertificateFetchException when channel returns empty or null list',
        () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return <Uint8List>[];
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'NO_CERTIFICATES')),
      );
    });

    test('translates PlatformException to CertificateFetchException', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        throw PlatformException(
          code: 'CONNECTION_FAILED',
          message: 'Host unreachable',
        );
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'CONNECTION_FAILED')
            .having((e) => e.message, 'message', contains('Host unreachable'))),
      );
    });

    test('translates MissingPluginException to CertificateFetchException',
        () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        throw MissingPluginException();
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'MISSING_PLUGIN')),
      );
    });

    test('handles timeout from channel', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        // A hanging completer future that never finishes
        await Completer<void>().future;
        return <Uint8List>[];
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(milliseconds: 50)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'TIMEOUT')),
      );
    });
  });

  group('HttpSecurityPinningPlugin desktop registrar', () {
    test('registerWith runs without error', () {
      expect(HttpSecurityPinningPlugin.registerWith, returnsNormally);
    });
  });
}
